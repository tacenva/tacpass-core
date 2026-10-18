package vault

import (
	"errors"
	"log"
	"slices"
	"sort"
	"strings"

	"github.com/oklog/ulid/v2"
	"github.com/tacenva/database"
	"github.com/tacenva/tacpass-core/contract"
	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/internal/permission"
	"github.com/tacenva/tacpass-core/internal/sync"
	"github.com/tacenva/tacpass-core/internal/vaultaccess"
	"github.com/tacenva/tacpass-core/util/credential"
	"github.com/tacenva/tacpass-core/util/keyring"
	"github.com/tacenva/tacpass-core/vaultrecord"
	"gorm.io/gorm"
)

var (
	ErrNotFound   = errors.New("vault not found")
	ErrNameEmpty  = errors.New("vault name cannot be empty")
	ErrPermission = errors.New("permission denied")
)

const syncEntityVault = "vault"

type Service struct {
	repository         *repository
	vaultaccessService *vaultaccess.Service
	vaultRecordService *vaultrecord.Service
	permissionService  *permission.Service
	syncService        *sync.Service
}

func NewService(
	repository *repository,
	vaultaccessService *vaultaccess.Service,
	permissionService *permission.Service,
	syncService *sync.Service,
) *Service {
	return &Service{
		repository: repository,
		vaultRecordService: vaultrecord.NewService(
			syncService,
		),
		vaultaccessService: vaultaccessService,
		permissionService:  permissionService,
		syncService:        syncService,
	}
}

func (s *Service) GetVaultRecordService() *vaultrecord.Service {
	return s.vaultRecordService
}

func (s *Service) VaultAccessList(
	authUser *entity.User,
) ([]entity.VaultAccess, error) {
	if authUser == nil {
		return nil, ErrPermission
	}

	vaultAccessList, err := s.repository.FindAccessible(
		authUser.PermissionID,
	)
	if err != nil {
		return nil, err
	}

	return vaultAccessList, nil
}

func (s *Service) ConnectedPublicKeys(
	authUser *entity.User,
) ([]entity.Permission, error) {
	return s.permissionService.ConnectedPublicKeys(authUser)
}

func (s *Service) CreateOnSoT(
	authUser *entity.User,
	vaultDir string,
	vault *entity.Vault,
	sotID string,
	lastChangeID *string,
) (*entity.VaultAccess, error) {
	if authUser == nil || !authUser.HasWritePermission() {
		return nil, ErrPermission
	}

	var vaData *entity.VaultAccess
	err := s.repository.Transaction(func(tx *gorm.DB) error {
		if err := s.repository.Create(tx, vault); err != nil {
			return err
		}

		connectedPermission, err := s.ConnectedPublicKeys(authUser)
		if err != nil {
			return err
		}

		vaultKey, err := credential.Generate(32)
		if err != nil {
			return err
		}

		vaList := make(
			[]entity.VaultAccess,
			0,
			len(connectedPermission),
		)

		for _, permissionData := range connectedPermission {
			keyPair := keyring.FromPublicKey(permissionData.PublicKey)
			wrappedVaultKey, err := keyPair.Seal([]byte(vaultKey))
			if err != nil {
				break
			}

			vaList = append(vaList, entity.VaultAccess{
				VaultID:      vault.ID,
				PermissionID: permissionData.ID,
				VaultKey:     wrappedVaultKey,
			})
		}

		vaListRes, err := s.vaultaccessService.CreateBulkTx(tx, vaList)
		for _, vaPointer := range vaListRes {
			if vaPointer.PermissionID == authUser.PermissionID {
				vaData = &vaList[len(vaList)-1]
				vaData.Vault = *vault
				err = s.vaultRecordService.Init(vaultDir, vaData.VaultID, vaultKey)
				break
			}
		}

		return s.syncService.RecordChange(
			tx,
			lastChangeID,
			syncEntityVault,
			vault.ID,
			sync.OperationCreate,
			sotID,
		)
	})
	return vaData, err
}

func (s *Service) CreateOnReplica(
	vaultDir string,
	vault *entity.Vault,
	sotID string,
	lastChangeID *string,
	dbFile *database.DatabaseFile,

	keypair *keyring.KeyPair,
) (*entity.VaultAccess, error) {
	vault.Name = strings.TrimSpace(vault.Name)
	if vault.Name == "" {
		return nil, ErrNameEmpty
	}

	vaultKey, err := credential.Generate(32)
	if err != nil {
		return nil, err
	}

	if vault.ID == "" {
		vault.ID = ulid.Make().String()
	}

	keyPair := keyring.FromPublicKey(keypair.PublicKey)
	wrappedVaultKey, err := keyPair.Seal([]byte(vaultKey))

	vaultAccess := &entity.VaultAccess{
		ID:       ulid.Make().String(),
		VaultID:  vault.ID,
		VaultKey: wrappedVaultKey,
		Vault:    *vault,
	}

	if _, err := dbFile.Insert(vaultAccess); err != nil {
		return nil, err
	}

	if err := s.syncService.RecordChangeWithoutTx(
		lastChangeID,
		syncEntityVault,
		vault.ID,
		sync.OperationCreate,
		sotID,
	); err != nil {
		return nil, err
	}
	err = s.vaultRecordService.Init(vaultDir, vault.ID, vaultKey)
	return vaultAccess, err
}

func (s *Service) UpdateOnSoT(
	authUser *entity.User,
	vault *entity.Vault,
	sotID string,
	lastChangeID *string,
) (*entity.Vault, error) {
	if authUser == nil || !authUser.HasWritePermission() {
		return nil, ErrPermission
	}

	vault.ID = strings.TrimSpace(vault.ID)
	vault.Name = strings.TrimSpace(vault.Name)

	if vault.ID == "" {
		return nil, ErrNotFound
	}

	if vault.Name == "" {
		return nil, ErrNameEmpty
	}

	_, err := s.repository.FindByID(vault.ID)
	if err != nil {
		return nil, err
	}

	err = s.repository.Transaction(func(tx *gorm.DB) error {
		if err := s.repository.Update(tx, vault); err != nil {
			return err
		}

		return s.syncService.RecordChange(
			tx,
			lastChangeID,
			syncEntityVault,
			vault.ID,
			sync.OperationUpdate,
			sotID,
		)
	})

	if err != nil {
		return nil, err
	}

	return vault, nil
}

func (s *Service) findVAOnReplica(
	vaultID string,
	dbFile *database.DatabaseFile,
) (*entity.VaultAccess, error) {
	var vaData entity.VaultAccess
	err := dbFile.FindFirstWhere(&vaData, func(data map[string]any) bool {
		vaultData, ok := data["vault"].(map[string]any)
		if !ok {
			return false
		}

		id, ok := vaultData["id"].(string)
		if !ok {
			return false
		}

		return vaultID == id
	})
	return &vaData, err
}

func (s *Service) UpdateOnReplica(
	vault *entity.Vault,
	sotID string,
	lastChangeID *string,

	dbFile *database.DatabaseFile,
) (*entity.Vault, error) {
	vault.ID = strings.TrimSpace(vault.ID)
	vault.Name = strings.TrimSpace(vault.Name)

	if vault.ID == "" {
		return nil, ErrNotFound
	}

	if vault.Name == "" {
		return nil, ErrNameEmpty
	}

	vaData, err := s.findVAOnReplica(vault.ID, dbFile)
	if err != nil {
		return nil, err
	}

	vaData.Vault = *vault
	err = dbFile.Update(&vaData)
	if err != nil {
		return nil, err
	}

	err = s.syncService.RecordChangeWithoutTx(
		lastChangeID,
		syncEntityVault,
		vaData.Vault.ID,
		sync.OperationUpdate,
		sotID,
	)
	if err != nil {
		return nil, err
	}

	return &vaData.Vault, nil
}

func (s *Service) DeleteOnSoT(
	authUser *entity.User,
	vaultDir string,
	id string,
	sotID string,
	lastChangeID *string,
) error {
	if authUser == nil || !authUser.HasWritePermission() {
		return ErrPermission
	}

	id = strings.TrimSpace(id)

	if id == "" {
		return ErrNotFound
	}

	vault, err := s.repository.FindByID(id)
	if err != nil {
		return err
	}

	if vault == nil {
		return ErrNotFound
	}

	err = s.repository.Transaction(func(tx *gorm.DB) error {
		if err := s.repository.Delete(
			tx,
			vault.ID,
		); err != nil {
			return err
		}

		return s.syncService.RecordChange(
			tx,
			lastChangeID,
			syncEntityVault,
			vault.ID,
			sync.OperationDelete,
			sotID,
		)
	})

	if err != nil {
		return err
	}

	if err := s.vaultRecordService.Destroy(
		vaultDir,
		vault.ID,
	); err != nil {
		return err
	}

	return nil
}

func (s *Service) DeleteOnReplica(
	vaultDir string,
	id string,
	sotID string,
	lastChangeID *string,

	dbFile *database.DatabaseFile,
) error {
	id = strings.TrimSpace(id)

	if id == "" {
		return ErrNotFound
	}

	vaData, err := s.findVAOnReplica(id, dbFile)
	if err != nil {
		return err
	}

	_, err = dbFile.Delete(vaData.ID)
	if err != nil {
		return err
	}

	err = s.syncService.RecordChangeWithoutTx(
		lastChangeID,
		syncEntityVault,
		vaData.VaultID,
		sync.OperationDelete,
		sotID,
	)
	if err != nil {
		return err
	}

	if err := s.vaultRecordService.Destroy(
		vaultDir,
		vaData.VaultID,
	); err != nil {
		return err
	}

	return nil
}

func (s *Service) GetSyncLatestChangeId(
	sotID string,
) (string, error) {
	syncState, err := s.syncService.GetSyncState(
		sotID,
		syncEntityVault,
	)

	return syncState.LastChangeID, err
}

func (s *Service) GetChangesAfterOnSoT(
	authUser *entity.User,
	sotID string,
	startID string,
	limit int,
) ([]contract.PendingVaultChange, error) {
	if authUser == nil || authUser.ID == "" {
		return nil, ErrPermission
	}

	changes, err := s.syncService.GetChangesAfter(
		sotID,
		syncEntityVault,
		startID,
		limit,
	)
	if err != nil {
		return nil, err
	}

	result := make(
		[]contract.PendingVaultChange,
		0,
		len(changes),
	)

	for _, change := range changes {
		item := contract.PendingVaultChange{
			SyncChange: change,
		}

		vault, err := s.repository.FindByID(
			change.EntityID,
		)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				vault = &entity.Vault{
					ID: change.EntityID,
				}
				err = nil
			} else {
				return nil, err
			}
		}

		item.Vault = vault
		if change.Operation != sync.OperationDelete {
			vaultAccessList, err := s.vaultaccessService.FindByVaultID(
				change.EntityID,
			)
			if err != nil {
				return nil, err
			}

			for _, vaData := range vaultAccessList {
				if vaData.PermissionID != authUser.PermissionID {
					continue
				}

				item.VaultAccessList = append(item.VaultAccessList, entity.VaultAccess{
					ID:           vaData.ID,
					VaultID:      vaData.VaultID,
					PermissionID: vaData.PermissionID,
					VaultKey:     vaData.VaultKey,
				})

				item.Vault = &vaData.Vault
				break
			}
		}

		result = append(result, item)
	}

	return result, nil
}

func (s *Service) GetChangesAfterOnReplica(
	sotID string,
	startID string,
	limit int,
	dbFile *database.DatabaseFile,
) ([]contract.PendingVaultChange, error) {
	changes, err := s.syncService.GetChangesAfter(
		sotID,
		syncEntityVault,
		startID,
		limit,
	)
	if err != nil {
		return nil, err
	}

	result := make([]contract.PendingVaultChange, 0, len(changes))

	for _, change := range changes {
		item := contract.PendingVaultChange{
			SyncChange: change,
		}

		if change.Operation != sync.OperationDelete {
			var vaListFound []entity.VaultAccess

			err := dbFile.FindWhere(
				&vaListFound,
				func(data map[string]any) bool {
					vaultID, ok := data["vault_id"]

					return ok && vaultID == change.EntityID
				},
			)
			if err != nil {
				return nil, err
			}

			vaFound := vaListFound[0]
			item.VaultAccessList = append(item.VaultAccessList,
				entity.VaultAccess{
					ID:       vaFound.ID,
					VaultID:  vaFound.VaultID,
					VaultKey: vaFound.VaultKey,
				},
			)

			item.Vault = &vaFound.Vault
		}

		result = append(result, item)
	}

	return result, nil
}

func (s *Service) GetChangeCount(
	sotID string,
	startID string,
) (int64, error) {
	return s.syncService.GetChangeCount(
		sotID,
		syncEntityVault,
		startID,
	)
}

func (s *Service) MergePendingVaultChange(
	base []contract.PendingVaultChange,
	comp []contract.PendingVaultChange,
) []contract.PendingVaultChange {
	clonedBase := slices.Clone(base)
	merged := make(map[string]contract.PendingVaultChange)
	for _, change := range clonedBase {
		if change.Vault == nil {
			continue
		}

		vaultID := change.Vault.ID
		existing, exist := merged[vaultID]
		if existing.SyncChange.Operation == sync.OperationDelete {
			continue
		}

		if !exist || change.SyncChange.ID > existing.SyncChange.ID {
			merged[vaultID] = change
		}
	}

	for _, change := range comp {
		if change.Vault == nil {
			continue
		}

		vaultID := change.Vault.ID
		existing, exists := merged[vaultID]
		if exists {
			if existing.SyncChange.Operation == sync.OperationDelete {
				continue
			}

			if change.SyncChange.ID > existing.SyncChange.ID {
				merged[vaultID] = change
			}
		}
	}

	result := make([]contract.PendingVaultChange, 0, len(merged))
	for _, change := range merged {
		result = append(result, change)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].SyncChange.ID < result[j].SyncChange.ID
	})

	return result
}

func (s *Service) ApplyChangeOnSoT(
	vaultChanges []contract.PendingVaultChange,
) error {
	err := s.repository.Transaction(func(tx *gorm.DB) error {
		for _, change := range vaultChanges {
			// debug, _ := json.MarshalIndent(change.VaultAccessList, "", "  ")
			// log.Printf(
			// 	"[DEBUG] Change[%d] Operation=%s VaultID=%s VaultAccessList Count=%d\n%s",
			// 	i,
			// 	change.SyncChange.Operation,
			// 	change.Vault.ID,
			// 	len(change.VaultAccessList),
			// 	debug,
			// )

			vault := change.Vault

			switch change.SyncChange.Operation {
			case sync.OperationCreate:
				if err := s.repository.Create(tx, vault); err != nil {
					return err
				}

				if err := s.vaultaccessService.CreateOrUpdateBulkTx(tx, change.VaultAccessList); err != nil {
					return err
				}

			case sync.OperationUpdate:
				if err := s.repository.Update(tx, vault); err != nil {
					return err
				}

				if err := s.vaultaccessService.CreateOrUpdateBulkTx(tx, change.VaultAccessList); err != nil {
					return err
				}

			case sync.OperationDelete:
				if err := s.repository.Delete(tx, vault.ID); err != nil {
					return err
				}
			}
		}

		return nil
	})

	if err != nil {
		log.Printf("[ERROR] ApplyChangeOnSoT failed: %v", err)
	}

	return err
}

func (s *Service) ApplyChangeOnReplica(
	vaultChanges []contract.PendingVaultChange,
	dbFile *database.DatabaseFile,
) error {
	for _, change := range vaultChanges {
		var vaData entity.VaultAccess
		if len(change.VaultAccessList) > 0 {
			vaData = change.VaultAccessList[0]
		}
		vaData.Vault = *change.Vault

		switch change.SyncChange.Operation {
		case sync.OperationCreate:
			_, err := dbFile.Insert(&vaData)
			if err != nil {
				return err
			}

		case sync.OperationUpdate:
			err := dbFile.Update(&vaData)
			if err != nil {
				if err == database.RecordNotFound {
					continue
				}
				return err
			}

		case sync.OperationDelete:
			foundVa, err := s.findVAOnReplica(
				change.Vault.ID,
				dbFile,
			)
			if err != nil {
				if err == database.RecordNotFound {
					continue
				}
				return err
			}

			_, err = dbFile.Delete(foundVa.ID)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Service) insertSyncChanges(
	sotID string,
	vaultChanges []contract.PendingVaultChange,
) error {
	if len(vaultChanges) == 0 {
		return nil
	}

	syncChanges := make([]sync.SyncChange, len(vaultChanges))

	for i, change := range vaultChanges {
		syncChanges[i] = change.SyncChange
		syncChanges[i].SotID = sotID
	}

	return s.syncService.InsertSyncChanges(
		sotID,
		syncEntityVault,
		syncChanges,
	)
}

func (s *Service) SyncOnReplica(
	sotID string,
	replicaChanges []contract.PendingVaultChange,
	sotChanges []contract.PendingVaultChange,
	dbFile *database.DatabaseFile,
) error {
	changes := s.MergePendingVaultChange(sotChanges, replicaChanges)
	if err := s.ApplyChangeOnReplica(changes, dbFile); err != nil {
		return err
	}

	return s.insertSyncChanges(sotID, sotChanges)
}

func (s *Service) SyncOnSoT(
	sotID string,
	changes []contract.PendingVaultChange,
) error {
	if err := s.ApplyChangeOnSoT(changes); err != nil {
		return err
	}

	return s.insertSyncChanges(sotID, changes)
}
