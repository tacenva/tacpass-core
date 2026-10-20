package vault

import (
	"errors"
	"slices"
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
	return s.permissionService.ConnectedPublicKeys(authUser.Permission.PublicKey)
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
	err = dbFile.Update(vaData)
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

	return s.repository.Transaction(func(tx *gorm.DB) error {
		if err := s.repository.Delete(
			tx,
			vault.ID,
		); err != nil {
			return err
		}

		if err := s.syncService.RecordChange(
			tx,
			lastChangeID,
			syncEntityVault,
			vault.ID,
			sync.OperationDelete,
			sotID,
		); err != nil {
			return err
		}

		return s.vaultRecordService.Destroy(
			vaultDir,
			vault.ID,
		)
	})
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
		id,
		sync.OperationDelete,
		sotID,
	)
	if err != nil {
		return err
	}

	if err := s.vaultRecordService.Destroy(
		vaultDir,
		id,
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
) (*contract.PendingVaultChange, error) {
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

	vaultChangeDataList := make(map[string]contract.VaultChangeData)
	for _, change := range changes {
		existing, exist := vaultChangeDataList[change.EntityID]
		if exist {
			continue
		}

		vault, err := s.repository.FindByID(change.EntityID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				continue
			} else {
				return nil, err
			}
		}

		existing.Vault = *vault
		vaultChangeDataList[change.EntityID] = existing
	}

	for vaultID := range vaultChangeDataList {
		existing := vaultChangeDataList[vaultID]
		if len(existing.VaultAccessList) > 0 {
			continue
		}

		vaFromVault, err := s.vaultaccessService.FindByVaultID(
			vaultID,
			authUser.PermissionID,
		)
		if err != nil {
			return nil, err
		}

		existing.VaultAccessList = vaFromVault
		vaultChangeDataList[vaultID] = existing
	}

	return &contract.PendingVaultChange{
		SyncChanges:         changes,
		VaultChangeDataList: vaultChangeDataList,
	}, nil
}

func (s *Service) GetChangesAfterOnReplica(
	sotID string,
	startID string,
	limit int,
	dbFile *database.DatabaseFile,
) (*contract.PendingVaultChange, error) {
	changes, err := s.syncService.GetChangesAfter(
		sotID,
		syncEntityVault,
		startID,
		limit,
	)
	if err != nil {
		return nil, err
	}

	vaultChangeDataList := make(map[string]contract.VaultChangeData)

	for _, change := range changes {
		if change.Operation != sync.OperationDelete {
			var vaFound entity.VaultAccess

			err := dbFile.FindFirstWhere(
				&vaFound,
				func(data map[string]any) bool {
					vaultID, ok := data["vault_id"]
					return ok && vaultID == change.EntityID
				},
			)

			if err != nil {
				if errors.Is(err, database.ErrRecordNotFound) {
					continue
				}
				return nil, err
			}

			existing, exist := vaultChangeDataList[vaFound.VaultID]
			if exist {
				continue
			}

			existing.Vault = vaFound.Vault

			vaFound.Vault = entity.Vault{}

			existing.VaultAccessList = append(
				existing.VaultAccessList,
				vaFound,
			)

			vaultChangeDataList[vaFound.VaultID] = existing
		}
	}

	return &contract.PendingVaultChange{
		SyncChanges:         changes,
		VaultChangeDataList: vaultChangeDataList,
	}, nil
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
	base *contract.PendingVaultChange,
	comp *contract.PendingVaultChange,
) *contract.PendingVaultChange {
	if base == nil {
		return nil
	}

	var compChanges []sync.SyncChange
	var compData map[string]contract.VaultChangeData

	if comp != nil {
		compChanges = comp.SyncChanges
		compData = comp.VaultChangeDataList
	}

	changes, data := sync.MergePendingChanges(
		base.SyncChanges,
		compChanges,
		base.VaultChangeDataList,
		compData,
	)

	return &contract.PendingVaultChange{
		SyncChanges:         changes,
		VaultChangeDataList: data,
	}
}

func (s *Service) applyChangeOnSoT(
	vaultChange *contract.PendingVaultChange,
) error {
	if vaultChange == nil {
		return nil
	}

	err := s.repository.Transaction(func(tx *gorm.DB) error {
		for _, change := range vaultChange.SyncChanges {
			vaultID := change.EntityID
			vaultChangeData, exist := vaultChange.VaultChangeDataList[vaultID]

			switch change.Operation {
			case sync.OperationCreate:
				if !exist {
					continue
				}

				if err := s.repository.Create(tx, &vaultChangeData.Vault); err != nil {
					return err
				}

				if err := s.vaultaccessService.CreateOrUpdateBulkTx(tx, vaultChangeData.VaultAccessList); err != nil {
					return err
				}

			case sync.OperationUpdate:
				if !exist {
					continue
				}

				if err := s.repository.FirstOrCreate(tx, &vaultChangeData.Vault); err != nil {
					return err
				}

				if err := s.vaultaccessService.CreateOrUpdateBulkTx(tx, vaultChangeData.VaultAccessList); err != nil {
					return err
				}

			case sync.OperationDelete:
				if err := s.repository.Delete(tx, vaultID); err != nil {
					return err
				}
			}
		}

		return nil
	})

	return err
}

func (s *Service) ApplyChangeOnReplica(
	vaultChange *contract.PendingVaultChange,
	dbFile *database.DatabaseFile,
) error {
	if vaultChange == nil {
		return nil
	}

	for _, change := range vaultChange.SyncChanges {
		vaultID := change.EntityID
		vaultChangeData := vaultChange.VaultChangeDataList[vaultID]
		var vaData entity.VaultAccess
		if len(vaultChangeData.VaultAccessList) > 0 {
			vaData = vaultChangeData.VaultAccessList[0]
			vaData.Vault = vaultChangeData.Vault
		}

		switch change.Operation {
		case sync.OperationCreate:
			_, err := dbFile.Insert(&vaData)
			if err != nil {
				return err
			}

		case sync.OperationUpdate:
			err := dbFile.Update(&vaData)
			if err != nil {
				if errors.Is(err, database.ErrRecordNotFound) {
					continue
				}
				return err
			}

		case sync.OperationDelete:
			foundVa, err := s.findVAOnReplica(
				vaultID,
				dbFile,
			)
			if err != nil {
				if errors.Is(err, database.ErrRecordNotFound) {
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
	syncChanges []sync.SyncChange,
) error {
	if len(syncChanges) == 0 {
		return nil
	}

	clonedSyncChanges := slices.Clone(syncChanges)

	for changeIndex := range clonedSyncChanges {
		clonedSyncChanges[changeIndex].SotID = sotID
	}

	return s.syncService.InsertSyncChanges(
		sotID,
		syncEntityVault,
		clonedSyncChanges,
	)
}

func (s *Service) SyncOnReplica(
	sotID string,
	replicaChanges *contract.PendingVaultChange,
	sotChanges *contract.PendingVaultChange,
	dbFile *database.DatabaseFile,
) error {
	appliedChanges := s.MergePendingVaultChange(sotChanges, replicaChanges)
	if appliedChanges == nil {
		return nil
	}

	if err := s.ApplyChangeOnReplica(appliedChanges, dbFile); err != nil {
		return err
	}

	return s.insertSyncChanges(sotID, sotChanges.SyncChanges)
}

func (s *Service) SyncOnSoT(
	sotID string,
	changes *contract.PendingVaultChange,
) error {
	appliedChanges := s.MergePendingVaultChange(changes, nil)
	if appliedChanges == nil {
		return nil
	}

	if err := s.applyChangeOnSoT(appliedChanges); err != nil {
		return err
	}

	return s.insertSyncChanges(sotID, changes.SyncChanges)
}

func (s *Service) SetSyncStateToBeLastest(
	sotID string,
) error {
	return s.syncService.Transaction(func(tx *gorm.DB) error {
		return s.syncService.SetSyncStateToBeLastest(
			tx,
			sotID,
			syncEntityVault,
		)
	})
}
