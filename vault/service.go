package vault

import (
	"errors"
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

func (s *Service) GetConnectedPermission(
	authUser *entity.User,
) ([]entity.Permission, error) {
	return s.permissionService.GetConnectedPermission(authUser)
}

func (s *Service) createOnSoT(
	vault *entity.Vault,
	sotID string,
	lastChangeID *string,
) (*entity.Vault, error) {
	err := s.repository.Transaction(func(tx *gorm.DB) error {
		if err := s.repository.Create(tx, vault); err != nil {
			return err
		}

		return s.syncService.RecordChange(
			tx,
			lastChangeID,
			syncEntityVault,
			vault.ID,
			sync.OperationCreate,
			sotID,
			// sync.SotType,
		)
	})
	return vault, err
}

func (s *Service) CreateOnSoT(
	authUser *entity.User,
	vaultDir string,
	name string,
	sotID string,
	lastChangeID *string,
) (*entity.VaultAccess, error) {
	if authUser == nil || !authUser.HasWritePermission() {
		return nil, ErrPermission
	}

	vault, err := s.createOnSoT(
		&entity.Vault{
			Name: name,
		},
		sotID,
		lastChangeID,
	)
	if err != nil {
		return nil, err
	}

	connectedPermission, err := s.GetConnectedPermission(authUser)
	if err != nil {
		return nil, err
	}

	vaultKey, err := credential.Generate(32)
	if err != nil {
		return nil, err
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

	vaListRes, err := s.vaultaccessService.CreateBulk(vaList)
	var vaData *entity.VaultAccess
	for _, vaPointer := range vaListRes {
		if vaPointer.PermissionID == authUser.PermissionID {
			vaData = &vaList[len(vaList)-1]
			vaData.Vault = *vault
			err = s.vaultRecordService.Init(vaultDir, vaData.VaultID, vaultKey)
			break
		}
	}

	return vaData, err
}

func (s *Service) CreateOnReplica(
	vaultDir string,
	name string,
	sotID string,
	lastChangeID *string,
	dbFile *database.DatabaseFile,

	keypair *keyring.KeyPair,
) (*entity.VaultAccess, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrNameEmpty
	}

	vaultKey, err := credential.Generate(32)
	if err != nil {
		return nil, err
	}

	vault := &entity.Vault{
		ID:   ulid.Make().String(),
		Name: name,
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
		// sync.ReplicaType,
	); err != nil {
		return nil, err
	}
	err = s.vaultRecordService.Init(vaultDir, vault.ID, vaultKey)
	return vaultAccess, err
}

func (s *Service) UpdateOnSoT(
	authUser *entity.User,
	id string,
	name string,
	sotID string,
	lastChangeID *string,
) (*entity.Vault, error) {
	if authUser == nil || !authUser.HasWritePermission() {
		return nil, ErrPermission
	}

	id = strings.TrimSpace(id)
	name = strings.TrimSpace(name)

	if id == "" {
		return nil, ErrNotFound
	}

	if name == "" {
		return nil, ErrNameEmpty
	}

	vault, err := s.repository.FindByID(id)
	if err != nil {
		return nil, err
	}

	if vault == nil {
		return nil, ErrNotFound
	}

	vault.Name = name

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
			// sync.SotType,
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
	id string,
	name string,
	sotID string,
	lastChangeID *string,

	dbFile *database.DatabaseFile,
) (*entity.Vault, error) {
	id = strings.TrimSpace(id)
	name = strings.TrimSpace(name)

	if id == "" {
		return nil, ErrNotFound
	}

	if name == "" {
		return nil, ErrNameEmpty
	}

	vaData, err := s.findVAOnReplica(id, dbFile)
	if err != nil {
		return nil, err
	}

	vaData.Vault.Name = name
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
		// sync.ReplicaType,
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
			// sync.SotType,
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
		// sync.ReplicaType,
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

		if change.Operation != sync.OperationDelete {
			vault, err := s.repository.FindByID(
				change.EntityID,
			)
			if err != nil {
				return nil, err
			}

			if vault == nil {
				continue
			}

			item.Vault = vault

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

func (s *Service) giveAccess(
	vaultaccessList []entity.VaultAccess,
) error {
	_, err := s.vaultaccessService.CreateBulk(vaultaccessList)
	return err
}

func (s *Service) SyncOnSoT(
	authUser *entity.User,
	vaultDir string,
	sotID string,
	vaultChanges []contract.PendingVaultChange,
) error {
	if authUser == nil || authUser.ID == "" {
		return ErrPermission
	}

	if len(vaultChanges) == 0 {
		return nil
	}

	for _, vaultChange := range vaultChanges {
		switch vaultChange.SyncChange.Operation {
		case sync.OperationCreate:
			if vaultChange.Vault == nil {
				return ErrNotFound
			}

			_, err := s.createOnSoT(
				vaultChange.Vault,
				sotID,
				&vaultChange.SyncChange.ID,
			)
			if err != nil {
				return err
			}

			if err := s.giveAccess(
				vaultChange.VaultAccessList,
			); err != nil {
				return err
			}

		case sync.OperationUpdate:
			if vaultChange.Vault == nil {
				return ErrNotFound
			}

			_, err := s.UpdateOnSoT(
				authUser,
				vaultChange.Vault.ID,
				vaultChange.Vault.Name,
				sotID,
				&vaultChange.SyncChange.ID,
			)
			if err != nil {
				return err
			}

		case sync.OperationDelete:
			if vaultChange.Vault == nil {
				return ErrNotFound
			}

			if err := s.DeleteOnSoT(
				authUser,
				vaultDir,
				vaultChange.Vault.ID,
				sotID,
				&vaultChange.SyncChange.ID,
			); err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *Service) SyncOnReplica(
	sotID string,
	vaultChanges []contract.PendingVaultChange,
	dbFile *database.DatabaseFile,
) error {
	if len(vaultChanges) == 0 {
		return nil
	}

	for _, vaultChange := range vaultChanges {
		vaData := vaultChange.VaultAccessList[0]
		vaData.Vault = *vaultChange.Vault
		switch vaultChange.SyncChange.Operation {
		case sync.OperationCreate:
			_, err := dbFile.Insert(vaData)
			if err != nil {
				return err
			}

		case sync.OperationUpdate:
			err := dbFile.Update(vaData)
			if err != nil {
				return err
			}

		case sync.OperationDelete:
			_, err := dbFile.Delete(vaData.ID)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *Service) DiffVaultChanges(
	base []contract.PendingVaultChange,
	changes []contract.PendingVaultChange,
) []contract.PendingVaultChange {
	baseChanges := s.normalizeVaultChanges(base)
	sourceChanges := s.normalizeVaultChanges(changes)

	result := make(
		[]contract.PendingVaultChange,
		0,
		len(sourceChanges),
	)

	for entityID, sourceChange := range sourceChanges {
		baseChange, exists := baseChanges[entityID]

		if !exists {
			if sourceChange.SyncChange.Operation != sync.OperationDelete {
				result = append(result, sourceChange)
			}
			continue
		}

		if baseChange.SyncChange.ID >= sourceChange.SyncChange.ID {
			continue
		}

		result = append(result, sourceChange)
	}

	return result
}

func (s *Service) normalizeVaultChanges(
	changes []contract.PendingVaultChange,
) map[string]contract.PendingVaultChange {
	result := make(
		map[string]contract.PendingVaultChange,
	)

	for _, change := range changes {
		entityID := change.SyncChange.EntityID

		current, exists := result[entityID]
		if !exists {
			result[entityID] = change
			continue
		}

		if current.SyncChange.Operation == sync.OperationCreate {
			switch change.SyncChange.Operation {
			case sync.OperationUpdate:
				result[entityID] = change

			case sync.OperationDelete:
				delete(result, entityID)
			}

			continue
		}

		if current.SyncChange.Operation == sync.OperationDelete {
			if current.SyncChange.ID < change.SyncChange.ID {
				result[entityID] = change
			}

			continue
		}

		if current.SyncChange.ID < change.SyncChange.ID {
			result[entityID] = change
		}
	}

	return result
}
