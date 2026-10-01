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
		permissionService: permissionService,
		syncService:       syncService,
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

func (s *Service) CreateOnSoT(
	authUser *entity.User,
	name string,
	sotID string,
	lastChangeID *string,
) (*entity.Vault, error) {
	if authUser == nil || !authUser.HasWritePermission() {
		return nil, ErrPermission
	}

	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrNameEmpty
	}

	vault := &entity.Vault{
		ID:   ulid.Make().String(),
		Name: name,
	}

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
		)
	})
	if err != nil {
		return nil, err
	}

	return vault, nil
}

func (s *Service) CreateOnReplica(
	authUser *entity.User,
	name string,
	sotID string,
	lastChangeID *string,
	dbFile *database.DatabaseFile,
) (*entity.VaultAccess, error) {
	if authUser == nil || !authUser.HasWritePermission() {
		return nil, ErrPermission
	}

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

	vaultAccess := &entity.VaultAccess{
		ID:           ulid.Make().String(),
		VaultID:      vault.ID,
		PermissionID: authUser.PermissionID,
		VaultKey:     vaultKey,
		Vault:        *vault,
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

	return vaultAccess, nil
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
		)
	})

	if err != nil {
		return nil, err
	}

	return vault, nil
}

func (s *Service) UpdateOnReplica(
	authUser *entity.User,
	id string,
	name string,
	sotID string,
	lastChangeID *string,

	dbFile *database.DatabaseFile,
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

	var vault *entity.Vault
	err := dbFile.Find(id, &vault)
	if err != nil {
		return nil, err
	}
	if vault == nil {
		return nil, ErrNotFound
	}

	vault.Name = name

	err = dbFile.Update(vault)
	if err != nil {
		return nil, err
	}

	err = s.syncService.RecordChangeWithoutTx(
		lastChangeID,
		syncEntityVault,
		vault.ID,
		sync.OperationUpdate,
		sotID,
	)
	if err != nil {
		return nil, err
	}

	return vault, nil
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
	authUser *entity.User,
	vaultDir string,
	id string,
	sotID string,
	lastChangeID *string,

	dbFile *database.DatabaseFile,
) error {
	if authUser == nil || !authUser.HasWritePermission() {
		return ErrPermission
	}

	id = strings.TrimSpace(id)

	if id == "" {
		return ErrNotFound
	}

	var vault *entity.Vault
	err := dbFile.Find(id, &vault)
	if err != nil {
		return err
	}
	if vault == nil {
		return ErrNotFound
	}

	if vault == nil {
		return ErrNotFound
	}

	_, err = dbFile.Delete(vault.ID)
	if err != nil {
		return err
	}

	err = s.syncService.RecordChangeWithoutTx(
		lastChangeID,
		syncEntityVault,
		vault.ID,
		sync.OperationDelete,
		sotID,
	)
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
	authUser *entity.User,
	sotID string,
	startID string,
	limit int,
	dbFile *database.DatabaseFile,
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
	authUser *entity.User,
	sotID string,
	startID string,
) (int64, error) {
	return s.syncService.GetChangeCount(
		sotID,
		syncEntityVault,
		startID,
	)
}

func (s *Service) GiveAccess(
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

			vault, err := s.CreateOnSoT(
				authUser,
				vaultChange.Vault.Name,
				sotID,
				&vaultChange.SyncChange.ID,
			)
			if err != nil {
				return err
			}

			vaultChange.Vault.ID = vault.ID

			if err := s.GiveAccess(
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
	authUser *entity.User,
	vaultDir string,
	sotID string,
	vaultChanges []contract.PendingVaultChange,
	dbFile *database.DatabaseFile,
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
			_, err := s.CreateOnReplica(
				authUser,
				vaultDir,
				sotID,
				&vaultChange.SyncChange.ID,
				dbFile,
			)
			if err != nil {
				return err
			}

		case sync.OperationUpdate:
			_, err := s.UpdateOnReplica(
				authUser,
				vaultChange.Vault.ID,
				vaultChange.Vault.Name,
				sotID,
				&vaultChange.SyncChange.ID,
				dbFile,
			)
			if err != nil {
				return err
			}

		case sync.OperationDelete:
			err := s.DeleteOnReplica(
				authUser,
				vaultDir,
				vaultChange.Vault.ID,
				sotID,
				&vaultChange.SyncChange.ID,
				dbFile,
			)
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
