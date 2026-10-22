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

func (s *Service) VaultList(
	authUser *entity.User,
) ([]entity.Vault, error) {
	if authUser == nil {
		return nil, ErrPermission
	}

	vaultList, err := s.repository.FindAccessible(
		authUser.Permission.GroupID,
	)
	if err != nil {
		return nil, err
	}

	return vaultList, nil
}

func (s *Service) GetPublicKeysByGroupIDs(
	authUser *entity.User,
	groupIDs []string,
	sotID string,
) ([]entity.Permission, error) {
	if authUser == nil || !authUser.HasWritePermission() {
		return nil, ErrPermission
	}

	return s.permissionService.GetPublicKeysByGroupIDs(groupIDs, sotID)
}

func (s *Service) ListPermissionGroup(sotID string) ([]entity.PermissionGroup, error) {
	sotID = strings.TrimSpace(sotID)
	return s.repository.ListPermissionGroup(sotID)
}

func (s *Service) ToGroupIDs(
	permissionGroups []entity.PermissionGroup,
) []string {
	groupIDs := make([]string, len(permissionGroups))
	for _, group := range permissionGroups {
		groupIDs = append(groupIDs, group.ID)
	}
	return groupIDs
}

func (s *Service) CreateOnSoT(
	authUser *entity.User,
	vaultDir string,
	vault *entity.Vault,
	sotID string,
	lastChangeID *string,
) error {
	if authUser == nil || !authUser.HasWritePermission() {
		return ErrPermission
	}

	err := s.repository.Transaction(func(tx *gorm.DB) error {
		if err := s.repository.Create(tx, vault); err != nil {
			return err
		}

		vaultPermission, err := s.GetPublicKeysByGroupIDs(authUser, vault.GroupIDs, sotID)
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
			len(vaultPermission),
		)

		for _, permissionData := range vaultPermission {
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

		if _, err := s.vaultaccessService.CreateBulkTx(tx, vaList); err != nil {
			return err
		}

		if err := s.vaultRecordService.Init(vaultDir, vault.ID, vaultKey); err != nil {
			return err
		}

		if err := s.syncService.RecordChange(
			tx,
			lastChangeID,
			syncEntityVault,
			vault.ID,
			sync.OperationCreate,
			sotID,
			authUser.Hostname,
		); err != nil {
			return err
		}

		return nil
	})

	return err
}

func (s *Service) CreateOnReplica(
	vaultDir string,
	vault *entity.Vault,
	sotID string,
	lastChangeID *string,
	dbFile *database.DatabaseFile,

	keypair *keyring.KeyPair,
) error {
	vault.Name = strings.TrimSpace(vault.Name)
	if vault.Name == "" {
		return ErrNameEmpty
	}

	vaultKey, err := credential.Generate(32)
	if err != nil {
		return err
	}

	if vault.ID == "" {
		vault.ID = ulid.Make().String()
	}

	keyPair := keyring.FromPublicKey(keypair.PublicKey)
	wrappedVaultKey, err := keyPair.Seal([]byte(vaultKey))
	vault.WrappedKey = wrappedVaultKey

	if err := dbFile.Insert(vault).Error; err != nil {
		return err
	}

	if err := s.syncService.RecordChangeWithoutTx(
		lastChangeID,
		syncEntityVault,
		vault.ID,
		sync.OperationCreate,
		sotID,
		"",
	); err != nil {
		return err
	}
	if err := s.vaultRecordService.Init(vaultDir, vault.ID, vaultKey); err != nil {
		return err
	}

	return nil
}

func diffIDs(oldIDs, newIDs []string) (toCreate, toDelete []string) {
	oldSet := make(map[string]struct{}, len(oldIDs))
	newSet := make(map[string]struct{}, len(newIDs))

	for _, id := range oldIDs {
		oldSet[id] = struct{}{}
	}

	for _, id := range newIDs {
		newSet[id] = struct{}{}
	}

	for _, id := range newIDs {
		if _, exists := oldSet[id]; !exists {
			toCreate = append(toCreate, id)
		}
	}

	for _, id := range oldIDs {
		if _, exists := newSet[id]; !exists {
			toDelete = append(toDelete, id)
		}
	}

	return toCreate, toDelete
}

func (s *Service) UpdateOnSoT(
	authUser *entity.User,
	vault *entity.Vault,
	sotID string,
	lastChangeID *string,
) error {
	if authUser == nil || !authUser.HasWritePermission() {
		return ErrPermission
	}

	vault.ID = strings.TrimSpace(vault.ID)
	vault.Name = strings.TrimSpace(vault.Name)

	if vault.ID == "" {
		return ErrNotFound
	}

	if vault.Name == "" {
		return ErrNameEmpty
	}

	_, err := s.repository.FindByID(vault.ID)
	if err != nil {
		return err
	}

	err = s.repository.Transaction(func(tx *gorm.DB) error {
		var oldVault entity.Vault
		if err := tx.First(&oldVault, "id = ?", vault.ID).Error; err != nil {
			return err
		}

		result := s.repository.Update(tx, vault)
		if result.Error != nil {
			return result.Error
		}

		if result.RowsAffected > 0 {
			return nil
		}

		toCreateIds, toDeleteIds := diffIDs(
			oldVault.GroupIDs,
			vault.GroupIDs,
		)

		toCreate, err := s.permissionService.GetPublicKeysByGroupIDs(toCreateIds, sotID)
		if err != nil {
			return err
		}

		vaList := make(
			[]entity.VaultAccess,
			0,
			len(toCreate),
		)

		for _, permissionData := range toCreate {
			vaList = append(vaList, entity.VaultAccess{
				VaultID:      vault.ID,
				PermissionID: permissionData.ID,
			})
		}

		if _, err := s.vaultaccessService.CreateBulkTx(tx, vaList); err != nil {
			return err
		}

		if err := s.vaultaccessService.DeleteBulkByGroupIDsTx(tx, toDeleteIds); err != nil {
			return err
		}

		if err := s.syncService.RecordChange(
			tx,
			lastChangeID,
			syncEntityVault,
			vault.ID,
			sync.OperationUpdate,
			sotID,
			authUser.Hostname,
		); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return err
	}

	return nil
}

func (s *Service) UpdateOnReplica(
	vault *entity.Vault,
	sotID string,
	lastChangeID *string,

	dbFile *database.DatabaseFile,
) error {
	vault.ID = strings.TrimSpace(vault.ID)
	vault.Name = strings.TrimSpace(vault.Name)

	if vault.ID == "" {
		return ErrNotFound
	}

	if vault.Name == "" {
		return ErrNameEmpty
	}

	result := dbFile.Update(vault)
	if result.Error != nil {
		return result.Error
	}

	if err := s.syncService.RecordChangeWithoutTx(
		lastChangeID,
		syncEntityVault,
		vault.ID,
		sync.OperationUpdate,
		sotID,
		"",
	); err != nil {
		return err
	}

	return nil
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
			authUser.Hostname,
		); err != nil {
			return err
		}

		if err := s.vaultRecordService.Destroy(
			vaultDir,
			vault.ID,
		); err != nil {
			return err
		}

		return nil
	})
}

func (s *Service) DeleteOnReplica(
	vaultDir string,
	vaultID string,
	sotID string,
	lastChangeID *string,

	dbFile *database.DatabaseFile,
) error {
	vaultID = strings.TrimSpace(vaultID)

	if vaultID == "" {
		return ErrNotFound
	}

	if err := dbFile.Delete(vaultID).Error; err != nil {
		return err
	}

	if err := s.syncService.RecordChangeWithoutTx(
		lastChangeID,
		syncEntityVault,
		vaultID,
		sync.OperationDelete,
		sotID,
		"",
	); err != nil {
		return err
	}

	if err := s.vaultRecordService.Destroy(
		vaultDir,
		vaultID,
	); err != nil {
		return err
	}

	return nil
}

func (s *Service) GetSyncLatestChangeID(
	sotID string,
) (string, error) {
	vaultSyncState, err := s.syncService.GetSyncState(
		sotID,
		syncEntityVault,
	)
	if err != nil {
		return "", nil
	}

	return vaultSyncState.LastChangeID, err
}

func (s *Service) GetChangesAfterOnSoT(
	authUser *entity.User,
	sotID string,
	syncLastChangeID string,
	syncLimit int,
) (*contract.PendingVaultChange, error) {
	if authUser == nil || authUser.ID == "" {
		return nil, ErrPermission
	}

	changes, err := s.syncService.GetChangesAfter(
		sotID,
		syncEntityVault,
		syncLastChangeID,
		syncLimit,
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
	syncLastChangeID string,
	syncLimit int,
	dbFile *database.DatabaseFile,
) (*contract.PendingVaultChange, error) {
	changes, err := s.syncService.GetChangesAfter(
		sotID,
		syncEntityVault,
		syncLastChangeID,
		syncLimit,
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
	syncLastChangeID string,
) (*contract.PendingTotalChanges, error) {
	vaultChangeCount, err := s.syncService.GetChangeCount(
		sotID,
		syncEntityVault,
		syncLastChangeID,
	)
	if err != nil {
		return nil, err
	}

	return &contract.PendingTotalChanges{
		Count: vaultChangeCount,
	}, nil
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
			if err := dbFile.Insert(&vaData).Error; err != nil {
				return err
			}

		case sync.OperationUpdate:
			if err := dbFile.Update(&vaData).Error; err != nil {
				if errors.Is(err, database.ErrRecordNotFound) {
					continue
				}
				return err
			}

		case sync.OperationDelete:
			if err := dbFile.Delete(vaultID).Error; err != nil {
				if errors.Is(err, database.ErrRecordNotFound) {
					continue
				}
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
	replicaChanges *contract.PendingVaultChange,
	changedBy string,
) error {
	appliedChanges := s.MergePendingVaultChange(replicaChanges, nil)
	if appliedChanges == nil {
		return nil
	}

	if err := s.applyChangeOnSoT(appliedChanges); err != nil {
		return err
	}

	changes := replicaChanges.SyncChanges
	for i := range changes {
		changes[i].ChangedBy = changedBy
	}

	return s.insertSyncChanges(sotID, replicaChanges.SyncChanges)
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

func (s *Service) FindByVaultAndPermission(
	vaultID string,
	permissionID string,
) (*entity.VaultAccess, error) {
	return s.vaultaccessService.FindByVaultAndPermission(
		vaultID,
		permissionID,
	)
}
