package vault

import (
	"encoding/json"
	"errors"
	"log"
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
	vaultrecordRepository := vaultrecord.NewRepository(
		repository.db,
	)
	return &Service{
		repository: repository,
		vaultRecordService: vaultrecord.NewService(
			syncService,
			vaultrecordRepository,
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
) (map[string][]entity.Permission, error) {
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

func (s *Service) CreateOnSot(
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

		vaultPermissions, err := s.GetPublicKeysByGroupIDs(authUser, vault.GroupIDs, sotID)
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
			len(vaultPermissions),
		)

		for groupID := range vaultPermissions {
			curPermissions := vaultPermissions[groupID]
			for _, permissionData := range curPermissions {
				keyPair := keyring.FromPublicKey(permissionData.PublicKey)
				wrappedVaultKey, err := keyPair.Seal([]byte(vaultKey))
				if err != nil {
					continue
				}

				vaList = append(vaList, entity.VaultAccess{
					VaultID:      vault.ID,
					PermissionID: permissionData.ID,
					VaultKey:     wrappedVaultKey,
				})
			}
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

func (s *Service) UpdateOnSot(
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

		for groupID := range toCreate {
			curPermission := toCreate[groupID]
			for _, permissionData := range curPermission {
				vaList = append(vaList, entity.VaultAccess{
					VaultID:      vault.ID,
					PermissionID: permissionData.ID,
				})
			}
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

func (s *Service) DeleteOnSot(
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

func (s *Service) GetChangesAfterOnSot(
	sotID string,
	syncLastChangeID string,
	syncLimit int,
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
			var vaultFound entity.Vault

			err := dbFile.FindFirstWhere(
				&vaultFound,
				func(data map[string]any) bool {
					ID, ok := data["id"]
					return ok && ID == change.EntityID
				},
			)

			if err != nil {
				if errors.Is(err, database.ErrRecordNotFound) {
					continue
				}
				return nil, err
			}

			existing, exist := vaultChangeDataList[vaultFound.ID]
			if exist {
				continue
			}

			existing.Vault = vaultFound
			existing.Vault.WrappedKey = ""

			vaultChangeDataList[vaultFound.ID] = existing
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
	shouldUpdateData func(mergedData, compData contract.VaultChangeData) bool,
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
		shouldUpdateData,
	)

	return &contract.PendingVaultChange{
		SyncChanges:         changes,
		VaultChangeDataList: data,
	}
}

func (s *Service) applyChangeOnSot(
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

				if err := s.vaultaccessService.Sync(tx, vaultID, vaultChangeData.VaultAccessList); err != nil {
					return err
				}

			case sync.OperationUpdate:
				if !exist {
					continue
				}

				if err := s.repository.Update(tx, &vaultChangeData.Vault).Error; err != nil {
					return err
				}

				if err := s.vaultaccessService.Sync(tx, vaultID, vaultChangeData.VaultAccessList); err != nil {
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

	data, err := json.Marshal(vaultChange)
	if err != nil {
		log.Printf("JSON marshal error: %+v", err)
		return err
	}

	log.Printf("JSON payload : %s", string(data))

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
		vault := vaultChangeData.Vault

		if len(vaultChangeData.VaultAccessList) > 0 {
			vaData := vaultChangeData.VaultAccessList[0]
			vault.WrappedKey = vaData.VaultKey
		}

		switch change.Operation {
		case sync.OperationCreate:
			if err := dbFile.Insert(&vault).Error; err != nil {
				return err
			}

		case sync.OperationUpdate:
			if err := dbFile.Update(&vault).Error; err != nil {
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
	groupID string,
	replicaChanges *contract.PendingVaultChange,
	sotChanges *contract.PendingVaultChange,
	dbFile *database.DatabaseFile,
) error {
	appliedChanges := s.MergePendingVaultChange(
		sotChanges,
		replicaChanges,
		func(mergedData, compData contract.VaultChangeData) bool {
			if slices.Contains(compData.Vault.GroupIDs, groupID) {
				return slices.Contains(mergedData.Vault.GroupIDs, groupID)
			}
			return true
		},
	)
	if appliedChanges == nil {
		return nil
	}

	if err := s.ApplyChangeOnReplica(appliedChanges, dbFile); err != nil {
		return err
	}

	return s.insertSyncChanges(sotID, sotChanges.SyncChanges)
}

func (s *Service) SyncOnSot(
	sotID string,
	groupID string,
	changedBy string,
	sotStartChangeID string,
	limit int,
	replicaChanges *contract.PendingVaultChange,
) (successList *contract.PendingVaultChange, err error) {
	successList, err = s.ValidateGroupOnSot(
		groupID,
		replicaChanges,
	)
	if err != nil {
		return nil, err
	}

	sotChanges, err := s.GetChangesAfterOnSot(
		sotID,
		sotStartChangeID,
		limit,
	)
	if err != nil {
		return nil, err
	}

	appliedChanges := s.MergePendingVaultChange(
		successList,
		sotChanges,
		nil,
	)
	if appliedChanges == nil {
		return nil, nil
	}

	if err := s.applyChangeOnSot(appliedChanges); err != nil {
		return nil, err
	}

	for i := range successList.SyncChanges {
		successList.SyncChanges[i].ChangedBy = changedBy
	}

	if err := s.insertSyncChanges(sotID, successList.SyncChanges); err != nil {
		return nil, err
	}

	return successList, nil
}

func (s *Service) ValidateGroupOnSot(
	groupID string,
	changes *contract.PendingVaultChange,
) (allowed *contract.PendingVaultChange, err error) {
	allowed = &contract.PendingVaultChange{
		SyncChanges:         make([]sync.SyncChange, 0),
		VaultChangeDataList: make(map[string]contract.VaultChangeData),
	}

	err = s.repository.Transaction(func(tx *gorm.DB) error {
		vaultValidationCache := make(map[string]bool)

		for _, syncChange := range changes.SyncChanges {
			vaultID := syncChange.EntityID
			vaultData := changes.VaultChangeDataList[vaultID]

			if isValidated, exists := vaultValidationCache[vaultID]; exists {
				if isValidated {
					allowed.SyncChanges = append(
						allowed.SyncChanges,
						syncChange,
					)
				}
				continue
			}

			if syncChange.Operation == sync.OperationCreate {
				allowed.SyncChanges = append(
					allowed.SyncChanges,
					syncChange,
				)
				allowed.VaultChangeDataList[vaultID] = vaultData
				vaultValidationCache[vaultID] = true
				continue
			}

			isAllowed, err := s.repository.IsAllowedToChange(
				tx,
				vaultID,
				groupID,
			)
			if err != nil {
				return err
			}

			vaultValidationCache[vaultID] = isAllowed

			if isAllowed {
				allowed.SyncChanges = append(
					allowed.SyncChanges,
					syncChange,
				)
				allowed.VaultChangeDataList[vaultID] = vaultData
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return allowed, nil
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

func (s *Service) VaultAccessList(
	vaultID string,
	permissionID string,
) (*entity.VaultAccess, error) {
	return s.vaultaccessService.FindByVaultAndPermission(
		vaultID,
		permissionID,
	)
}
