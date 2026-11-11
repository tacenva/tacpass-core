package vault

import (
	"errors"
	"strings"

	tacenvaentity "github.com/tacenva/tacenva-core/entity"
	"github.com/tacenva/tacenva-core/genericerror"
	"github.com/tacenva/tacenva-core/sync"
	"github.com/tacenva/tacenva-core/util/credential"
	"github.com/tacenva/tacpass-core/contract"
	tacpassentity "github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/internal/vaultaccess"
	"github.com/tacenva/tacpass-core/vaultrecord"
	"gorm.io/gorm"
)

type SotService struct {
	repository         *repository
	vaultaccessService *vaultaccess.Service
	vaultRecordService *vaultrecord.Service
	syncService        *sync.Service

	vaultDir *string
}

func (s *SotService) SetConfig(vaultDir string) {
	s.vaultDir = &vaultDir
}

func NewSotService(
	repository *repository,
	vaultaccessService *vaultaccess.Service,
	vaultRecordService *vaultrecord.Service,
	syncService *sync.Service,
) *SotService {
	return &SotService{
		repository:         repository,
		vaultaccessService: vaultaccessService,
		vaultRecordService: vaultRecordService,
		syncService:        syncService,
	}
}

func (s *SotService) create(
	tx *gorm.DB,
	vault *tacpassentity.Vault,
	vaultAccessList []tacpassentity.VaultAccess,
) error {
	groupIDs := make([]string, 0, len(vaultAccessList))
	for _, vaultAccess := range vaultAccessList {
		groupIDs = append(groupIDs, vaultAccess.AccessGroupID)
	}
	vault.GroupIDs = groupIDs
	if err := s.repository.Create(tx, vault); err != nil {
		return err
	}

	if err := s.vaultaccessService.Sync(tx, vault.ID, vaultAccessList); err != nil {
		return err
	}
	return nil
}

func (s *SotService) Create(
	authorizedUser *tacenvaentity.User,
	vault *tacpassentity.Vault,
	lastChangeID *string,
) error {
	if err := s.verifyWriterAccess(
		authorizedUser,
	); err != nil {
		return err
	}

	publicKeyOfGroups, err := s.vaultaccessService.PublicKeyOfGroups(
		authorizedUser,
		vault.GroupIDs,
	)
	if err != nil {
		return err
	}

	unwrappedVaultKey, err := credential.Generate(32)
	if err != nil {
		return err
	}

	vaultAccessList, err := s.vaultaccessService.Generate(publicKeyOfGroups, []byte(unwrappedVaultKey))
	if err != nil {
		return err
	}

	err = s.repository.db.Transaction(func(tx *gorm.DB) error {
		err := s.create(tx, vault, vaultAccessList)
		if err != nil {
			return err
		}
		if err := s.vaultRecordService.Local.Init(*s.vaultDir, vault.ID, unwrappedVaultKey); err != nil {
			return err
		}

		if err := s.syncService.RecordChange(
			tx,
			lastChangeID,
			syncEntityVault,
			vault.ID,
			tacenvaentity.OperationCreate,
			authorizedUser.AccessUnit.SotID,
			authorizedUser.IdentityKey(),
		); err != nil {
			return err
		}

		return nil
	})

	return err
}

func (s *SotService) update(
	tx *gorm.DB,
	vault *tacpassentity.Vault,
	vaultAccessList []tacpassentity.VaultAccess,
) error {
	if err := genericerror.ValidateRequired(map[string]any{
		"vault id":   vault.ID,
		"vault name": vault.Name,
	}); err != nil {
		return err
	}

	groupIDs := make([]string, 0, len(vaultAccessList))
	for _, vaultAccess := range vaultAccessList {
		groupIDs = append(groupIDs, vaultAccess.AccessGroupID)
	}
	vault.GroupIDs = groupIDs
	result := s.repository.Update(tx, vault)
	if result.Error != nil {
		return result.Error
	}

	if err := s.vaultaccessService.Sync(tx, vault.ID, vaultAccessList); err != nil {
		return err
	}

	return nil
}

func (s *SotService) Update(
	authorizedUser *tacenvaentity.User,
	vault *tacpassentity.Vault,
	unwrappedVaultkey []byte,
	lastChangeID *string,
) error {
	if vault == nil {
		return genericerror.ErrRequired("vault")
	}

	if err := s.verifyVaultAccess(
		authorizedUser,
		vault.ID,
	); err != nil {
		return err
	}

	vault.ID = strings.TrimSpace(vault.ID)
	vault.Name = strings.TrimSpace(vault.Name)

	publicKeyOfGroups, err := s.vaultaccessService.PublicKeyOfGroups(
		authorizedUser,
		vault.GroupIDs,
	)
	if err != nil {
		return err
	}

	vaultAccessList, err := s.vaultaccessService.Generate(publicKeyOfGroups, unwrappedVaultkey)
	if err != nil {
		return err
	}

	return s.repository.db.Transaction(func(tx *gorm.DB) error {
		err := s.update(tx, vault, vaultAccessList)
		if err != nil {
			return err
		}

		return s.syncService.RecordChange(
			tx,
			lastChangeID,
			syncEntityVault,
			vault.ID,
			tacenvaentity.OperationUpdate,
			authorizedUser.AccessUnit.SotID,
			authorizedUser.IdentityKey(),
		)
	})
}

func (s *SotService) delete(
	tx *gorm.DB,
	vaultID string,
) error {
	if err := s.repository.Delete(
		tx,
		vaultID,
	); err != nil {
		return err
	}

	if err := s.vaultRecordService.Destroy(
		*s.vaultDir,
		vaultID,
	); err != nil {
		return err
	}

	return nil
}

func (s *SotService) Delete(
	authorizedUser *tacenvaentity.User,
	vaultID string,
	sotID string,
	lastChangeID *string,
) error {
	if err := s.verifyVaultAccess(
		authorizedUser,
		vaultID,
	); err != nil {
		return err
	}

	vault, err := s.repository.FindByID(vaultID)
	if err != nil {
		return err
	}

	if vault == nil {
		return genericerror.ErrRequired("vault")
	}

	return s.repository.db.Transaction(func(tx *gorm.DB) error {
		err := s.delete(tx, vault.ID)
		if err != nil {
			return err
		}

		if err := s.syncService.RecordChange(
			tx,
			lastChangeID,
			syncEntityVault,
			vault.ID,
			tacenvaentity.OperationDelete,
			sotID,
			authorizedUser.IdentityKey(),
		); err != nil {
			return err
		}

		return nil
	})
}

func (s *SotService) List(
	authorizedUser *tacenvaentity.User,
) ([]tacpassentity.Vault, error) {
	vaultList, err := s.repository.FindAccessible(
		authorizedUser.AccessUnit.GroupID,
	)
	if err != nil {
		return nil, err
	}

	return vaultList, nil
}

func (s *SotService) applyChanges(
	tx *gorm.DB,
	appliedChanges *contract.PendingVaultChange,
) error {
	syncChanges := appliedChanges.SyncChanges
	for _, change := range syncChanges {
		vaultID := change.EntityID
		switch change.Operation {
		case tacenvaentity.OperationCreate:
			existData, exist := appliedChanges.VaultChangeDataList[vaultID]
			if !exist {
				continue
			}

			err := s.create(tx, &existData.Vault, existData.VaultAccessList)
			if err != nil {
				return err
			}

		case tacenvaentity.OperationUpdate:
			existData, exist := appliedChanges.VaultChangeDataList[vaultID]
			if !exist {
				continue
			}

			err := s.update(tx, &existData.Vault, existData.VaultAccessList)
			if err != nil {
				return err
			}

		case tacenvaentity.OperationDelete:
			err := s.delete(tx, vaultID)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func containsGroupID(groupIDs []string, target string) bool {
	for _, groupID := range groupIDs {
		if groupID == target {
			return true
		}
	}

	return false
}

func (s *SotService) filterAllowedChangesOnly(
	authorizedGroupID string,
	replicaChanges *contract.PendingVaultChange,
) (*contract.PendingVaultChange, error) {
	if err := genericerror.ValidateRequired(map[string]any{
		"group id":        authorizedGroupID,
		"replica changes": replicaChanges,
	}); err != nil {
		return nil, err
	}

	allowedChanges := &contract.PendingVaultChange{
		SyncChanges: make(
			[]tacenvaentity.SyncChange,
			0,
			len(replicaChanges.SyncChanges),
		),
		VaultChangeDataList: make(
			map[contract.VaultID]contract.VaultChangeData,
		),
	}

	seen := make(map[contract.VaultID]bool, len(replicaChanges.SyncChanges))

	for _, syncChange := range replicaChanges.SyncChanges {
		vaultID := contract.VaultID(syncChange.EntityID)

		isAllowed, exists := seen[vaultID]
		if !exists {
			switch syncChange.Operation {
			case tacenvaentity.OperationCreate:
				changeData, ok := replicaChanges.VaultChangeDataList[vaultID]
				if !ok {
					return nil, genericerror.ErrRequired("change data")
				}

				isAllowed = containsGroupID(
					changeData.Vault.GroupIDs,
					authorizedGroupID,
				)

			default:
				allowed, err := s.vaultaccessService.Exists(
					syncChange.EntityID,
					authorizedGroupID,
				)
				if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
					return nil, err
				}

				isAllowed = allowed
			}

			seen[vaultID] = isAllowed
		}

		if !isAllowed {
			continue
		}

		allowedChanges.SyncChanges = append(
			allowedChanges.SyncChanges,
			syncChange,
		)

		if changeData, exists := replicaChanges.VaultChangeDataList[vaultID]; exists {
			allowedChanges.VaultChangeDataList[vaultID] = changeData
		}
	}

	return allowedChanges, nil
}

func (s *SotService) Sync(
	authorizedUser *tacenvaentity.User,
	sotStartChangeID string,
	limit int64,
	replicaChanges *contract.PendingVaultChange,
) (*contract.PendingVaultChange, error) {
	if err := s.verifyWriterAccess(
		authorizedUser,
	); err != nil {
		return nil, err
	}

	allowedChanges, err := s.filterAllowedChangesOnly(
		authorizedUser.AccessUnit.GroupID,
		replicaChanges,
	)
	if err != nil {
		return nil, err
	}
	// debug.LogJSON("Replica changes", replicaChanges)
	// debug.LogJSON("Allowed changes", allowedChanges)

	sotChanges, err := s.GetChangesAfter(
		authorizedUser,
		sotStartChangeID,
		limit,
	)
	if err != nil {
		return nil, err
	}

	appliedChanges, appliedData := sync.MergePendingChanges(
		allowedChanges.SyncChanges,
		sotChanges.SyncChanges,
		allowedChanges.VaultChangeDataList,
		sotChanges.VaultChangeDataList,
		nil,
	)
	// debug.LogJSON("applied changes", appliedChanges)

	err = s.repository.db.Transaction(func(tx *gorm.DB) error {
		if err := s.applyChanges(
			tx,
			&contract.PendingVaultChange{
				SyncChanges:         appliedChanges,
				VaultChangeDataList: appliedData,
			}); err != nil {
			return err
		}

		return s.syncService.InsertSyncChanges(
			tx,
			authorizedUser.AccessUnit.SotID,
			syncEntityVault,
			allowedChanges.SyncChanges,
		)
	})
	if err != nil {
		return nil, err
	}

	return allowedChanges, nil
}

func (s *SotService) GetWrappedKey(
	authorizedUser *tacenvaentity.User,
	vaultID string,
) (string, error) {
	vaFromVault, err := s.vaultaccessService.Get(
		vaultID,
		authorizedUser.AccessUnit.GroupID,
	)

	if err != nil {
		return "", err
	}

	return vaFromVault.WrappedVaultKey, nil
}

func (s *SotService) GetChangesAfter(
	authorizedUser *tacenvaentity.User,
	syncLastChangeID string,
	syncLimit int64,
) (*contract.PendingVaultChange, error) {
	changes, err := s.syncService.GetChangesAfter(
		authorizedUser.AccessUnit.SotID,
		syncEntityVault,
		syncLastChangeID,
		syncLimit,
	)
	if err != nil {
		return nil, err
	}

	vaultIDs := make([]string, 0, len(changes))
	seen := make(map[string]struct{}, len(changes))

	for i := range changes {
		id := changes[i].EntityID
		if _, exists := seen[id]; exists {
			continue
		}

		seen[id] = struct{}{}
		vaultIDs = append(vaultIDs, id)
	}

	vaultChangeDataList, err := s.vaultaccessService.FindVaultChangeData(
		vaultIDs,
		authorizedUser.AccessUnit.GroupID,
	)
	if err != nil {
		return nil, err
	}

	return &contract.PendingVaultChange{
		SyncChanges:         changes,
		VaultChangeDataList: vaultChangeDataList,
	}, nil
}

func (s *SotService) GetChangeCount(
	authorizedUser *tacenvaentity.User,
	syncLastChangeID string,
) (*contract.PendingTotalChanges, error) {
	totalVaultChanges, err := s.syncService.GetChangeCount(
		authorizedUser.AccessUnit.SotID,
		syncEntityVault,
		syncLastChangeID,
	)
	if err != nil {
		return nil, err
	}

	return &contract.PendingTotalChanges{
		Count: totalVaultChanges,
	}, nil
}
