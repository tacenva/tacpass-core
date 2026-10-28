package vault

import (
	"errors"
	"strings"

	tacenvaentity "github.com/tacenva/tacenva-core/entity"
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

	if err := s.vaultaccessService.Sync(tx, vaultAccessList); err != nil {
		return err
	}
	return nil
}

func (s *SotService) Create(
	authorizedUser *tacenvaentity.User,
	vault *tacpassentity.Vault,
	lastChangeID *string,
) error {
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

	err = s.repository.Transaction(func(tx *gorm.DB) error {
		err := s.create(tx, vault, vaultAccessList)
		if err != nil {
			return nil
		}
		if err := s.vaultRecordService.Local.Init(vault.ID, unwrappedVaultKey); err != nil {
			return err
		}

		if err := s.syncService.RecordChange(
			tx,
			lastChangeID,
			syncEntityVault,
			vault.ID,
			tacenvaentity.OperationCreate,
			authorizedUser.AccessUnit.SotID,
			authorizedUser.Hostname,
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
	if vault.ID == "" {
		return ErrNotFound
	}

	if vault.Name == "" {
		return ErrNameEmpty
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

	if err := s.vaultaccessService.Sync(tx, vaultAccessList); err != nil {
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
		return ErrNotFound
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

	return s.repository.Transaction(func(tx *gorm.DB) error {
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
			authorizedUser.Hostname,
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
	id string,
	sotID string,
	lastChangeID *string,
) error {
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
			authorizedUser.Hostname,
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

func (s *SotService) GetChangesAfter(
	authorizedUser *tacenvaentity.User,
	syncLastChangeID string,
	syncLimit int,
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

	vaultChangeDataList := make(map[string]contract.VaultChangeData)

	for _, change := range changes {
		if _, exists := vaultChangeDataList[change.EntityID]; exists {
			continue
		}

		vault, err := s.repository.FindByID(change.EntityID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				continue
			}
			return nil, err
		}

		vaultChangeDataList[change.EntityID] = contract.VaultChangeData{
			Vault: *vault,
		}
	}

	for vaultID, data := range vaultChangeDataList {
		vaFromVault, err := s.vaultaccessService.Get(
			vaultID,
			authorizedUser.AccessUnit.GroupID,
		)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				continue
			}

			return nil, err
		}

		data.VaultAccessList = []tacpassentity.VaultAccess{*vaFromVault}
		vaultChangeDataList[vaultID] = data
	}

	return &contract.PendingVaultChange{
		SyncChanges:         changes,
		VaultChangeDataList: vaultChangeDataList,
	}, nil
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

func (s *SotService) Sync(
	authorizedUser *tacenvaentity.User,
	sotStartChangeID string,
	limit int,
	replicaChanges *contract.PendingVaultChange,
) error {
	// TODO: get allowed to edit too
	sotChanges, err := s.GetChangesAfter(
		authorizedUser,
		sotStartChangeID,
		limit,
	)
	if err != nil {
		return err
	}

	appliedChanges, appliedData := sync.MergePendingChanges(
		replicaChanges.SyncChanges,
		sotChanges.SyncChanges,
		replicaChanges.VaultChangeDataList,
		sotChanges.VaultChangeDataList,
		nil,
	)

	if appliedChanges == nil || appliedData == nil {
		//
	}

	err = s.repository.db.Transaction(func(tx *gorm.DB) error {
		err := s.applyChanges(tx, &contract.PendingVaultChange{
			SyncChanges:         appliedChanges,
			VaultChangeDataList: appliedData,
		})
		if err != nil {
			return err
		}

		err = s.syncService.InsertSyncChanges(
			authorizedUser.AccessUnit.SotID,
			syncEntityVault,
			replicaChanges.SyncChanges, // TODO: changes to something right
		)
		if err != nil {
			return err
		}
		return nil
	})

	return err
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
