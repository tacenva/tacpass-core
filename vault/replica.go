package vault

import (
	"errors"
	"slices"
	"strings"

	"github.com/oklog/ulid/v2"
	"github.com/tacenva/database"
	tacenvaentity "github.com/tacenva/tacenva-core/entity"
	"github.com/tacenva/tacenva-core/sync"
	"github.com/tacenva/tacenva-core/util/credential"
	"github.com/tacenva/tacenva-core/util/keyring"
	"github.com/tacenva/tacpass-core/contract"
	"github.com/tacenva/tacpass-core/entity"
	tacpassentity "github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/vaultrecord"
)

type ReplicaService struct {
	vaultRecordService *vaultrecord.Service
	syncService        *sync.Service

	vaultDir  *string
	vaultFile *database.DatabaseFile
}

func NewReplicaService(
	vaultRecordService *vaultrecord.Service,
	syncService *sync.Service,
) *ReplicaService {
	return &ReplicaService{
		vaultRecordService: vaultRecordService,
		syncService:        syncService,
	}
}

func (s *ReplicaService) SetConfig(vaultDir, masterKey string) error {
	db := database.New(vaultDir)
	vaultFile, err := db.File("vault", masterKey, database.FileModeOpenOrCreate)
	if err != nil {
		return err
	}

	s.vaultDir = &vaultDir
	s.vaultFile = vaultFile

	return nil
}

func (s *ReplicaService) Create(
	vault *tacpassentity.Vault,
	sotID string,
	lastChangeID *string,

	keyPairOfAccessGroup *keyring.KeyPair,
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

	wrappedVaultKey, err := keyPairOfAccessGroup.Seal([]byte(vaultKey))
	vault.WrappedKey = wrappedVaultKey

	if err := s.vaultFile.Insert(vault).Error; err != nil {
		return err
	}

	if err := s.syncService.RecordChangeWithoutTx(
		lastChangeID,
		syncEntityVault,
		vault.ID,
		tacenvaentity.OperationCreate,
		sotID,
		"",
	); err != nil {
		return err
	}
	if err := s.vaultRecordService.Local.Init(vault.ID, vaultKey); err != nil {
		return err
	}

	return nil
}

func (s *ReplicaService) Update(
	vault *tacpassentity.Vault,
	sotID string,
	lastChangeID *string,
) error {
	vault.ID = strings.TrimSpace(vault.ID)
	vault.Name = strings.TrimSpace(vault.Name)

	if vault.ID == "" {
		return ErrNotFound
	}

	if vault.Name == "" {
		return ErrNameEmpty
	}

	result := s.vaultFile.Update(vault)
	if result.Error != nil {
		return result.Error
	}

	if err := s.syncService.RecordChangeWithoutTx(
		lastChangeID,
		syncEntityVault,
		vault.ID,
		tacenvaentity.OperationUpdate,
		sotID,
		"",
	); err != nil {
		return err
	}

	return nil
}

func (s *ReplicaService) Delete(
	vaultID string,
	sotID string,
	lastChangeID *string,
) error {
	vaultID = strings.TrimSpace(vaultID)

	if vaultID == "" {
		return ErrNotFound
	}

	if err := s.vaultFile.Delete(vaultID).Error; err != nil {
		return err
	}

	if err := s.syncService.RecordChangeWithoutTx(
		lastChangeID,
		syncEntityVault,
		vaultID,
		tacenvaentity.OperationDelete,
		sotID,
		"",
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

func (s *ReplicaService) List(
	groupID string,
) ([]tacpassentity.Vault, error) {
	var vaultList []tacpassentity.Vault
	err := s.vaultFile.FindWhere(&vaultList, func(m map[string]any) bool {
		groupIDs, ok := m["group_ids"].([]any)
		if !ok {
			return false
		}

		for _, value := range groupIDs {
			id, ok := value.(string)
			if ok && id == groupID {
				return true
			}
		}

		return false
	}).Order("ID ASC").Error
	if err != nil {
		return nil, err
	}

	return vaultList, nil
}

func (s *ReplicaService) GetChangesAfter(
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
		if change.Operation != tacenvaentity.OperationDelete {
			var vaultFound entity.Vault

			err := s.vaultFile.FindFirstWhere(
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

func (s *ReplicaService) applyChanges(
	replicaAccessGroupID string,
	appliedChanges *contract.PendingVaultChange,
) error {
	syncChanges := appliedChanges.SyncChanges
	setVault := func(vaultChangeData *contract.VaultChangeData, accessGroupID string) *tacpassentity.Vault {
		if len(vaultChangeData.VaultAccessList) == 0 {
			return nil
		}

		vault := vaultChangeData.Vault
		for _, vaData := range vaultChangeData.VaultAccessList {
			if vaData.AccessGroupID == accessGroupID {
				vault.WrappedKey = vaData.WrappedVaultKey
				break
			}
		}

		return &vault
	}

	for _, change := range syncChanges {
		vaultID := change.EntityID
		switch change.Operation {
		case tacenvaentity.OperationCreate:
			existData, exist := appliedChanges.VaultChangeDataList[vaultID]
			if !exist {
				continue
			}
			vault := setVault(&existData, replicaAccessGroupID)
			err := s.vaultFile.Insert(&vault).Error
			if err != nil {
				return err
			}

		case tacenvaentity.OperationUpdate:
			existData, exist := appliedChanges.VaultChangeDataList[vaultID]
			if !exist {
				continue
			}
			vault := setVault(&existData, replicaAccessGroupID)
			err := s.vaultFile.Update(&vault).Error
			if err != nil {
				if errors.Is(err, database.ErrRecordNotFound) {
					continue
				}

				return err
			}

		case tacenvaentity.OperationDelete:
			err := s.vaultFile.Delete(vaultID).Error
			if err != nil {
				if errors.Is(err, database.ErrRecordNotFound) {
					continue
				}
				return err
			}

			if err := s.vaultRecordService.Destroy(
				*s.vaultDir,
				vaultID,
			); err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *ReplicaService) Sync(
	sotID string,
	replicaAccessGroupID string,
	replicaChanges *contract.PendingVaultChange,
	sotChanges *contract.PendingVaultChange,
) error {
	appliedChanges, appliedData := sync.MergePendingChanges(
		sotChanges.SyncChanges,
		replicaChanges.SyncChanges,
		sotChanges.VaultChangeDataList,
		replicaChanges.VaultChangeDataList,
		func(mergedData, compData contract.VaultChangeData) bool {
			if slices.Contains(compData.Vault.GroupIDs, replicaAccessGroupID) {
				return slices.Contains(mergedData.Vault.GroupIDs, replicaAccessGroupID)
			}
			return true
		},
	)
	if appliedChanges == nil || appliedData == nil {
		// return nil
	}

	if err := s.applyChanges(replicaAccessGroupID, &contract.PendingVaultChange{
		SyncChanges:         appliedChanges,
		VaultChangeDataList: appliedData,
	}); err != nil {
		return err
	}

	return s.syncService.InsertSyncChanges(
		sotID,
		syncEntityVault,
		sotChanges.SyncChanges,
	)
}

func (s *ReplicaService) GetWrappedKey(
	vaultID string,
) (string, error) {
	var vaultFound entity.Vault

	err := s.vaultFile.FindFirstWhere(
		&vaultFound,
		func(data map[string]any) bool {
			ID, ok := data["id"]
			return ok && ID == vaultID
		},
	)
	if err != nil {
		return "", err
	}

	return vaultFound.WrappedKey, nil
}
