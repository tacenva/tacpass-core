package vaultrecord

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/tacenva/database"
	tacenvaentity "github.com/tacenva/tacenva-core/entity"
	"github.com/tacenva/tacenva-core/sync"
	"github.com/tacenva/tacpass-core/contract"
	"gorm.io/gorm"
)

var (
	ErrForbidden       = errors.New("forbidden")
	ErrVaultIDEmpty    = errors.New("vault ID cannot be empty")
	ErrRecordIDEmpty   = errors.New("record ID cannot be empty")
	ErrRecordDataEmpty = errors.New("record data cannot be empty")
)

const syncEntityVaultRecord = "vault_record"

type Service struct {
	syncService *sync.Service
	repository  *repository

	Local  *Local
	Remote *Remote
}

func NewService(
	syncService *sync.Service,
	repository *repository,
) *Service {
	return &Service{
		syncService: syncService,
		repository:  repository,
	}
}

func (s *Service) Destroy(
	vaultDir string,
	vaultID string,
) error {
	vaultID = strings.TrimSpace(vaultID)

	if vaultID == "" {
		return ErrVaultIDEmpty
	}

	db := database.New(vaultDir)

	err := db.Destroy(vaultID)
	if err == database.ErrFileNotFound {
		return nil
	}
	return err
}

func (s *Service) getEntityName(
	vaultID string,
) string {
	return syncEntityVaultRecord + ":" + vaultID
}

func (s *Service) GetChangesAfter(
	vaultDir string,
	vaultID string,
	sotID string,
	startID string,
	limit int,
) (*contract.PendingVaultRecordChange, error) {
	if vaultID == "" {
		return nil, ErrVaultIDEmpty
	}

	entityName := s.getEntityName(vaultID)

	changes, err := s.syncService.GetChangesAfter(
		sotID,
		entityName,
		startID,
		limit,
	)
	if err != nil {
		return nil, err
	}

	db := database.New(vaultDir)

	fileDB, err := db.NewRawFile(vaultID)
	if err != nil {
		return nil, err
	}

	encryptedRecords := make(map[string][]byte, len(changes))

	for _, change := range changes {
		recordID := change.EntityID
		if recordID == "" {
			return nil, fmt.Errorf(
				"pending change %s has empty entity_id",
				change.ID,
			)
		}

		if _, exists := encryptedRecords[recordID]; exists {
			continue
		}

		encryptedRecord, err := fileDB.FindRaw(recordID)
		if err != nil {
			if errors.Is(err, database.ErrRecordNotFound) {
				continue
			}
			return nil, err
		}

		encryptedRecords[recordID] = encryptedRecord
	}

	return &contract.PendingVaultRecordChange{
		SyncChanges:      changes,
		EncryptedRecords: encryptedRecords,
	}, nil
}

func (s *Service) GetChangeCount(
	sotID string,
	vaultID string,
	startID string,
) (int64, error) {
	entityName := s.getEntityName(vaultID)
	return s.syncService.GetChangeCount(
		sotID,
		entityName,
		startID,
	)
}

func (s *Service) GetSyncLatestChangeId(
	sotID string,
	vaultID string,
) (string, error) {
	entityName := s.getEntityName(vaultID)
	syncState, err := s.syncService.GetSyncState(
		sotID,
		entityName,
	)

	return syncState.LastChangeID, err
}

func (s *Service) MergePendingVaultRecordChange(
	base *contract.PendingVaultRecordChange,
	comp *contract.PendingVaultRecordChange,
) *contract.PendingVaultRecordChange {
	if base == nil {
		return nil
	}

	var compChanges []tacenvaentity.SyncChange
	var compData map[string][]byte

	if comp != nil {
		compChanges = comp.SyncChanges
		compData = comp.EncryptedRecords
	}

	changes, data := sync.MergePendingChanges(
		base.SyncChanges,
		compChanges,
		base.EncryptedRecords,
		compData,
		nil,
	)

	return &contract.PendingVaultRecordChange{
		SyncChanges:      changes,
		EncryptedRecords: data,
	}
}

func (s *Service) applyChange(
	vaultDir string,
	vaultID string,
	recordChange *contract.PendingVaultRecordChange,
) error {
	if recordChange == nil {
		return nil
	}

	db := database.New(vaultDir)

	fileDB, err := db.NewRawFile(vaultID)
	if err != nil {
		return err
	}

	for _, change := range recordChange.SyncChanges {
		recordID := change.EntityID
		encryptedRecord := recordChange.EncryptedRecords[recordID]
		switch change.Operation {
		case tacenvaentity.OperationCreate:
			err := fileDB.InsertRaw(&recordID, encryptedRecord)
			if err != nil {
				return err
			}

		case tacenvaentity.OperationUpdate:
			err := fileDB.UpdateRaw(recordID, encryptedRecord)
			if err != nil {
				if !errors.Is(err, database.ErrRecordNotFound) {
					return err
				}
			}

		case tacenvaentity.OperationDelete:
			err := fileDB.DeleteRaw(recordID)
			if err != nil {
				if !errors.Is(err, database.ErrRecordNotFound) {
					return err
				}
			}
		}
	}

	return nil
}

func (s *Service) insertSyncChanges(
	sotID string,
	vaultID string,
	syncChanges []tacenvaentity.SyncChange,
) error {
	if len(syncChanges) == 0 {
		return nil
	}

	clonedSyncChanges := slices.Clone(syncChanges)

	for i := range clonedSyncChanges {
		clonedSyncChanges[i].SotID = sotID
	}

	entityName := s.getEntityName(vaultID)

	return s.syncService.InsertSyncChanges(
		sotID,
		entityName,
		clonedSyncChanges,
	)
}

func (s *Service) SyncOnReplica(
	vaultDir string,
	sotID string,
	vaultID string,
	changeBase *contract.PendingVaultRecordChange,
	changeComp *contract.PendingVaultRecordChange,
) error {
	appliedChanges := s.MergePendingVaultRecordChange(
		changeBase,
		changeComp,
	)
	if appliedChanges == nil {
		return nil
	}

	if err := s.applyChange(vaultDir, vaultID, appliedChanges); err != nil {
		return err
	}

	return s.insertSyncChanges(sotID, vaultID, changeBase.SyncChanges)
}

func (s *Service) SyncOnSot(
	authorizer *tacenvaentity.User,
	vaultDir string,
	sotID string,
	vaultID string,
	sotStartChangeID string,
	limit int,
	replicaChanges *contract.PendingVaultRecordChange,
) (err error) {
	isAllowed := true
	err = s.repository.Transaction(func(tx *gorm.DB) error {
		isAllowed, err = s.repository.IsAllowedToChange(
			tx,
			vaultID,
			authorizer.AccessUnit.GroupID,
		)
		return err
	})

	if !isAllowed {
		return ErrForbidden
	}

	sotChanges, err := s.GetChangesAfter(
		vaultDir,
		vaultID,
		sotID,
		sotStartChangeID,
		limit,
	)
	if err != nil {
		return err
	}

	appliedChanges := s.MergePendingVaultRecordChange(
		replicaChanges,
		sotChanges,
	)
	if appliedChanges == nil {
		return nil
	}

	if err := s.applyChange(vaultDir, vaultID, appliedChanges); err != nil {
		return err
	}

	for i := range replicaChanges.SyncChanges {
		replicaChanges.SyncChanges[i].ChangedBy = authorizer.Hostname
	}

	if err = s.insertSyncChanges(sotID, vaultID, replicaChanges.SyncChanges); err != nil {
		return err
	}

	return nil
}

func (s *Service) SetSyncStateToBeLastest(
	sotID string,
	vaultID string,
) error {
	entityName := s.getEntityName(vaultID)
	return s.syncService.Transaction(func(tx *gorm.DB) error {
		return s.syncService.SetSyncStateToBeLastest(
			tx,
			sotID,
			entityName,
		)
	})
}
