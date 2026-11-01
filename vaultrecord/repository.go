package vaultrecord

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tacenva/database"
	tacenvaentity "github.com/tacenva/tacenva-core/entity"
	"github.com/tacenva/tacenva-core/sync"
	"github.com/tacenva/tacpass-core/contract"
	"github.com/tacenva/tacpass-core/entity"
	"gorm.io/gorm"
)

type repository struct {
	syncService *sync.Service
	db          *gorm.DB
}

func NewRepository(db *gorm.DB) *repository {
	return &repository{
		db: db,
	}
}

func (r *repository) Transaction(
	fn func(tx *gorm.DB) error,
) error {
	return r.db.Transaction(fn)
}

func (r *repository) IsAllowedToChange(
	vaultID string,
	groupID string,
) (bool, error) {
	var vault entity.Vault

	err := r.db.
		Where(`
			EXISTS (
				SELECT 1
				FROM json_each(
					CASE
						WHEN json_valid(vaults.group_ids)
						THEN vaults.group_ids
						ELSE '[]'
					END
				)
				WHERE json_each.value = ?
			)
			AND vaults.id = ?
		`, groupID, vaultID).
		First(&vault).
		Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func (r *repository) getEntityName(
	vaultID string,
) string {
	return syncEntityVaultRecord + ":" + vaultID
}

func (r *repository) Destroy(
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

func (r *repository) GetChangesAfter(
	vaultDir string,
	vaultID string,
	sotID string,
	startID string,
	limit int,
) (*contract.PendingVaultRecordChange, error) {
	if vaultID == "" {
		return nil, ErrVaultIDEmpty
	}

	entityName := r.getEntityName(vaultID)

	changes, err := r.syncService.GetChangesAfter(
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

func (r *repository) ApplyChange(
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

func (r *repository) GetChangeCount(
	sotID string,
	vaultID string,
	startID string,
) (int64, error) {
	entityName := r.getEntityName(vaultID)
	return r.syncService.GetChangeCount(
		sotID,
		entityName,
		startID,
	)
}

func (r *repository) GetSyncLatestChangeId(
	sotID string,
	vaultID string,
) (string, error) {
	entityName := r.getEntityName(vaultID)
	syncState, err := r.syncService.GetSyncState(
		sotID,
		entityName,
	)

	return syncState.LastChangeID, err
}

func (r *repository) MergePendingVaultRecordChange(
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

func (r *repository) insertSyncChanges(
	sotID string,
	vaultID string,
	syncChanges []tacenvaentity.SyncChange,
) error {
	entityName := r.getEntityName(vaultID)
	return r.syncService.InsertSyncChanges(
		sotID,
		entityName,
		syncChanges,
	)
}

func (r *repository) SyncOnReplica(
	vaultDir string,
	sotID string,
	vaultID string,
	changeBase *contract.PendingVaultRecordChange,
	changeComp *contract.PendingVaultRecordChange,
) error {
	appliedChanges := r.MergePendingVaultRecordChange(
		changeBase,
		changeComp,
	)
	if appliedChanges == nil {
		return nil
	}

	if err := r.ApplyChange(vaultDir, vaultID, appliedChanges); err != nil {
		return err
	}

	return r.insertSyncChanges(sotID, vaultID, changeBase.SyncChanges)
}

func (r *repository) SetSyncStateToBeLatest(
	sotID string,
	vaultID string,
) error {
	entityName := r.getEntityName(vaultID)
	return r.syncService.Transaction(func(tx *gorm.DB) error {
		return r.syncService.SetSyncStateToBeLatest(
			tx,
			sotID,
			entityName,
		)
	})
}

func (r *repository) SyncOnSot(
	authorizer *tacenvaentity.User,
	vaultDir string,
	sotID string,
	vaultID string,
	sotStartChangeID string,
	limit int,
	replicaChanges *contract.PendingVaultRecordChange,
) (err error) {
	isAllowed, err := r.IsAllowedToChange(
		vaultID,
		authorizer.AccessUnit.GroupID,
	)
	if err != nil {
		return err
	}

	if !isAllowed {
		return ErrForbidden
	}

	sotChanges, err := r.GetChangesAfter(
		vaultDir,
		vaultID,
		sotID,
		sotStartChangeID,
		limit,
	)
	if err != nil {
		return err
	}

	appliedChanges := r.MergePendingVaultRecordChange(
		replicaChanges,
		sotChanges,
	)
	if appliedChanges == nil {
		return nil
	}

	if err := r.ApplyChange(vaultDir, vaultID, appliedChanges); err != nil {
		return err
	}

	for i := range replicaChanges.SyncChanges {
		replicaChanges.SyncChanges[i].ChangedBy = authorizer.Hostname
	}

	if err = r.insertSyncChanges(sotID, vaultID, replicaChanges.SyncChanges); err != nil {
		return err
	}

	return nil
}
