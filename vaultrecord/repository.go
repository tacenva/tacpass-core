package vaultrecord

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tacenva/database"
	tacenvaentity "github.com/tacenva/tacenva-core/entity"
	"github.com/tacenva/tacenva-core/sync"
	"github.com/tacenva/tacenva-core/transactionmanager"
	"github.com/tacenva/tacpass-core/contract"
	"github.com/tacenva/tacpass-core/entity"
	"gorm.io/gorm"
)

type repository struct {
	syncService *sync.Service
	db          *gorm.DB
}

func NewRepository(
	db *gorm.DB,
	syncService *sync.Service,
) *repository {
	return &repository{
		db:          db,
		syncService: syncService,
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
	limit int64,
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

func (r *repository) applyChange(
	fileTx *database.DatabaseFile,
	recordChange *contract.PendingVaultRecordChange,
) error {
	if recordChange == nil {
		// log.Printf("[ApplyChange] no changes to apply")
		return nil
	}

	// log.Printf(
	// 	"[ApplyChange] started: total=%d",
	// 	len(recordChange.SyncChanges),
	// )

	for _, change := range recordChange.SyncChanges {
		recordID := change.EntityID
		encryptedRecord := recordChange.EncryptedRecords[recordID]

		// log.Printf(
		// 	"[ApplyChange] processing: index=%d/%d, record_id=%s, operation=%s",
		// 	i+1,
		// 	len(recordChange.SyncChanges),
		// 	recordID,
		// 	change.Operation,
		// )

		switch change.Operation {
		case tacenvaentity.OperationCreate:
			// log.Printf("[ApplyChange] inserting record: %s", recordID)

			if err := fileTx.InsertRaw(&recordID, encryptedRecord); err != nil {
				// log.Printf("[ApplyChange] insert failed: record_id=%s, error=%v", recordID, err)
				return err
			}

			// log.Printf("[ApplyChange] insert completed: %s", recordID)

		case tacenvaentity.OperationUpdate:
			// log.Printf("[ApplyChange] updating record: %s", recordID)

			if err := fileTx.UpdateRaw(recordID, encryptedRecord); err != nil {
				if !errors.Is(err, database.ErrRecordNotFound) {
					// log.Printf("[ApplyChange] update failed: record_id=%s, error=%v", recordID, err)
					return err
				}

				// log.Printf("[ApplyChange] update skipped, record not found: %s", recordID)
			} else {
				// log.Printf("[ApplyChange] update completed: %s", recordID)
			}

		case tacenvaentity.OperationDelete:
			// log.Printf("[ApplyChange] deleting record: %s", recordID)

			if err := fileTx.DeleteRaw(recordID); err != nil {
				if !errors.Is(err, database.ErrRecordNotFound) {
					// log.Printf("[ApplyChange] delete failed: record_id=%s, error=%v", recordID, err)
					return err
				}

				// log.Printf("[ApplyChange] delete skipped, record not found: %s", recordID)
			} else {
				// log.Printf("[ApplyChange] delete completed: %s", recordID)
			}

		default:
			// log.Printf(
			// 	"[ApplyChange] unknown operation: record_id=%s, operation=%s",
			// 	recordID,
			// 	change.Operation,
			// )
		}
	}

	// log.Printf("[ApplyChange] completed")

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

func (r *repository) mergePendingVaultRecordChange(
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
	tx *gorm.DB,
	sotID string,
	vaultID string,
	syncChanges []tacenvaentity.SyncChange,
) error {
	entityName := r.getEntityName(vaultID)
	return r.syncService.InsertSyncChanges(
		tx,
		sotID,
		entityName,
		syncChanges,
	)
}

// func countChanges(change *contract.PendingVaultRecordChange) int {
// 	if change == nil {
// 		return 0
// 	}

// 	return len(change.SyncChanges)
// }

func (r *repository) SyncOnReplica(
	vaultDir string,
	sotID string,
	vaultID string,
	changeBase *contract.PendingVaultRecordChange,
	changeComp *contract.PendingVaultRecordChange,
) error {
	// startedAt := time.Now()

	// log.Printf("[SyncOnReplica] started: vault_id=%s", vaultID)

	// log.Printf("[SyncOnReplica] merging pending changes")

	appliedChanges := r.mergePendingVaultRecordChange(
		changeBase,
		changeComp,
	)

	if appliedChanges == nil {
		// log.Printf("[SyncOnReplica] no changes to apply")
		return nil
	}

	// log.Printf(
	// 	"[SyncOnReplica] merge completed: base=%d, comp=%d, applied=%d",
	// 	countChanges(changeBase),
	// 	countChanges(changeComp),
	// 	countChanges(appliedChanges),
	// )

	// log.Printf("[SyncOnReplica] creating database instance")

	db := database.New(vaultDir)

	// log.Printf("[SyncOnReplica] opening raw vault file")

	vaultFile, err := db.NewRawFile(vaultID)
	if err != nil {
		// log.Printf("[SyncOnReplica] failed to open vault file: %v", err)
		return err
	}

	// log.Printf("[SyncOnReplica] raw vault file opened")

	// log.Printf("[SyncOnReplica] starting transaction")

	err = transactionmanager.Transaction(
		r.db,
		vaultFile,
		func(gormTx *gorm.DB, fileTx *database.DatabaseFile) error {
			// log.Printf("[SyncOnReplica] transaction started")

			// log.Printf("[SyncOnReplica] applying changes")

			if err := r.applyChange(
				fileTx,
				appliedChanges,
			); err != nil {
				// log.Printf("[SyncOnReplica] apply changes failed: %v", err)
				return err
			}

			// log.Printf("[SyncOnReplica] changes applied")

			// log.Printf("[SyncOnReplica] inserting sync changes")

			if err := r.insertSyncChanges(
				gormTx,
				sotID,
				vaultID,
				changeBase.SyncChanges,
			); err != nil {
				// log.Printf("[SyncOnReplica] insert sync changes failed: %v", err)
				return err
			}

			// log.Printf("[SyncOnReplica] sync changes inserted")

			return nil
		},
	)

	if err != nil {
		// log.Printf("[SyncOnReplica] transaction failed: %v", err)
		return err
	}

	// log.Printf(
	// 	"[SyncOnReplica] completed: vault_id=%s, duration=%s",
	// 	vaultID,
	// 	time.Since(startedAt),
	// )

	return nil
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
	limit int64,
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

	appliedChanges := r.mergePendingVaultRecordChange(
		replicaChanges,
		sotChanges,
	)
	if appliedChanges == nil {
		return nil
	}

	db := database.New(vaultDir)
	vaultFile, err := db.NewRawFile(vaultID)
	if err != nil {
		return err
	}
	return transactionmanager.Transaction(
		r.db,
		vaultFile,
		func(gormTx *gorm.DB, fileTx *database.DatabaseFile) error {
			if err := r.applyChange(
				fileTx,
				appliedChanges,
			); err != nil {
				return err
			}

			for i := range replicaChanges.SyncChanges {
				replicaChanges.SyncChanges[i].ChangedBy = authorizer.IdentityKey()
			}

			if err = r.insertSyncChanges(
				gormTx,
				sotID,
				vaultID,
				replicaChanges.SyncChanges,
			); err != nil {
				return err
			}

			return nil
		},
	)
}
