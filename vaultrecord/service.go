package vaultrecord

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tacenva/database"
	"github.com/tacenva/tacpass-core/contract"
	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/internal/sync"
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
}

func NewService(
	syncService *sync.Service,
) *Service {
	return &Service{
		syncService: syncService,
	}
}

func (s *Service) Blob(
	authUser *entity.User,
	vaultDir string,
	vaultID string,
	sotID string,
) ([]byte, error) {
	if authUser == nil || authUser.ID == "" {
		return nil, ErrForbidden
	}

	vaultID = strings.TrimSpace(vaultID)
	if vaultID == "" {
		return nil, ErrVaultIDEmpty
	}

	db := database.New(vaultDir)

	blob, err := db.Read(vaultID)
	if err != nil {
		return nil, err
	}

	return blob, nil
}

func (s *Service) Init(
	vaultDir string,
	vaultID string,
	vaultKey string,
) error {
	vaultID = strings.TrimSpace(vaultID)

	if vaultID == "" {
		return ErrVaultIDEmpty
	}

	db := database.New(vaultDir)

	_, err := db.File(
		vaultID,
		vaultKey,
		database.FileModeOpenOrCreate,
	)

	return err
}

func (s *Service) Create(
	authUser *entity.User,
	vaultDir string,
	vaultID string,
	recordID *string,
	data []byte,
	sotID string,
	lastChangeID *string,
) error {
	vaultID = strings.TrimSpace(vaultID)

	if authUser == nil || authUser.ID == "" {
		return ErrForbidden
	}

	if vaultID == "" {
		return ErrVaultIDEmpty
	}

	if len(data) == 0 {
		return ErrRecordDataEmpty
	}

	db := database.New(vaultDir)

	fileDB, err := db.NewRawFile(vaultID)
	if err != nil {
		return err
	}

	err = fileDB.InsertRaw(recordID, data)
	if err != nil {
		return err
	}

	entityName := s.getEntityName(vaultID)

	err = s.syncService.Transaction(func(tx *gorm.DB) error {
		return s.syncService.RecordChange(
			tx,
			lastChangeID,
			entityName,
			*recordID,
			sync.OperationCreate,
			sotID,
			// sync.SotType,
		)
	})
	if err != nil {
		return err
	}

	return nil
}

func (s *Service) Update(
	authUser *entity.User,
	vaultDir string,
	vaultID string,
	recordID string,
	data []byte,
	sotID string,
	lastChangeID *string,
) error {
	vaultID = strings.TrimSpace(vaultID)
	recordID = strings.TrimSpace(recordID)

	if authUser == nil || authUser.ID == "" {
		return ErrForbidden
	}

	if vaultID == "" {
		return ErrVaultIDEmpty
	}

	if recordID == "" {
		return ErrRecordIDEmpty
	}

	if len(data) == 0 {
		return ErrRecordDataEmpty
	}

	db := database.New(vaultDir)

	fileDB, err := db.NewRawFile(vaultID)
	if err != nil {
		return err
	}

	if err := fileDB.UpdateRaw(
		recordID,
		data,
	); err != nil {
		return err
	}

	entityName := s.getEntityName(vaultID)

	return s.syncService.Transaction(func(tx *gorm.DB) error {
		return s.syncService.RecordChange(
			tx,
			lastChangeID,
			entityName,
			recordID,
			sync.OperationUpdate,
			sotID,
			// sync.SotType,
		)
	})
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

	return db.Destroy(vaultID)
}

func (s *Service) Delete(
	authUser *entity.User,
	vaultDir string,
	vaultID string,
	recordID string,
	sotID string,
	lastChangeID *string,
) error {
	vaultID = strings.TrimSpace(vaultID)
	recordID = strings.TrimSpace(recordID)

	if authUser == nil || authUser.ID == "" {
		return ErrForbidden
	}

	if vaultID == "" {
		return ErrVaultIDEmpty
	}

	if recordID == "" {
		return ErrRecordIDEmpty
	}

	db := database.New(vaultDir)

	fileDB, err := db.NewRawFile(vaultID)
	if err != nil {
		return err
	}

	if err := fileDB.DeleteRaw(recordID); err != nil {
		return err
	}

	entityName := s.getEntityName(vaultID)

	return s.syncService.Transaction(func(tx *gorm.DB) error {
		return s.syncService.RecordChange(
			tx,
			lastChangeID,
			entityName,
			recordID,
			sync.OperationDelete,
			sotID,
			// sync.SotType,
		)
	})
}

func (s *Service) getEntityName(
	vaultID string,
) string {
	return syncEntityVaultRecord + ":" + vaultID
}

func (s *Service) GetChangesAfter(
	authUser *entity.User,
	vaultDir string,
	vaultID string,
	sotID string,
	startID string,
	limit int,
) ([]contract.PendingVaultRecordChange, error) {
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

	result := make(
		[]contract.PendingVaultRecordChange,
		0,
		len(changes),
	)

	for _, change := range changes {
		item := contract.PendingVaultRecordChange{
			SyncChange: change,
		}

		if change.Operation == sync.OperationDelete {
			result = append(result, item)
			continue
		}

		if change.EntityID == "" {
			return nil, fmt.Errorf(
				"pending change %s has empty entity_id",
				change.ID,
			)
		}

		record, err := fileDB.FindRaw(
			change.EntityID,
		)
		if err != nil {
			return nil, err
		}

		if record == nil {
			continue
		}

		item.Record = record

		result = append(result, item)
	}

	return result, nil
}

func (s *Service) GetChangeCount(
	authUser *entity.User,
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

func (s *Service) Sync(
	authUser *entity.User,
	vaultDir string,
	sotID string,
	vaultID string,
	recordChanges []contract.PendingVaultRecordChange,
) error {
	for _, recordChange := range recordChanges {
		switch recordChange.SyncChange.Operation {
		case sync.OperationCreate:
			err := s.Create(
				authUser,
				vaultDir,
				vaultID,
				&recordChange.RecordID,
				recordChange.Record,
				sotID,
				&recordChange.SyncChange.ID,
			)
			if err != nil {
				return err
			}
		case sync.OperationUpdate:
			err := s.Update(
				authUser,
				vaultDir,
				vaultID,
				recordChange.RecordID,
				recordChange.Record,
				sotID,
				&recordChange.SyncChange.ID,
			)
			if err != nil {
				return err
			}
		case sync.OperationDelete:
			err := s.Delete(
				authUser,
				vaultDir,
				vaultID,
				recordChange.RecordID,
				sotID,
				&recordChange.SyncChange.ID,
			)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *Service) DiffRecordChanges(
	base []contract.PendingVaultRecordChange,
	changes []contract.PendingVaultRecordChange,
) []contract.PendingVaultRecordChange {
	baseChanges := s.normalizeRecordChanges(base)
	sourceChanges := s.normalizeRecordChanges(changes)

	result := make(
		[]contract.PendingVaultRecordChange,
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

func (s *Service) normalizeRecordChanges(
	changes []contract.PendingVaultRecordChange,
) map[string]contract.PendingVaultRecordChange {
	result := make(
		map[string]contract.PendingVaultRecordChange,
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
				// create + update = state terbaru tetap update
				result[entityID] = change

			case sync.OperationDelete:
				// create + delete = tidak pernah perlu ada
				delete(result, entityID)
			}

			continue
		}

		if current.SyncChange.Operation == sync.OperationDelete {
			// Setelah delete, change berikutnya harus punya
			// ID yang lebih baru agar menghidupkan record lagi.
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

func (s *Service) List(
	authUser *entity.User,
	vaultDir string,
	vaultID string,
	vaultKey string,
) ([]entity.VaultRecord, error) {
	if authUser == nil || authUser.ID == "" {
		return nil, ErrForbidden
	}

	vaultID = strings.TrimSpace(vaultID)
	if vaultID == "" {
		return nil, ErrVaultIDEmpty
	}

	vaultKey = strings.TrimSpace(vaultKey)
	if vaultKey == "" {
		return nil, errors.New("Vault Key is Empty")
	}

	db := database.New(vaultDir)

	fileDB, err := db.File(
		vaultID,
		vaultKey,
		database.FileModeOpen,
	)
	if err != nil {
		return nil, err
	}

	var records []entity.VaultRecord

	err = fileDB.FindWhere(
		&records,
		func(data map[string]any) bool {
			return true
		},
	)
	if err != nil {
		return nil, err
	}

	return records, nil
}
