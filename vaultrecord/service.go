package vaultrecord

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"
	"sort"
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

	blob, err := db.ReadMetadataOnly(vaultID)
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
	vaultDir string,
	vaultID string,
	recordID *string,
	data []byte,
	sotID string,
	lastChangeID *string,
) error {
	vaultID = strings.TrimSpace(vaultID)
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
		)
	})
	if err != nil {
		return err
	}

	return nil
}

func (s *Service) Update(
	vaultDir string,
	vaultID string,
	recordID string,
	data []byte,
	sotID string,
	lastChangeID *string,
) error {
	vaultID = strings.TrimSpace(vaultID)
	recordID = strings.TrimSpace(recordID)

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

	err := db.Destroy(vaultID)
	if err == database.ErrFileNotFound {
		return nil
	}
	return err
}

func (s *Service) Delete(
	vaultDir string,
	vaultID string,
	recordID string,
	sotID string,
	lastChangeID *string,
) error {
	vaultID = strings.TrimSpace(vaultID)
	recordID = strings.TrimSpace(recordID)

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
		)
	})
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
			if !errors.Is(err, database.ErrRecordNotFound) {
				return nil, err
			}
		}

		item.Record = record

		result = append(result, item)
	}

	return result, nil
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

func (s *Service) List(
	vaultDir string,
	vaultID string,
	vaultKey string,
) ([]entity.VaultRecord, error) {
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

	err = fileDB.FindAll(
		&records,
	).Order("ID ASC").Err
	if err != nil {
		return nil, err
	}

	return records, nil
}

func (s *Service) mergePendingVaultRecordChange(
	base []contract.PendingVaultRecordChange,
	comp []contract.PendingVaultRecordChange,
) []contract.PendingVaultRecordChange {
	clonedBase := slices.Clone(base)
	merged := make(map[string]contract.PendingVaultRecordChange)

	for _, change := range clonedBase {
		recordID := change.SyncChange.EntityID
		existing, exists := merged[recordID]

		if exists && (existing.SyncChange.Operation == sync.OperationDelete ||
			(existing.SyncChange.Operation == sync.OperationCreate &&
				change.SyncChange.Operation == sync.OperationUpdate)) {
			continue
		}

		if !exists || change.SyncChange.ID > existing.SyncChange.ID {
			merged[recordID] = change
		}
	}

	for _, change := range comp {
		recordID := change.SyncChange.EntityID
		existing, exists := merged[recordID]

		if !exists {
			continue
		}

		if existing.SyncChange.Operation == sync.OperationDelete {
			continue
		}

		if change.SyncChange.ID > existing.SyncChange.ID {
			merged[recordID] = change
		}
	}

	result := make([]contract.PendingVaultRecordChange, 0, len(merged))
	for _, change := range merged {
		result = append(result, change)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].SyncChange.ID < result[j].SyncChange.ID
	})

	return result
}

func (s *Service) applyChange(
	vaultDir string,
	vaultID string,
	recordChanges []contract.PendingVaultRecordChange,
) error {
	db := database.New(vaultDir)

	fileDB, err := db.NewRawFile(vaultID)
	if err != nil {
		return err
	}

	for _, change := range recordChanges {
		changeJSON, err := json.MarshalIndent(change, "", "  ")
		if err != nil {
			log.Printf("[DEBUG] Gagal marshal change: %v", err)
		} else {
			log.Printf("[DEBUG] applyChange change:\n%s", string(changeJSON))
		}
		recordID := change.SyncChange.EntityID
		switch change.SyncChange.Operation {
		case sync.OperationCreate:
			err := fileDB.InsertRaw(&recordID, change.Record)
			if err != nil {
				return err
			}

		case sync.OperationUpdate:
			err := fileDB.UpdateRaw(recordID, change.Record)
			if err != nil {
				if !errors.Is(err, database.ErrRecordNotFound) {
					return err
				}
			}

		case sync.OperationDelete:
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
	recordChanges []contract.PendingVaultRecordChange,
) error {
	if len(recordChanges) == 0 {
		return nil
	}

	syncChanges := make([]sync.SyncChange, len(recordChanges))

	for i, change := range recordChanges {
		syncChanges[i] = change.SyncChange
		syncChanges[i].SotID = sotID
	}

	entityName := s.getEntityName(vaultID)
	return s.syncService.InsertSyncChanges(
		sotID,
		entityName,
		syncChanges,
	)
}

func (s *Service) Sync(
	vaultDir string,
	sotID string,
	vaultID string,
	changeBase []contract.PendingVaultRecordChange,
	changeComp []contract.PendingVaultRecordChange,
) error {
	appliedChanges := s.mergePendingVaultRecordChange(
		changeBase,
		changeComp,
	)
	if err := s.applyChange(vaultDir, vaultID, appliedChanges); err != nil {
		return err
	}

	return s.insertSyncChanges(sotID, vaultID, changeBase)
}
