package vaultrecord

import (
	"errors"
	"fmt"
	"slices"
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

func (s *Service) GetBlob(
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

func (s *Service) StoreBlob(
	authUser *entity.User,
	vaultDir string,
	vaultID string,
	sotID string,
	data []byte,
) error {
	if authUser == nil || authUser.ID == "" {
		return ErrForbidden
	}

	vaultID = strings.TrimSpace(vaultID)
	if vaultID == "" {
		return ErrVaultIDEmpty
	}

	db := database.New(vaultDir)

	err := db.Write(vaultID, data)
	if err != nil {
		return err
	}

	return nil
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
	hostname string,
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
			hostname,
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
	hostname string,
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
			hostname,
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
	hostname string,
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
			hostname,
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
	).Order("ID ASC").Error
	if err != nil {
		return nil, err
	}

	return records, nil
}

func (s *Service) MergePendingVaultRecordChange(
	base *contract.PendingVaultRecordChange,
	comp *contract.PendingVaultRecordChange,
) *contract.PendingVaultRecordChange {
	if base == nil {
		return nil
	}

	var compChanges []sync.SyncChange
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
		case sync.OperationCreate:
			err := fileDB.InsertRaw(&recordID, encryptedRecord)
			if err != nil {
				return err
			}

		case sync.OperationUpdate:
			err := fileDB.UpdateRaw(recordID, encryptedRecord)
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
	syncChanges []sync.SyncChange,
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

func (s *Service) Sync(
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

func (s *Service) SyncOnSoT(
	authUser *entity.User,
	vaultDir string,
	sotID string,
	vaultID string,
	pendingChange *contract.PendingVaultRecordChange,
) error {
	for i := range pendingChange.SyncChanges {
		pendingChange.SyncChanges[i].ChangedBy = authUser.Hostname
	}

	return s.Sync(
		vaultDir,
		sotID,
		vaultID,
		pendingChange,
		nil,
	)
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
