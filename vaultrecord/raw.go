package vaultrecord

import (
	"strings"

	"github.com/tacenva/database"
	"github.com/tacenva/tacpass-core/internal/sync"
	"github.com/tacenva/tacpass-core/internal/vaultaccess"
	"gorm.io/gorm"
)

type RawService struct {
	tacenvaDB          *database.DB
	syncService        *sync.Service
	vaultaccessService *vaultaccess.Service
}

func NewRawService(
	tacenvaDB *database.DB,
	syncService *sync.Service,
	vaultaccessService *vaultaccess.Service,
) *RawService {
	return &RawService{
		tacenvaDB:          tacenvaDB,
		syncService:        syncService,
		vaultaccessService: vaultaccessService,
	}
}

func (s *RawService) Blob(
	vaultID string,
) ([]byte, error) {
	vaultID = strings.TrimSpace(vaultID)

	if vaultID == "" {
		return nil, ErrVaultIDEmpty
	}

	return s.tacenvaDB.Read(vaultID)
}

func (s *RawService) Init(
	vaultID string,
	vaultKey string,
) error {
	vaultID = strings.TrimSpace(vaultID)

	if vaultID == "" {
		return ErrVaultIDEmpty
	}

	_, err := s.tacenvaDB.File(
		vaultID,
		vaultKey,
		database.FileModeOpenOrCreate,
	)

	return err
}

func (s *RawService) Create(
	vaultID string,
	data []byte,
) (string, error) {
	vaultID = strings.TrimSpace(vaultID)

	if vaultID == "" {
		return "", ErrVaultIDEmpty
	}

	if len(data) == 0 {
		return "", ErrRecordDataEmpty
	}

	userIDs, err := s.userIDsByVaultID(vaultID)
	if err != nil {
		return "", err
	}

	fileDB, err := s.tacenvaDB.NewRawFile(vaultID)
	if err != nil {
		return "", err
	}

	recordID, err := fileDB.InsertRaw(data)
	if err != nil {
		return "", err
	}

	entityName := s.getEntityName(vaultID)

	err = s.syncService.Transaction(func(tx *gorm.DB) error {
		return s.syncService.RecordChange(
			tx,
			entityName,
			recordID,
			sync.OperationCreate,
			userIDs,
		)
	})
	if err != nil {
		return "", err
	}

	return recordID, nil
}

func (s *RawService) Update(
	vaultID string,
	recordID string,
	data []byte,
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

	userIDs, err := s.userIDsByVaultID(vaultID)
	if err != nil {
		return err
	}

	fileDB, err := s.tacenvaDB.NewRawFile(vaultID)
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
			entityName,
			recordID,
			sync.OperationUpdate,
			userIDs,
		)
	})
}

func (s *RawService) Delete(
	vaultID string,
	recordID string,
) error {
	vaultID = strings.TrimSpace(vaultID)
	recordID = strings.TrimSpace(recordID)

	if vaultID == "" {
		return ErrVaultIDEmpty
	}

	if recordID == "" {
		return ErrRecordIDEmpty
	}

	userIDs, err := s.userIDsByVaultID(vaultID)
	if err != nil {
		return err
	}

	fileDB, err := s.tacenvaDB.NewRawFile(vaultID)
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
			entityName,
			recordID,
			sync.OperationDelete,
			userIDs,
		)
	})
}

func (s *RawService) userIDsByVaultID(
	vaultID string,
) ([]string, error) {
	vaultID = strings.TrimSpace(vaultID)

	if vaultID == "" {
		return nil, ErrVaultIDEmpty
	}

	vaultAccessList, err := s.vaultaccessService.FindByVaultID(
		vaultID,
	)
	if err != nil {
		return nil, err
	}

	userIDs := make([]string, 0)
	seen := make(map[string]struct{})

	for _, vaultAccess := range vaultAccessList {
		for _, user := range vaultAccess.Permission.Users {
			if user.ID == "" {
				continue
			}

			if _, ok := seen[user.ID]; ok {
				continue
			}

			seen[user.ID] = struct{}{}

			userIDs = append(
				userIDs,
				user.ID,
			)
		}
	}

	return userIDs, nil
}

func (s *RawService) getEntityName(
	vaultID string,
) string {
	return syncEntityVaultRecord + ":" + vaultID
}

func (s *RawService) PendingCount(
	userID string,
	vaultID string,
) (int64, error) {
	userID = strings.TrimSpace(userID)
	vaultID = strings.TrimSpace(vaultID)

	if userID == "" {
		return 0, ErrForbidden
	}

	if vaultID == "" {
		return 0, ErrVaultIDEmpty
	}

	return s.syncService.PendingCount(
		userID,
		s.getEntityName(vaultID),
	)
}

type PendingVaultChange struct {
	SyncChange sync.SyncChange `json:"sync_change"`
	Record     []byte          `json:"record,omitempty"`
}

func (s *RawService) GetPendingChanges(
	userID string,
	vaultID string,
) ([]PendingVaultChange, error) {
	userID = strings.TrimSpace(userID)
	vaultID = strings.TrimSpace(vaultID)

	if userID == "" {
		return nil, ErrForbidden
	}

	if vaultID == "" {
		return nil, ErrVaultIDEmpty
	}

	changes, err := s.syncService.GetPendingChanges(
		userID,
		s.getEntityName(vaultID),
		500,
	)
	if err != nil {
		return nil, err
	}

	fileDB, err := s.tacenvaDB.NewRawFile(vaultID)
	if err != nil {
		return nil, err
	}

	result := make(
		[]PendingVaultChange,
		0,
		len(changes),
	)

	for _, change := range changes {
		item := PendingVaultChange{
			SyncChange: change,
		}

		if change.Operation != sync.OperationDelete {
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
		}

		result = append(result, item)
	}

	return result, nil
}

func (s *RawService) MarkChangesSynced(
	userID string,
	vaultID string,
	changeIDs []string,
) error {
	userID = strings.TrimSpace(userID)
	vaultID = strings.TrimSpace(vaultID)

	if userID == "" {
		return ErrForbidden
	}

	if vaultID == "" {
		return ErrVaultIDEmpty
	}

	if len(changeIDs) == 0 {
		return nil
	}

	return s.syncService.Transaction(func(tx *gorm.DB) error {
		if err := s.syncService.MarkSynced(
			tx,
			userID,
			s.getEntityName(vaultID),
			changeIDs,
		); err != nil {
			return err
		}

		return s.syncService.CleanupChanges(tx)
	})
}
