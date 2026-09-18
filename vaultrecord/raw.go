package vaultrecord

import (
	"fmt"
	"strings"

	"github.com/tacenva/database"
	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/internal/sync"
	"github.com/tacenva/tacpass-core/internal/vaultaccess"
	"gorm.io/gorm"
)

type RawService struct {
	syncService        *sync.Service
	vaultaccessService *vaultaccess.Service
}

func NewRawService(
	syncService *sync.Service,
	vaultaccessService *vaultaccess.Service,
) *RawService {
	return &RawService{
		syncService:        syncService,
		vaultaccessService: vaultaccessService,
	}
}

func (s *RawService) Blob(
	authUser *entity.User,
	vaultDir string,
	vaultID string,
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

	entityName := s.getEntityName(vaultID)

	changes, err := s.syncService.GetPendingChanges(
		authUser.ID,
		entityName,
		500,
	)
	if err != nil {
		return nil, err
	}

	if len(changes) == 0 {
		return blob, nil
	}

	changeIDs := make(
		[]string,
		0,
		len(changes),
	)

	for _, change := range changes {
		changeIDs = append(
			changeIDs,
			change.ID,
		)
	}

	if err := s.syncService.Transaction(func(tx *gorm.DB) error {
		if err := s.syncService.MarkSynced(
			tx,
			authUser.ID,
			entityName,
			changeIDs,
		); err != nil {
			return err
		}

		return s.syncService.CleanupChanges(tx)
	}); err != nil {
		return nil, err
	}

	return blob, nil
}

func (s *RawService) Init(
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

func (s *RawService) Create(
	authUser *entity.User,
	vaultDir string,
	vaultID string,
	data []byte,
) (string, error) {
	vaultID = strings.TrimSpace(vaultID)

	if authUser == nil || authUser.ID == "" {
		return "", ErrForbidden
	}

	if vaultID == "" {
		return "", ErrVaultIDEmpty
	}

	if len(data) == 0 {
		return "", ErrRecordDataEmpty
	}

	userIDs, err := s.userIDsByVaultID(
		vaultID,
		authUser.ID,
	)
	if err != nil {
		return "", err
	}

	db := database.New(vaultDir)

	fileDB, err := db.NewRawFile(vaultID)
	if err != nil {
		return "", err
	}

	recordID, err := fileDB.InsertRaw("", data)
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
	authUser *entity.User,
	vaultDir string,
	vaultID string,
	recordID string,
	data []byte,
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

	userIDs, err := s.userIDsByVaultID(
		vaultID,
		authUser.ID,
	)
	if err != nil {
		return err
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
			entityName,
			recordID,
			sync.OperationUpdate,
			userIDs,
		)
	})
}

func (s *RawService) Destroy(
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

func (s *RawService) Delete(
	authUser *entity.User,
	vaultDir string,
	vaultID string,
	recordID string,
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

	userIDs, err := s.userIDsByVaultID(
		vaultID,
		authUser.ID,
	)
	if err != nil {
		return err
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
			entityName,
			recordID,
			sync.OperationDelete,
			userIDs,
		)
	})
}

func (s *RawService) userIDsByVaultID(
	vaultID string,
	excludeUserID string,
) ([]string, error) {
	vaultID = strings.TrimSpace(vaultID)
	excludeUserID = strings.TrimSpace(excludeUserID)

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

			if user.ID == excludeUserID {
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
	vaultDir string,
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

	entityName := s.getEntityName(vaultID)

	changes, err := s.syncService.GetPendingChanges(
		userID,
		entityName,
		500,
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
		[]PendingVaultChange,
		0,
		len(changes),
	)

	for _, change := range changes {
		item := PendingVaultChange{
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
