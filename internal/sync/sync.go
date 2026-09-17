package sync

import (
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
	"gorm.io/gorm"
)

const (
	OperationCreate = "create"
	OperationUpdate = "update"
	OperationDelete = "delete"
)

type Service struct {
	db *gorm.DB
}

func NewService(db *gorm.DB) *Service {
	return &Service{
		db: db,
	}
}

func (s *Service) RecordChange(
	tx *gorm.DB,
	entity string,
	entityID string,
	operation string,
	userIDs []string,
) error {
	if entity == "" {
		return fmt.Errorf("sync entity is required")
	}

	if entityID == "" {
		return fmt.Errorf("sync entity id is required")
	}

	switch operation {
	case OperationCreate,
		OperationUpdate,
		OperationDelete:
	default:
		return fmt.Errorf(
			"invalid sync operation %q",
			operation,
		)
	}

	var lastSequence uint64

	err := tx.
		Model(&SyncChange{}).
		Select("COALESCE(MAX(sequence), 0)").
		Scan(&lastSequence).
		Error
	if err != nil {
		return fmt.Errorf(
			"get last sync sequence: %w",
			err,
		)
	}

	sequence := lastSequence + 1

	now := time.Now()

	change := SyncChange{
		ID:        ulid.Make().String(),
		Sequence:  sequence,
		Entity:    entity,
		EntityID:  entityID,
		Operation: operation,
		CreatedAt: now,
	}

	if err := tx.Create(&change).Error; err != nil {
		return fmt.Errorf(
			"create sync change: %w",
			err,
		)
	}

	if len(userIDs) == 0 {
		return nil
	}

	pendingChanges := make([]SyncUserChange, 0, len(userIDs))

	for _, userID := range userIDs {
		if userID == "" {
			continue
		}

		pendingChanges = append(
			pendingChanges,
			SyncUserChange{
				ID:           ulid.Make().String(),
				SyncChangeID: change.ID,
				UserID:       userID,
				CreatedAt:    now,
			},
		)
	}

	if len(pendingChanges) == 0 {
		return nil
	}

	if err := tx.Create(&pendingChanges).Error; err != nil {
		return fmt.Errorf(
			"create sync user changes: %w",
			err,
		)
	}

	return nil
}
func (s *Service) GetPendingChanges(
	userID string,
	entity string,
	limit int,
) ([]SyncChange, error) {
	if userID == "" {
		return nil, fmt.Errorf("user id is required")
	}

	if entity == "" {
		return nil, fmt.Errorf("sync entity is required")
	}

	if limit <= 0 {
		limit = 500
	}

	var changes []SyncChange

	err := s.db.
		Table("sync_changes").
		Joins(
			"JOIN sync_user_changes suc ON suc.sync_change_id = sync_changes.id",
		).
		Where(
			"suc.user_id = ? AND sync_changes.entity = ?",
			userID,
			entity,
		).
		Order("sync_changes.sequence ASC").
		Limit(limit).
		Find(&changes).
		Error

	if err != nil {
		return nil, fmt.Errorf(
			"get pending sync changes: %w",
			err,
		)
	}

	return changes, nil
}

func (s *Service) MarkSynced(
	tx *gorm.DB,
	userID string,
	changeIDs []string,
) error {
	if userID == "" {
		return fmt.Errorf("user id is required")
	}

	if len(changeIDs) == 0 {
		return nil
	}

	if err := tx.
		Where(
			"user_id = ? AND sync_change_id IN ?",
			userID,
			changeIDs,
		).
		Delete(&SyncUserChange{}).
		Error; err != nil {
		return fmt.Errorf(
			"mark sync changes as synced: %w",
			err,
		)
	}

	return nil
}

func (s *Service) MarkSyncedBySequence(
	tx *gorm.DB,
	userID string,
	lastSequence uint64,
) error {
	if userID == "" {
		return fmt.Errorf("user id is required")
	}

	if lastSequence == 0 {
		return nil
	}

	if err := tx.
		Exec(`
			DELETE FROM sync_user_changes
			WHERE user_id = ?
			AND sync_change_id IN (
				SELECT id
				FROM sync_changes
				WHERE sequence <= ?
			)
		`,
			userID,
			lastSequence,
		).
		Error; err != nil {
		return fmt.Errorf(
			"mark sync changes by sequence: %w",
			err,
		)
	}

	return nil
}

func (s *Service) PendingCount(
	userID string,
	entity string,
) (int64, error) {
	if userID == "" {
		return 0, fmt.Errorf("user id is required")
	}

	if entity == "" {
		return 0, fmt.Errorf("sync entity is required")
	}

	var count int64

	err := s.db.
		Model(&SyncUserChange{}).
		Joins(
			"JOIN sync_changes ON sync_changes.id = sync_user_changes.sync_change_id",
		).
		Where(
			"sync_user_changes.user_id = ? AND sync_changes.entity = ?",
			userID,
			entity,
		).
		Count(&count).
		Error

	if err != nil {
		return 0, fmt.Errorf(
			"count pending sync changes: %w",
			err,
		)
	}

	return count, nil
}

func (s *Service) GetLatestSequence() (uint64, error) {
	var change SyncChange

	err := s.db.
		Order("sequence DESC").
		First(&change).
		Error

	switch err {
	case nil:
		return change.Sequence, nil

	case gorm.ErrRecordNotFound:
		return 0, nil

	default:
		return 0, fmt.Errorf(
			"get latest sync sequence: %w",
			err,
		)
	}
}

func (s *Service) GetSyncState(
	userID string,
) (*SyncState, error) {
	if userID == "" {
		return nil, fmt.Errorf("user id is required")
	}

	var state SyncState

	err := s.db.
		Where("id = ?", userID).
		First(&state).
		Error

	switch err {
	case nil:
		return &state, nil

	case gorm.ErrRecordNotFound:
		now := time.Now()

		state = SyncState{
			ID:           userID,
			LastSequence: 0,
			LastSyncAt:   nil,
			UpdatedAt:    now,
		}

		return &state, nil

	default:
		return nil, fmt.Errorf(
			"get sync state: %w",
			err,
		)
	}
}

func (s *Service) UpdateSyncState(
	tx *gorm.DB,
	userID string,
	lastSequence uint64,
) error {
	if userID == "" {
		return fmt.Errorf("user id is required")
	}

	now := time.Now()

	state := SyncState{
		ID:           userID,
		LastSequence: lastSequence,
		LastSyncAt:   &now,
		UpdatedAt:    now,
	}

	if err := tx.
		Save(&state).
		Error; err != nil {
		return fmt.Errorf(
			"update sync state: %w",
			err,
		)
	}

	return nil
}

func (s *Service) CleanupChanges(
	tx *gorm.DB,
) error {
	if err := tx.
		Where(`
			id NOT IN (
				SELECT sync_change_id
				FROM sync_user_changes
			)
		`).
		Delete(&SyncChange{}).
		Error; err != nil {
		return fmt.Errorf(
			"cleanup sync changes: %w",
			err,
		)
	}

	return nil
}
