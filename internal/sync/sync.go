package sync

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/tacenva/tacpass-core/internal/user"
	"gorm.io/gorm"
)

type Service struct {
	db          *gorm.DB
	userService *user.Service
}

func NewService(
	db *gorm.DB,
	userService *user.Service,
) *Service {
	return &Service{
		db:          db,
		userService: userService,
	}
}

func (s *Service) RecordChangeWithoutTx(
	syncChangeID *string,
	entity string,
	entityID string,
	operation SyncOperation,
	sotID string,
) error {
	return s.Transaction(func(tx *gorm.DB) error {
		return s.RecordChange(
			tx,
			syncChangeID,
			entity,
			entityID,
			operation,
			sotID,
		)
	})
}

func (s *Service) RecordChange(
	tx *gorm.DB,
	syncChangeID *string,
	entity string,
	entityID string,
	operation SyncOperation,
	sotID string,
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

	if tx == nil {
		return fmt.Errorf("sync transaction is required")
	}

	unsynced := (*syncChangeID == "")
	if unsynced {
		*syncChangeID = ulid.Make().String()
	}

	now := time.Now()
	change := SyncChange{
		ID:        *syncChangeID,
		Entity:    entity,
		EntityID:  entityID,
		Operation: operation,
		CreatedAt: now,

		SotID: sotID,
	}

	if err := tx.Create(&change).Error; err != nil {
		return fmt.Errorf(
			"create sync change: %w",
			err,
		)
	}

	if !unsynced {
		state := SyncState{
			SotID:        sotID,
			Entity:       entity,
			LastChangeID: change.ID,
			UpdatedAt:    now,
		}

		if err := tx.
			Where(
				"sot_id = ? AND entity = ?",
				sotID,
				entity,
			).
			Assign(state).
			FirstOrCreate(&state).Error; err != nil {
			return fmt.Errorf(
				"update sync state: %w",
				err,
			)
		}
	}

	return nil
}

func (s *Service) GetChangesAfter(
	sotID string,
	entity string,
	startID string,
	limit int,
) ([]SyncChange, error) {
	if sotID == "" {
		return nil, fmt.Errorf("sot id is required")
	}

	if entity == "" {
		return nil, fmt.Errorf("sync entity is required")
	}

	// if startID == "" {
	// 	return nil, fmt.Errorf("current id is required")
	// }

	if limit <= 0 {
		limit = 500
	}

	var changes []SyncChange

	err := s.db.
		Table("sync_changes").
		Where(
			"sot_id = ? AND entity = ? AND id > ?",
			sotID,
			entity,
			startID,
		).
		Order("id ASC").
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

func (s *Service) GetSyncState(
	sotID string,
	entity string,
) (SyncState, error) {
	if sotID == "" {
		return SyncState{}, fmt.Errorf("sot id is required")
	}

	if entity == "" {
		return SyncState{}, fmt.Errorf("sync entity is required")
	}

	var state SyncState

	err := s.db.
		Where(
			"sot_id = ? AND entity = ?",
			sotID,
			entity,
		).
		First(&state).
		Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return SyncState{}, nil
			// return SyncState{}, fmt.Errorf(
			// 	"sync state not found",
			// )
		}

		return SyncState{}, fmt.Errorf(
			"get sync state: %w",
			err,
		)
	}

	return state, nil
}

func (s *Service) GetChangeCount(
	sotID string,
	entity string,
	startID string,
) (int64, error) {
	if sotID == "" {
		return 0, fmt.Errorf("sot id is required")
	}

	if entity == "" {
		return 0, fmt.Errorf("sync entity is required")
	}

	var count int64

	err := s.db.
		Model(&SyncChange{}).
		Where(
			"sot_id = ? AND entity = ? AND id > ?",
			sotID,
			entity,
			startID,
		).
		Count(&count).
		Error

	if err != nil {
		return 0, fmt.Errorf(
			"get sync change count after %q: %w",
			startID,
			err,
		)
	}

	return count, nil
}

func (s *Service) Transaction(
	fn func(tx *gorm.DB) error,
) error {
	if fn == nil {
		return fmt.Errorf("transaction function is required")
	}

	return s.db.Transaction(fn)
}

func (s *Service) InsertSyncChanges(
	sotID string,
	entity string,
	syncChanges []SyncChange,
) error {
	if len(syncChanges) == 0 {
		return nil
	}

	return s.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&syncChanges).Error; err != nil {
			return err
		}

		return s.SetSyncStateToBeLastest(tx, sotID, entity)
	})
}

func (s *Service) SetSyncStateToBeLastest(
	tx *gorm.DB,
	sotID string,
	entity string,
) error {
	var lastChange SyncChange

	err := tx.
		Where("sot_id = ? AND entity = ?", sotID, entity).
		Order("id DESC").
		First(&lastChange).
		Error
	if err != nil {
		return fmt.Errorf("get latest sync change: %w", err)
	}

	state := SyncState{
		SotID:        sotID,
		Entity:       entity,
		LastChangeID: lastChange.ID,
		UpdatedAt:    time.Now(),
	}

	return tx.
		Where("sot_id = ? AND entity = ?", sotID, entity).
		Assign(map[string]any{
			"last_change_id": state.LastChangeID,
			"updated_at":     state.UpdatedAt,
		}).
		FirstOrCreate(&state).
		Error
}

func MergePendingChanges[T any](
	baseChanges []SyncChange,
	compChanges []SyncChange,
	baseData map[string]T,
	compData map[string]T,
) ([]SyncChange, map[string]T) {
	mergedChanges := make(map[string]SyncChange)
	mergedData := make(map[string]T)

	for _, change := range baseChanges {
		entityID := change.EntityID
		existing, exists := mergedChanges[entityID]

		if exists && (existing.Operation == OperationDelete ||
			(existing.Operation == OperationCreate &&
				change.Operation == OperationUpdate)) {
			continue
		}

		if !exists {
			mergedChanges[entityID] = change
			mergedData[entityID] = baseData[entityID]
		} else if change.Operation == OperationDelete {
			mergedChanges[entityID] = change
			delete(mergedData, entityID)
		} else if change.ID > existing.ID {
			mergedChanges[entityID] = change
		}
	}

	for _, change := range compChanges {
		entityID := change.EntityID
		existing, exists := mergedChanges[entityID]

		if !exists {
			continue
		}

		if existing.Operation == OperationDelete {
			continue
		}

		if change.Operation == OperationDelete {
			delete(mergedChanges, entityID)
			delete(mergedData, entityID)
		} else if change.ID > existing.ID {
			mergedData[entityID] = compData[entityID]
		}
	}

	sortedChanges := make([]SyncChange, 0, len(mergedChanges))
	for _, change := range mergedChanges {
		sortedChanges = append(sortedChanges, change)
	}

	sort.Slice(sortedChanges, func(i, j int) bool {
		return sortedChanges[i].ID < sortedChanges[j].ID
	})

	return sortedChanges, mergedData
}
