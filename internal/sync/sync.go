package sync

import (
	"errors"
	"fmt"
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
	// nodeType NodeType,
) error {
	return s.Transaction(func(tx *gorm.DB) error {
		return s.RecordChange(
			tx,
			syncChangeID,
			entity,
			entityID,
			operation,
			sotID,
			// nodeType,
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
	// nodeType NodeType,
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

	// var lastSequence uint64

	// err := tx.
	// 	Model(&SyncChange{}).
	// 	Select("COALESCE(MAX(sequence), 0)").
	// 	Scan(&lastSequence).
	// 	Error
	// if err != nil {
	// 	return fmt.Errorf(
	// 		"get last sync sequence: %w",
	// 		err,
	// 	)
	// }

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
			// NodeType:     nodeType,
			UpdatedAt: now,
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

	if startID == "" {
		return nil, fmt.Errorf("current id is required")
	}

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

	// if startID == "" {
	// 	return 0, fmt.Errorf("start id is required")
	// }

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
