package sync

import "time"

type SyncChange struct {
	ID string `json:"id" gorm:"type:varchar(26);primaryKey"`

	Sequence uint64 `json:"sequence" gorm:"uniqueIndex;not null"`

	Entity   string `json:"entity" gorm:"type:varchar(100);index;not null"`
	EntityID string `json:"entity_id" gorm:"type:varchar(26);index;not null"`

	Operation string `json:"operation" gorm:"type:varchar(20);not null"`

	CreatedAt time.Time `json:"created_at" gorm:"not null"`

	Users []SyncUserChange `json:"users,omitempty" gorm:"foreignKey:SyncChangeID;constraint:OnDelete:CASCADE,OnUpdate:CASCADE"`
}

type SyncUserChange struct {
	ID string `json:"id" gorm:"type:varchar(26);primaryKey"`

	SyncChangeID string `json:"sync_change_id" gorm:"type:varchar(26);not null;index;uniqueIndex:idx_sync_user_change"`
	UserID       string `json:"user_id" gorm:"type:varchar(26);not null;index;uniqueIndex:idx_sync_user_change"`

	CreatedAt time.Time `json:"created_at" gorm:"not null"`
}

type SyncState struct {
	ID string `json:"id" gorm:"type:varchar(26);primaryKey"`

	LastSequence uint64 `json:"last_sequence" gorm:"not null"`

	LastSyncAt *time.Time `json:"last_sync_at,omitempty"`

	UpdatedAt time.Time `json:"updated_at" gorm:"not null"`
}
