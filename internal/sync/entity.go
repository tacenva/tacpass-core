package sync

import "time"

type SyncChange struct {
	ID string `gorm:"type:varchar(26);primaryKey"`

	Sequence uint64 `gorm:"uniqueIndex;not null"`

	Entity   string `gorm:"type:varchar(50);index;not null"`
	EntityID string `gorm:"type:varchar(26);index;not null"`

	Operation string `gorm:"type:varchar(20);not null"`

	CreatedAt time.Time `gorm:"not null"`

	Users []SyncUserChange `gorm:"foreignKey:SyncChangeID;constraint:OnDelete:CASCADE,OnUpdate:CASCADE"`
}

type SyncUserChange struct {
	ID string `gorm:"type:varchar(26);primaryKey"`

	SyncChangeID string `gorm:"type:varchar(26);not null;index;uniqueIndex:idx_sync_user_change"`
	UserID       string `gorm:"type:varchar(26);not null;index;uniqueIndex:idx_sync_user_change"`

	CreatedAt time.Time `gorm:"not null"`
}

type SyncState struct {
	ID string `gorm:"type:varchar(26);primaryKey"`

	LastSequence uint64 `gorm:"not null"`

	LastSyncAt *time.Time

	UpdatedAt time.Time `gorm:"not null"`
}
