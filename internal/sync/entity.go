package sync

import "time"

type SyncOperation string

const (
	OperationCreate SyncOperation = "create"
	OperationUpdate SyncOperation = "update"
	OperationDelete SyncOperation = "delete"
)

type SyncChange struct {
	ID        string        `json:"id" gorm:"type:varchar(26);primaryKey"`
	SotID     string        `json:"-" gorm:"type:varchar(26);primaryKey"`
	Entity    string        `json:"entity" gorm:"type:varchar(100);index"`
	EntityID  string        `json:"entity_id" gorm:"type:varchar(26);index;not null"`
	Operation SyncOperation `json:"operation" gorm:"type:varchar(20);not null"`
	CreatedAt time.Time     `json:"created_at" gorm:"not null"`
}

type SyncState struct {
	SotID        string     `json:"sot_id" gorm:"type:varchar(26);primaryKey"`
	Entity       string     `json:"entity" gorm:"type:varchar(100);primaryKey"`
	LastChangeID string     `json:"last_change_id" gorm:"type:varchar(26);not null"`
	UpdatedAt    time.Time  `json:"updated_at" gorm:"not null"`
	LastChange   SyncChange `json:"last_change" gorm:"foreignKey:LastChangeID,SotID;references:ID,SotID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
}
