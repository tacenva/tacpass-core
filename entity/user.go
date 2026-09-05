package entity

import (
	"github.com/oklog/ulid/v2"
	"gorm.io/gorm"
)

type UserStatus string

const (
	UserStatusPending  UserStatus = "pending"
	UserStatusApproved UserStatus = "approved"
	UserStatusRevoked  UserStatus = "revoked"
)

type User struct {
	ID           string     `json:"-" gorm:"type:varchar(26);primaryKey"`
	PermissionID string     `json:"permission_id" gorm:"type:varchar(26);not null"`
	Hostname     string     `json:"hostname" gorm:"type:varchar(50);not null"`
	Token        string     `json:"token" gorm:"type:varchar(128);not null"`
	Status       UserStatus `json:"status" gorm:"type:varchar(20);not null"`

	Permission Permission `json:"permission" gorm:"foreignKey:PermissionID;references:ID"`
}

func (p *User) BeforeCreate(tx *gorm.DB) error {
	if p.ID == "" {
		p.ID = ulid.Make().String()
	}

	return nil
}
