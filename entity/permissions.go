package entity

import (
	"github.com/oklog/ulid/v2"
	"gorm.io/gorm"
)

type Privilege string

const (
	PrivilegeAdmin Privilege = "admin"
	PrivilegeWrite Privilege = "write"
	PrivilegeRead  Privilege = "read"
)

type Permission struct {
	ID        string    `json:"-" gorm:"type:varchar(26);primaryKey"`
	Privilege Privilege `json:"privilege" gorm:"type:varchar(10);not null"`
	Token     string    `json:"token" gorm:"type:varchar(128);not null"`
	Revoked   bool      `json:"revoked" gorm:"not null;default:false"`

	Users []User `json:"users,omitempty" gorm:"foreignKey:PermissionId"`
}

func (p Privilege) IsValid() bool {
	switch p {
	case PrivilegeAdmin,
		PrivilegeWrite,
		PrivilegeRead:
		return true
	default:
		return false
	}
}

func (p *Permission) BeforeCreate(tx *gorm.DB) error {
	if p.ID == "" {
		p.ID = ulid.Make().String()
	}

	return nil
}
