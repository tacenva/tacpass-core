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
	ID        string    `json:"id" gorm:"type:varchar(26);primaryKey"`
	Name      string    `json:"name,omitempty" gorm:"type:varchar(100);not null;uniqueIndex"`
	Privilege Privilege `json:"privilege,omitempty" gorm:"type:varchar(10);not null"`
	Group     string    `json:"group,omitempty" gorm:"type:varchar(100);not null;default:'';index"`
	PublicKey string    `json:"public_key,omitempty" gorm:"type:text;not null"`
	Revoked   bool      `json:"revoked,omitempty" gorm:"not null;default:false"`

	Users    []User        `json:"users,omitempty" gorm:"foreignKey:PermissionID;references:ID;constraint:OnDelete:CASCADE,OnUpdate:CASCADE"`
	Accesses []VaultAccess `json:"-" gorm:"foreignKey:PermissionID;references:ID;constraint:OnDelete:CASCADE,OnUpdate:CASCADE"`
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
