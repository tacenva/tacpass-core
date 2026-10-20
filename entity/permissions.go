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

type PermissionGroup struct {
	ID   string `json:"id" gorm:"type:varchar(26);primaryKey"`
	Name string `json:"name,omitempty" gorm:"type:varchar(100);not null;uniqueIndex"`

	Permissions []Permission `json:"permissions,omitempty" gorm:"foreignKey:GroupID;references:ID"`
}

type Permission struct {
	ID          string    `json:"id" gorm:"type:varchar(26);primaryKey"`
	Name        string    `json:"name,omitempty" gorm:"type:varchar(100);not null;uniqueIndex"`
	Privilege   Privilege `json:"privilege,omitempty" gorm:"type:varchar(10);not null"`
	GroupID     *string   `json:"group_id" gorm:"type:varchar(26);index"`
	PublicKey   string    `json:"public_key,omitempty" gorm:"type:text;not null"`
	Revoked     bool      `json:"revoked" gorm:"not null;default:false"`
	AutoApprove bool      `json:"auto_approve" gorm:"not null;default:false"`

	Group    PermissionGroup `json:"group,omitempty" gorm:"foreignKey:GroupID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
	Users    []User          `json:"users,omitempty" gorm:"foreignKey:PermissionID;references:ID;constraint:OnDelete:CASCADE,OnUpdate:CASCADE"`
	Accesses []VaultAccess   `json:"-" gorm:"foreignKey:PermissionID;references:ID;constraint:OnDelete:CASCADE,OnUpdate:CASCADE"`
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
