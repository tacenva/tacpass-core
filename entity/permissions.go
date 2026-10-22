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
	ID    string `json:"id" gorm:"type:varchar(26);primaryKey"`
	SotID string `json:"sot_id,omitempty" gorm:"type:varchar(26);primaryKey"`
	Name  string `json:"name,omitempty" gorm:"type:varchar(100);not null"`

	Permissions []Permission `json:"permissions,omitempty" gorm:"foreignKey:GroupID,SotID;references:ID,SotID"`
}

type PermissionGroupHierarchy struct {
	SotID         string `json:"sot_id" gorm:"type:varchar(26);primaryKey"`
	ParentGroupID string `json:"parent_group_id" gorm:"type:varchar(26);primaryKey;index"`
	ChildGroupID  string `json:"child_group_id" gorm:"type:varchar(26);primaryKey;index"`

	Parent PermissionGroup `json:"parent,omitempty" gorm:"foreignKey:ParentGroupID,SotID;references:ID,SotID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	Child  PermissionGroup `json:"child,omitempty" gorm:"foreignKey:ChildGroupID,SotID;references:ID,SotID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

type Permission struct {
	ID          string    `json:"id" gorm:"type:varchar(26);primaryKey"`
	Name        string    `json:"name" gorm:"type:varchar(100);not null;uniqueIndex"`
	GroupID     string    `json:"group_id" gorm:"type:varchar(26);not null;index"`
	SotID       string    `json:"sot_id" gorm:"type:varchar(26);not null;index"`
	Privilege   Privilege `json:"privilege,omitempty" gorm:"type:varchar(10);not null"`
	PublicKey   string    `json:"public_key,omitempty" gorm:"type:text;not null"`
	Revoked     bool      `json:"revoked" gorm:"not null;default:false"`
	AutoApprove bool      `json:"auto_approve" gorm:"not null;default:false"`

	Group    PermissionGroup `json:"group,omitempty" gorm:"foreignKey:GroupID,SotID;references:ID,SotID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
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
