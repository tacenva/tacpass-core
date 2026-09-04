package entity

import (
	"github.com/oklog/ulid/v2"
	"gorm.io/gorm"
)

type VaultAccess struct {
	ID           string `json:"-" gorm:"type:varchar(26);primaryKey"`
	VaultID      string `json:"-" gorm:"type:varchar(26);not null;uniqueIndex:idx_vault_permission"`
	PermissionID string `json:"-" gorm:"type:varchar(26);not null;uniqueIndex:idx_vault_permission"`
	VaultKey     string `json:"-" gorm:"type:text;not null"`

	Vault      Vault      `json:"-" gorm:"foreignKey:VaultID;references:ID;constraint:OnDelete:CASCADE"`
	Permission Permission `json:"-" gorm:"foreignKey:PermissionID;references:ID;constraint:OnDelete:CASCADE"`
}

func (p *VaultAccess) BeforeCreate(tx *gorm.DB) error {
	if p.ID == "" {
		p.ID = ulid.Make().String()
	}

	return nil
}
