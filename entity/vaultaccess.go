package entity

import (
	"github.com/oklog/ulid/v2"
	// tacenvaentity "github.com/tacenva/tacenva-core/entity"
	"gorm.io/gorm"
)

type VaultAccess struct {
	ID              string `json:"id" gorm:"type:varchar(26);primaryKey"`
	VaultID         string `json:"vault_id,omitempty" gorm:"type:varchar(26);not null;uniqueIndex:idx_vault_permission"`
	AccessGroupID   string `json:"access_group_id,omitempty" gorm:"type:varchar(26);not null;uniqueIndex:idx_vault_permission"`
	WrappedVaultKey string `json:"wrapped_vault_key,omitempty" gorm:"type:text;not null"`

	Vault Vault `json:"vault,omitempty" gorm:"foreignKey:VaultID;references:ID;constraint:OnDelete:CASCADE,OnUpdate:CASCADE"`
	// Permission tacenvaentity.Permission `json:"-" gorm:"foreignKey:PermissionID;references:ID;constraint:OnDelete:CASCADE,OnUpdate:CASCADE"`
}

func (p *VaultAccess) BeforeCreate(tx *gorm.DB) error {
	if p.ID == "" {
		p.ID = ulid.Make().String()
	}

	return nil
}
