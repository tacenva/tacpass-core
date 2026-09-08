package app

import (
	"github.com/tacenva/tacpass-core/entity"
	"gorm.io/gorm"
)

func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&entity.Permission{},
		&entity.User{},
		&entity.Vault{},
		&entity.VaultAccess{},
	)
}
