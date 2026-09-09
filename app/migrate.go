package app

import (
	"github.com/tacenva/tacpass-core/entity"
	"gorm.io/gorm"
)

func Migrate(db *gorm.DB) error {
	if err := db.Exec("PRAGMA foreign_keys = ON").Error; err != nil {
		return err
	}

	return db.AutoMigrate(
		&entity.Permission{},
		&entity.User{},
		&entity.Vault{},
		&entity.VaultAccess{},
	)
}
