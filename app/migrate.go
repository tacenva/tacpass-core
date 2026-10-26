package app

import (
	tacenvaapp "github.com/tacenva/tacenva-core/app"
	"github.com/tacenva/tacpass-core/entity"
	"gorm.io/gorm"
)

func Migrate(db *gorm.DB) error {
	if err := db.Exec("PRAGMA foreign_keys = ON").Error; err != nil {
		return err
	}

	tacenvaapp.Migrate(db)

	return db.AutoMigrate(
		&entity.Vault{},
		&entity.VaultAccess{},
	)
}
