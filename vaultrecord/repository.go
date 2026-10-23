package vaultrecord

import (
	"errors"

	"github.com/tacenva/tacpass-core/entity"
	"gorm.io/gorm"
)

type repository struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) *repository {
	return &repository{
		db: db,
	}
}

func (r *repository) Transaction(
	fn func(tx *gorm.DB) error,
) error {
	return r.db.Transaction(fn)
}

func (r *repository) IsAllowedToChange(
	tx *gorm.DB,
	vaultID string,
	groupID string,
) (bool, error) {
	var vault entity.Vault

	err := tx.
		Where(`
			EXISTS (
				SELECT 1
				FROM json_each(
					CASE
						WHEN json_valid(vaults.group_ids)
						THEN vaults.group_ids
						ELSE '[]'
					END
				)
				WHERE json_each.value = ?
			)
			AND vaults.id = ?
		`, groupID, vaultID).
		First(&vault).
		Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}
