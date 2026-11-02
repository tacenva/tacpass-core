package vault

import (
	"encoding/json"
	"errors"

	tacpassentity "github.com/tacenva/tacpass-core/entity"
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

func (r *repository) Create(
	tx *gorm.DB,
	vault *tacpassentity.Vault,
) error {
	return tx.Create(vault).Error
}

func (r *repository) FindByID(
	id string,
) (*tacpassentity.Vault, error) {
	var vault tacpassentity.Vault

	err := r.db.
		Where("id = ?", id).
		First(&vault).
		Error

	if err != nil {
		return nil, err
	}

	return &vault, nil
}

func (r *repository) FindAccessible(
	groupID string,
) ([]tacpassentity.Vault, error) {
	var vaults []tacpassentity.Vault

	err := r.db.
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
        `, groupID).
		Order("id ASC").
		Find(&vaults).
		Error

	if err != nil {
		return nil, err
	}

	return vaults, nil
}

func (r *repository) Update(
	tx *gorm.DB,
	vault *tacpassentity.Vault,
) *gorm.DB {
	groupIDsJSON, err := json.Marshal(vault.GroupIDs)
	if err != nil {
		return &gorm.DB{
			Error: err,
		}
	}

	return tx.
		Model(&tacpassentity.Vault{}).
		Where("id = ?", vault.ID).
		Updates(map[string]interface{}{
			"name":      vault.Name,
			"group_ids": string(groupIDsJSON),
		})
}

func (r *repository) Delete(
	tx *gorm.DB,
	id string,
) error {
	return tx.
		Where("id = ?", id).
		Delete(&tacpassentity.Vault{}).
		Error
}

func (r *repository) IsAllowedToChange(
	vaultID string,
	groupID string,
) (bool, error) {
	var vault tacpassentity.Vault

	err := r.db.
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
			return true, nil
		}
		return false, err
	}

	return true, nil
}
