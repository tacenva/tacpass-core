package vault

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

func (r *repository) Create(vault *entity.Vault) error {
	return r.db.Create(vault).Error
}

func (r *repository) FindByID(id string) (*entity.Vault, error) {
	var vault entity.Vault

	err := r.db.
		Where("id = ?", id).
		First(&vault).
		Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	return &vault, nil
}

func (r *repository) FindAccessible(permissionID string) ([]entity.Vault, error) {
	var vaults []entity.Vault

	err := r.db.
		Joins("JOIN vault_accesses ON vault_accesses.vault_id = vaults.id").
		Where("vault_accesses.permission_id = ?", permissionID).
		Find(&vaults).
		Error

	if err != nil {
		return nil, err
	}

	return vaults, nil
}

func (r *repository) Update(vault *entity.Vault) error {
	return r.db.
		Model(&entity.Vault{}).
		Where("id = ?", vault.ID).
		Update("name", vault.Name).
		Error
}

func (r *repository) Delete(id string) error {
	return r.db.
		Where("id = ?", id).
		Delete(&entity.Vault{}).
		Error
}
