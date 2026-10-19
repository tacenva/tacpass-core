package vault

import (
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

func (r *repository) Create(
	tx *gorm.DB,
	vault *entity.Vault,
) error {
	return tx.Create(vault).Error
}

func (r *repository) FindByID(
	id string,
) (*entity.Vault, error) {
	var vault entity.Vault

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
	permissionID string,
) ([]entity.VaultAccess, error) {
	var vaultAccessList []entity.VaultAccess

	err := r.db.
		Where("permission_id = ?", permissionID).
		Preload("Vault").
		Find(&vaultAccessList).
		Order("id ASC").
		Error

	if err != nil {
		return nil, err
	}

	return vaultAccessList, nil
}

func (r *repository) Update(
	tx *gorm.DB,
	vault *entity.Vault,
) error {
	return tx.
		Model(&entity.Vault{}).
		Where("id = ?", vault.ID).
		Update("name", vault.Name).
		Error
}

func (r *repository) FirstOrCreate(
	tx *gorm.DB,
	vault *entity.Vault,
) error {
	return tx.
		Where("id = ?", vault.ID).
		Assign(map[string]any{
			"name": vault.Name,
		}).
		FirstOrCreate(vault).
		Error
}

func (r *repository) Delete(
	tx *gorm.DB,
	id string,
) error {
	return tx.
		Where("id = ?", id).
		Delete(&entity.Vault{}).
		Error
}
