package vaultaccess

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

func (r *repository) Create(
	vaultAccess *entity.VaultAccess,
) error {
	return r.db.Create(vaultAccess).Error
}

func (r *repository) CreateTx(
	tx *gorm.DB,
	vaultAccess *entity.VaultAccess,
) error {
	return tx.Create(vaultAccess).Error
}

func (r *repository) CreateBulk(
	vaultAccesses []*entity.VaultAccess,
) error {
	if len(vaultAccesses) == 0 {
		return nil
	}

	return r.db.
		CreateInBatches(vaultAccesses, 100).
		Error
}

func (r *repository) CreateBulkTx(
	tx *gorm.DB,
	vaultAccesses []*entity.VaultAccess,
) error {
	if len(vaultAccesses) == 0 {
		return nil
	}

	return tx.
		CreateInBatches(vaultAccesses, 100).
		Error
}

func (r *repository) CreateOrUpdateBulkTx(
	tx *gorm.DB,
	vaultAccesses []*entity.VaultAccess,
) error {
	if len(vaultAccesses) == 0 {
		return nil
	}

	for _, vaultAccess := range vaultAccesses {
		if vaultAccess == nil {
			continue
		}

		if vaultAccess.ID == "" {
			return gorm.ErrInvalidData
		}

		result := tx.
			Model(&entity.VaultAccess{}).
			Where("id = ?", vaultAccess.ID).
			Updates(map[string]any{
				"vault_id":      vaultAccess.VaultID,
				"permission_id": vaultAccess.PermissionID,
				"vault_key":     vaultAccess.VaultKey,
			})

		if result.Error != nil {
			return result.Error
		}

		if result.RowsAffected == 0 {
			if err := tx.Create(vaultAccess).Error; err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *repository) FindByPermissionID(
	permissionId string,
) (*entity.VaultAccess, error) {
	var vaultAccess entity.VaultAccess

	err := r.db.
		First(&vaultAccess, "permission_id = ?", permissionId).
		Error

	if err != nil {
		return nil, err
	}

	return &vaultAccess, nil
}

func (r *repository) FindByVaultID(
	vaultID string,
	permissionID string,
) ([]entity.VaultAccess, error) {
	var values []entity.VaultAccess

	err := r.db.
		Where("vault_id = ? AND permission_id = ?", vaultID, permissionID).
		Find(&values).
		Error

	if err != nil {
		return nil, err
	}

	return values, nil
}

func (r *repository) FindByVaultAndPermission(
	vaultID string,
	permissionID string,
) (*entity.VaultAccess, error) {
	var vaultAccess entity.VaultAccess

	err := r.db.
		Where(
			"vault_id = ? AND permission_id = ?",
			vaultID,
			permissionID,
		).
		First(&vaultAccess).
		Error

	if err != nil {
		return nil, err
	}

	return &vaultAccess, nil
}

func (r *repository) FindAll() ([]entity.VaultAccess, error) {
	var vaultAccesses []entity.VaultAccess

	err := r.db.
		Find(&vaultAccesses).
		Error

	if err != nil {
		return nil, err
	}

	return vaultAccesses, nil
}

func (r *repository) Update(
	vaultAccess *entity.VaultAccess,
) error {
	return r.db.Save(vaultAccess).Error
}

func (r *repository) Delete(id string) error {
	result := r.db.Delete(
		&entity.VaultAccess{},
		"id = ?",
		id,
	)

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	return nil
}
