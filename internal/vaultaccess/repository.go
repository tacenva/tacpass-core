package vaultaccess

import (
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

// func (r *repository) Create(
// 	tx *gorm.DB,
// 	vaultAccess *entity.VaultAccess,
// ) error {
// 	return tx.Create(vaultAccess).Error
// }

func (r *repository) CreateBulk(
	tx *gorm.DB,
	vaultAccesses []tacpassentity.VaultAccess,
) error {
	if len(vaultAccesses) == 0 {
		return nil
	}

	return tx.
		CreateInBatches(vaultAccesses, 100).
		Error
}

func (r *repository) DeleteBulk(
	tx *gorm.DB,
	vaultID string,
	toDelete []string,
) error {
	if len(toDelete) == 0 {
		return nil
	}

	return tx.
		Where("vault_id = ? AND access_group_id IN ?", vaultID, toDelete).
		Delete(&tacpassentity.VaultAccess{}).Error
}

// func (r *repository) DeleteMissing(
// 	tx *gorm.DB,
// 	incomingIDs []string,
// ) error {
// 	if len(incomingIDs) > 0 {
// 		return nil
// 	}
// 	return tx.
// 		Where("id NOT IN ?", incomingIDs).
// 		Delete(&tacenvaentity.AccessGroup{}).
// 		Error
// }

func (r *repository) FindByVaultAndAccessGroup(
	vaultID string,
	accessGroupID string,
) (*tacpassentity.VaultAccess, error) {
	var result tacpassentity.VaultAccess

	err := r.db.
		Where("vault_id = ? AND access_group_id = ?", vaultID, accessGroupID).
		First(&result).Error
	if err != nil {
		return nil, err
	}

	return &result, nil
}

func (r *repository) FindByVault(
	tx *gorm.DB,
	vaultID string,
) ([]tacpassentity.VaultAccess, error) {
	var result []tacpassentity.VaultAccess

	err := tx.
		Where("vault_id = ?", vaultID).
		Find(&result).Error
	if err != nil {
		return nil, err
	}

	return result, nil
}
