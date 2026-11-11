package vaultaccess

import (
	"github.com/tacenva/tacpass-core/contract"
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

func (r *repository) Exists(
	vaultID string,
	accessGroupID string,
) (bool, error) {
	var count int64

	err := r.db.
		Model(&tacpassentity.VaultAccess{}).
		Where(
			"vault_id = ? AND access_group_id = ?",
			vaultID,
			accessGroupID,
		).
		Count(&count).Error

	if err != nil {
		return false, err
	}

	return count > 0, nil
}

func (r *repository) CountAccessibleVaults(
	vaultIDs []string,
	accessGroupID string,
) (int64, error) {
	if len(vaultIDs) == 0 {
		return 0, nil
	}

	var count int64

	err := r.db.
		Model(&tacpassentity.VaultAccess{}).
		Where("vault_id IN ?", vaultIDs).
		Where("access_group_id = ?", accessGroupID).
		Count(&count).
		Error

	if err != nil {
		return 0, err
	}

	return count, nil
}

func (r *repository) FindVaultChangeData(
	vaultIDs []string,
	accessGroupID string,
) (map[contract.VaultID]contract.VaultChangeData, error) {
	if len(vaultIDs) == 0 {
		return nil, nil
	}

	var results []struct {
		Vault       tacpassentity.Vault       `gorm:"embedded"`
		VaultAccess tacpassentity.VaultAccess `gorm:"embedded;embeddedPrefix:vault_access_"`
	}

	err := r.db.
		Table("vault_accesses AS va").
		Select(`
            v.*,
            va.id AS vault_access_id,
            va.vault_id AS vault_access_vault_id,
            va.access_group_id AS vault_access_access_group_id,
            va.wrapped_vault_key AS vault_access_wrapped_vault_key,
            va.created_at AS vault_access_created_at,
            va.updated_at AS vault_access_updated_at
        `).
		Joins("JOIN vaults AS v ON v.id = va.vault_id").
		Where("va.vault_id IN ?", vaultIDs).
		Where("va.access_group_id = ?", accessGroupID).
		Scan(&results).
		Error
	if err != nil {
		return nil, err
	}

	result := make(
		map[contract.VaultID]contract.VaultChangeData,
		len(results),
	)

	for _, item := range results {
		vaultID := item.Vault.ID

		data := result[vaultID]
		data.Vault = item.Vault
		data.VaultAccessList = append(
			data.VaultAccessList,
			item.VaultAccess,
		)

		result[vaultID] = data
	}

	return result, nil
}
