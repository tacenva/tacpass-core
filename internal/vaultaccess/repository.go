package vaultaccess

import (
	tacenvaentity "github.com/tacenva/tacenva-core/entity"
	"github.com/tacenva/tacpass-core/entity"
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
	vaultAccesses []entity.VaultAccess,
) error {
	if len(vaultAccesses) == 0 {
		return nil
	}

	return tx.
		CreateInBatches(vaultAccesses, 100).
		Error
}

func (r *repository) DeleteBulkTx(
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

// func (r *repository) Upsert(
// 	tx *gorm.DB,
// 	vaultAccesses []entity.VaultAccess,
// ) error {
// 	if len(vaultAccesses) == 0 {
// 		return nil
// 	}

// 	records := make([]entity.VaultAccess, 0, len(vaultAccesses))

// 	for _, item := range vaultAccesses {
// 		if item.ID == "" {
// 			return gorm.ErrInvalidData
// 		}

// 		records = append(records, item)
// 	}

// 	if len(records) == 0 {
// 		return nil
// 	}

// 	return tx.
// 		Clauses(clause.OnConflict{
// 			Columns: []clause.Column{
// 				{Name: "id"},
// 			},
// 			DoUpdates: clause.AssignmentColumns([]string{
// 				"vault_id",
// 				"access_unit_id",
// 				"vault_key",
// 			}),
// 		}).
// 		Create(&records).
// 		Error
// }

func (r *repository) DeleteMissing(
	tx *gorm.DB,
	incomingIDs []string,
) error {
	if len(incomingIDs) > 0 {
		return nil
	}
	return tx.
		Where("id NOT IN ?", incomingIDs).
		Delete(&tacenvaentity.AccessGroup{}).
		Error
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

// func (r *repository)
