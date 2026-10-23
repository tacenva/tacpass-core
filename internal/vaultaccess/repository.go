package vaultaccess

import (
	"github.com/tacenva/tacpass-core/entity"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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
) ([]entity.VaultAccess, error) {
	var values []entity.VaultAccess

	err := r.db.
		Where("vault_id = ?", vaultID).
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

func (r *repository) DeleteBulkTx(
	tx *gorm.DB,
	vaultAccesses []*entity.VaultAccess,
) error {
	if len(vaultAccesses) == 0 {
		return nil
	}

	return tx.Delete(vaultAccesses).Error
}

func (r *repository) DeleteBulkByGroupIDsTx(
	tx *gorm.DB,
	groupIDs []string,
) error {
	if len(groupIDs) == 0 {
		return nil
	}

	permissionIDs := tx.
		Model(&entity.Permission{}).
		Select("id").
		Where("group_id IN ?", groupIDs)

	return tx.
		Where("permission_id IN (?)", permissionIDs).
		Delete(&entity.VaultAccess{}).
		Error
}

func (r *repository) Transaction(
	fn func(tx *gorm.DB) error,
) error {
	return r.db.Transaction(fn)
}

func (r *repository) Upsert(
	tx *gorm.DB,
	vaultAccesses []entity.VaultAccess,
) error {
	if len(vaultAccesses) == 0 {
		return nil
	}

	records := make([]entity.VaultAccess, 0, len(vaultAccesses))

	for _, item := range vaultAccesses {
		if item.ID == "" {
			return gorm.ErrInvalidData
		}

		records = append(records, item)
	}

	if len(records) == 0 {
		return nil
	}

	return tx.
		Clauses(clause.OnConflict{
			Columns: []clause.Column{
				{Name: "id"},
			},
			DoUpdates: clause.AssignmentColumns([]string{
				"vault_id",
				"permission_id",
				"vault_key",
			}),
		}).
		Create(&records).
		Error
}

func (r *repository) DeleteMissing(
	tx *gorm.DB,
	incomingIDs []string,
) error {
	if len(incomingIDs) > 0 {
		return nil
	}
	return tx.
		Where("id NOT IN ?", incomingIDs).
		Delete(&entity.PermissionGroup{}).
		Error
}
