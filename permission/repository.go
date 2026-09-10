package permission

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

func (r *repository) Create(permission *entity.Permission) error {
	return r.db.Create(permission).Error
}

func (r *repository) Find(id string) (*entity.Permission, error) {
	var permission entity.Permission

	err := r.db.
		Preload("Users").
		Where("id = ?", id).
		First(&permission).
		Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	return &permission, nil
}

func (r *repository) FindAdmin() (*entity.Permission, error) {
	var permission entity.Permission

	err := r.db.
		Where("privilege = ?", entity.PrivilegeAdmin).
		First(&permission).
		Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	return &permission, nil
}

func (r *repository) FindByPublicKey(publicKey string) (*entity.Permission, error) {
	var permission entity.Permission

	err := r.db.
		Where("public_key = ?", publicKey).
		First(&permission).
		Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	return &permission, nil
}

func (r *repository) FindAll() ([]entity.Permission, error) {
	var permissions []entity.Permission

	err := r.db.
		Order("id ASC").
		Find(&permissions).
		Error

	if err != nil {
		return nil, err
	}

	return permissions, nil
}

func (r *repository) Update(permission *entity.Permission) error {
	return r.db.
		Model(&entity.Permission{}).
		Where("id = ?", permission.ID).
		Updates(map[string]any{
			"name":      permission.Name,
			"privilege": permission.Privilege,
			"revoked":   permission.Revoked,
		}).
		Error
}

func (r *repository) Delete(id string) error {
	return r.db.
		Where("id = ?", id).
		Delete(&entity.Permission{}).
		Error
}
