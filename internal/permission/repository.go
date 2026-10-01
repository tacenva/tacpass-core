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

	result := r.db.
		Where("privilege = ?", entity.PrivilegeAdmin).
		Limit(1).
		Find(&permission)

	if result.Error != nil {
		return nil, result.Error
	}

	if result.RowsAffected == 0 {
		return nil, nil
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

func (r *repository) FindAllByUserStatus(status entity.UserStatus) ([]entity.Permission, error) {
	var permissions []entity.Permission

	err := r.db.
		Preload("Users").
		Where(
			"EXISTS (?)",
			r.db.
				Model(&entity.User{}).
				Select("1").
				Where(
					"users.permission_id = permissions.id",
				).
				Where(
					"users.status = ?",
					status,
				),
		).
		Order("id ASC").
		Find(&permissions).
		Error

	if err != nil {
		return nil, err
	}

	return permissions, nil
}

func (r *repository) FindAllWithoutRevokedUsers() ([]entity.Permission, error) {
	var permissions []entity.Permission

	err := r.db.
		Preload("Users").
		Where(
			"EXISTS (?)",
			r.db.
				Model(&entity.User{}).
				Select("1").
				Where(
					"users.permission_id = permissions.id",
				).
				Where(
					"users.status != ?",
					entity.UserStatusRevoked,
				),
		).
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
			"group":     permission.Group,
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

func (r *repository) ListPublicKey() ([]entity.Permission, error) {
	var permissions []entity.Permission
	err := r.db.
		Select("id", "public_key").
		Find(&permissions).
		Error
	if err != nil {
		return nil, err
	}

	return permissions, nil
}

func (r *repository) GetConnectedPermission(authUser *entity.User) ([]entity.Permission, error) {
	if authUser.Permission.Privilege == entity.PrivilegeAdmin {
		return r.ListPublicKey()
	}

	var permissions []entity.Permission
	err := r.db.
		Select("id", "public_key").
		Where("group = ?", authUser.Permission.Group).
		Find(&permissions).
		Error

	if err != nil {
		return nil, err
	}

	return permissions, nil
}
