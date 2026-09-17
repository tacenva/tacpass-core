package user

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

func (r *repository) Create(user *entity.User) error {
	return r.db.Create(user).Error
}

func (r *repository) FindByID(id string) (*entity.User, error) {
	var user entity.User

	err := r.db.
		Where("id = ?", id).
		First(&user).
		Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (r *repository) FindByToken(tokenHash string) (*entity.User, error) {
	var user entity.User

	err := r.db.
		Preload("Permission").
		Where("token = ?", tokenHash).
		First(&user).
		Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (r *repository) FindAll() ([]entity.User, error) {
	var users []entity.User

	err := r.db.
		Order("hostname ASC").
		Find(&users).
		Error

	if err != nil {
		return nil, err
	}

	return users, nil
}

func (r *repository) Update(user *entity.User) error {
	return r.db.
		Model(&entity.User{}).
		Where("id = ?", user.ID).
		Updates(map[string]any{
			"permission_id": user.PermissionID,
			"hostname":      user.Hostname,
			"token":         user.Token,
			"status":        user.Status,
		}).
		Error
}

func (r *repository) Delete(id string) error {
	return r.db.
		Where("id = ?", id).
		Delete(&entity.User{}).
		Error
}
