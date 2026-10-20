package permission

import (
	"errors"
	"fmt"
	"strings"

	"github.com/oklog/ulid/v2"
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

func (r *repository) findOrCreateGroup(
	tx *gorm.DB,
	permission *entity.Permission,
) error {
	if permission.Privilege == entity.PrivilegeAdmin {
		permission.GroupID = nil
		return nil
	}

	group := &permission.Group

	// Jika ID tersedia, gunakan group yang sudah ada.
	if group.ID != "" {
		var existing entity.PermissionGroup

		if err := tx.First(&existing, "id = ?", group.ID).Error; err != nil {
			return err
		}

		group.ID = existing.ID
		group.Name = existing.Name

		groupID := existing.ID
		permission.GroupID = &groupID

		return nil
	}

	// Jika ID kosong, cari berdasarkan nama.
	name := strings.TrimSpace(group.Name)
	if name == "" {
		return fmt.Errorf("permission group is required")
	}

	var existing entity.PermissionGroup

	err := tx.Where("name = ?", name).First(&existing).Error

	switch {
	case err == nil:
		group.ID = existing.ID
		group.Name = existing.Name

	case errors.Is(err, gorm.ErrRecordNotFound):
		group.ID = ulid.Make().String()
		group.Name = name

		if err := tx.Create(group).Error; err != nil {
			return err
		}

	default:
		return err
	}

	groupID := group.ID
	permission.GroupID = &groupID

	return nil
}

func (r *repository) Create(permission *entity.Permission) error {
	if permission == nil {
		return fmt.Errorf("permission is required")
	}

	return r.db.Transaction(func(tx *gorm.DB) error {
		if permission.ID == "" {
			permission.ID = ulid.Make().String()
		}

		if err := r.findOrCreateGroup(tx, permission); err != nil {
			return err
		}

		return tx.Create(permission).Error
	})
}

func (r *repository) Update(permission *entity.Permission) error {
	if permission == nil {
		return fmt.Errorf("permission is required")
	}

	permission.ID = strings.TrimSpace(permission.ID)
	if permission.ID == "" {
		return fmt.Errorf("permission id is required")
	}

	return r.db.Transaction(func(tx *gorm.DB) error {
		// Pastikan permission yang akan diperbarui memang ada.
		var existing entity.Permission

		if err := tx.First(&existing, "id = ?", permission.ID).Error; err != nil {
			return err
		}

		if err := r.findOrCreateGroup(tx, permission); err != nil {
			return err
		}

		updates := map[string]interface{}{
			"name":         permission.Name,
			"privilege":    permission.Privilege,
			"public_key":   permission.PublicKey,
			"auto_approve": permission.AutoApprove,
			"group_id":     permission.GroupID,
		}

		result := tx.Model(&entity.Permission{}).
			Where("id = ?", permission.ID).
			Updates(updates)

		if result.Error != nil {
			return result.Error
		}

		if result.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}

		return nil
	})
}

func (r *repository) SetRevoked(id string, revoked bool) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("permission id is required")
	}

	result := r.db.
		Model(&entity.Permission{}).
		Where("id = ?", id).
		Update("revoked", revoked)

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	return nil
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

func (r *repository) FindByPublicKey(
	publicKey string,
) (*entity.Permission, error) {
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

func (r *repository) FindAllByUserStatus(
	status entity.UserStatus,
) ([]entity.Permission, error) {
	var permissions []entity.Permission

	err := r.db.
		Preload("Users", func(tx *gorm.DB) *gorm.DB {
			return tx.Order("id ASC")
		}).
		Where(
			"EXISTS (?)",
			r.db.
				Model(&entity.User{}).
				Select("1").
				Where("users.permission_id = permissions.id").
				Where("users.status = ?", status),
		).
		Order("id ASC").
		Find(&permissions).
		Error

	if err != nil {
		return nil, err
	}

	return permissions, nil
}

func (r *repository) FindAll() ([]entity.Permission, error) {
	var permissions []entity.Permission

	err := r.db.
		Preload("Users", func(tx *gorm.DB) *gorm.DB {
			return tx.Order("id ASC")
		}).
		Preload("Group").
		Order("id ASC").
		Find(&permissions).
		Error

	if err != nil {
		return nil, err
	}

	return permissions, nil
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

func (r *repository) ConnectedPublicKeys(
	groupID string,
) ([]entity.Permission, error) {
	var permissions []entity.Permission
	err := r.db.
		Select("id", "public_key").
		Where("group_id = ?", groupID).
		Find(&permissions).
		Error

	if err != nil {
		return nil, err
	}

	return permissions, nil
}

func (r *repository) GetGroups() ([]entity.PermissionGroup, error) {
	var groups []entity.PermissionGroup

	err := r.db.Transaction(func(tx *gorm.DB) error {
		// Hapus group yang tidak digunakan permission mana pun.
		if err := tx.
			Where(`
				NOT EXISTS (
					SELECT 1
					FROM permissions
					WHERE permissions.group_id = permission_groups.id
				)
			`).
			Delete(&entity.PermissionGroup{}).
			Error; err != nil {
			return err
		}

		return tx.
			Order("id ASC").
			Find(&groups).
			Error
	})

	if err != nil {
		return nil, err
	}

	return groups, nil
}

func (r *repository) UpdateGroup(
	group *entity.PermissionGroup,
) error {
	if group == nil {
		return fmt.Errorf("permission group is required")
	}

	return r.db.Transaction(func(tx *gorm.DB) error {
		result := tx.
			Model(&entity.PermissionGroup{}).
			Where("id = ?", group.ID).
			Update("name", strings.TrimSpace(group.Name))

		if result.Error != nil {
			return result.Error
		}

		if result.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}

		return nil
	})
}

func (r *repository) DeleteGroup(id string) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		var group entity.PermissionGroup

		if err := tx.
			Where("id = ?", id).
			First(&group).
			Error; err != nil {
			return err
		}

		var count int64

		if err := tx.
			Model(&entity.Permission{}).
			Where("group_id = ?", id).
			Count(&count).
			Error; err != nil {
			return err
		}

		if count > 0 {
			return fmt.Errorf(
				"group masih digunakan oleh %d permission",
				count,
			)
		}

		return tx.Delete(&group).Error
	})
}
