package permission

import (
	"errors"
	"fmt"
	"strings"

	"github.com/oklog/ulid/v2"
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

func (r *repository) findOrCreateGroup(
	tx *gorm.DB,
	permission *entity.Permission,
	parentGroupID string,
) error {
	group := &permission.Group

	parentGroupID = strings.TrimSpace(parentGroupID)
	group.Name = strings.TrimSpace(group.Name)

	// Validasi nama group.
	if group.ID == "" && group.Name == "" {
		return fmt.Errorf("permission group is required")
	}

	// Jika parent diberikan, pastikan parent memang ada.
	var parent entity.PermissionGroup
	if parentGroupID != "" {
		if err := tx.First(&parent, "id = ?", parentGroupID).Error; err != nil {
			return fmt.Errorf("find parent group: %w", err)
		}
	}

	// Cari group berdasarkan ID jika sudah ditentukan.
	if group.ID != "" {
		query := tx.Where("id = ?", group.ID)

		if group.SotID != "" {
			query = query.Where("sot_id = ?", group.SotID)
		}

		var existing entity.PermissionGroup
		if err := query.First(&existing).Error; err != nil {
			return err
		}

		*group = existing
	} else {
		// Cari group berdasarkan nama dalam SOT yang sama.
		var existing entity.PermissionGroup

		query := tx.Where("name = ?", group.Name)

		if parentGroupID != "" {
			query = query.Where("sot_id = ?", parent.SotID)
		} else if group.SotID != "" {
			query = query.Where("sot_id = ?", group.SotID)
		}

		err := query.First(&existing).Error

		switch {
		case err == nil:
			*group = existing

		case errors.Is(err, gorm.ErrRecordNotFound):
			group.ID = ulid.Make().String()

			if parentGroupID != "" {
				group.SotID = parent.SotID
			}

			if err := tx.Create(group).Error; err != nil {
				return fmt.Errorf("create permission group: %w", err)
			}

		default:
			return err
		}
	}

	permission.GroupID = group.ID
	permission.SotID = group.SotID

	// Tidak perlu membuat relasi jika parent tidak ditentukan
	// atau group itu sendiri adalah parent.
	if parentGroupID == "" || group.ID == parentGroupID {
		return nil
	}

	// Parent dan child harus berada dalam SOT yang sama.
	if parent.SotID != group.SotID {
		return fmt.Errorf("parent and child groups must belong to the same SOT")
	}

	// Cegah relasi duplikat.
	var hierarchy entity.PermissionGroupHierarchy
	err := tx.Where(
		"sot_id = ? AND parent_group_id = ? AND child_group_id = ?",
		group.SotID,
		parent.ID,
		group.ID,
	).First(&hierarchy).Error

	switch {
	case err == nil:
		return nil

	case !errors.Is(err, gorm.ErrRecordNotFound):
		return err
	}

	// Buat relasi parent -> child.
	hierarchy = entity.PermissionGroupHierarchy{
		SotID:         group.SotID,
		ParentGroupID: parent.ID,
		ChildGroupID:  group.ID,
	}

	if err := tx.Create(&hierarchy).Error; err != nil {
		return fmt.Errorf("create group hierarchy: %w", err)
	}

	return nil
}

func (r *repository) Create(
	permission *entity.Permission,
	parentGroupID string,
) error {
	if permission == nil {
		return fmt.Errorf("permission is required")
	}

	return r.db.Transaction(func(tx *gorm.DB) error {
		if permission.ID == "" {
			permission.ID = ulid.Make().String()
		}

		if err := r.findOrCreateGroup(tx, permission, parentGroupID); err != nil {
			return err
		}

		return tx.Create(permission).Error
	})
}

func (r *repository) Update(
	permission *entity.Permission,
	parentGroupID string,
) error {
	if permission == nil {
		return fmt.Errorf("permission is required")
	}

	permission.ID = strings.TrimSpace(permission.ID)
	if permission.ID == "" {
		return fmt.Errorf("permission id is required")
	}

	return r.db.Transaction(func(tx *gorm.DB) error {
		var existing entity.Permission

		if err := tx.First(&existing, "id = ?", permission.ID).Error; err != nil {
			return err
		}

		if err := r.findOrCreateGroup(tx, permission, parentGroupID); err != nil {
			return err
		}

		updates := map[string]interface{}{
			"name":         permission.Name,
			"privilege":    permission.Privilege,
			"public_key":   permission.PublicKey,
			"auto_approve": permission.AutoApprove,
			"group_id":     permission.GroupID,
			"sot_id":       permission.SotID,
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

func (r *repository) FindByGroupIDs(
	groupIDs []string,
) ([]entity.Permission, error) {
	if len(groupIDs) == 0 {
		return []entity.Permission{}, nil
	}

	var permissions []entity.Permission

	err := r.db.
		Preload("Users", func(tx *gorm.DB) *gorm.DB {
			return tx.Order("id ASC")
		}).
		Preload("Group").
		Where("group_id IN ?", groupIDs).
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

func (r *repository) GetPublicKeysByGroupIDs(
	groupIDs []string,
	sotID string,
) (map[string][]entity.Permission, error) {
	var permissions []entity.Permission

	err := r.db.
		Model(&entity.Permission{}).
		Select("id", "public_key", "group_id").
		Where("group_id IN ? AND sot_id = ?", groupIDs, sotID).
		Find(&permissions).Error
	if err != nil {
		return nil, err
	}

	result := make(map[string][]entity.Permission)

	for _, permission := range permissions {
		result[permission.GroupID] = append(
			result[permission.GroupID],
			permission,
		)
	}

	return result, nil
}

func (r *repository) GetGroupDescendants(
	groupID string,
) ([]entity.PermissionGroup, error) {
	var groups []entity.PermissionGroup

	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		return nil, fmt.Errorf("group ID is required")
	}

	err := r.db.Raw(`
		WITH RECURSIVE group_tree AS (
			SELECT pg.id, pg.sot_id, pg.name
			FROM permission_groups pg
			WHERE pg.id = ?

			UNION

			SELECT child.id, child.sot_id, child.name
			FROM permission_groups child
			INNER JOIN permission_group_hierarchies h
				ON h.child_group_id = child.id
				AND h.sot_id = child.sot_id
			INNER JOIN group_tree parent
				ON h.parent_group_id = parent.id
				AND h.sot_id = parent.sot_id
		)
		SELECT pg.*
		FROM permission_groups pg
		INNER JOIN group_tree tree
			ON tree.id = pg.id
			AND tree.sot_id = pg.sot_id
		ORDER BY pg.id ASC
	`, groupID).Scan(&groups).Error

	if err != nil {
		return nil, err
	}

	return groups, nil
}

func (r *repository) IsSameOrDescendantGroup(
	referenceGroupID string,
	candidateGroupID string,
	sotID string,
) (bool, error) {
	var exists bool

	err := r.db.Raw(`
		WITH RECURSIVE descendants(id, sot_id) AS (
			SELECT id, sot_id
			FROM permission_groups
			WHERE id = ? AND sot_id = ?

			UNION

			SELECT h.child_group_id, h.sot_id
			FROM permission_group_hierarchies h
			INNER JOIN descendants d
				ON h.parent_group_id = d.id
				AND h.sot_id = d.sot_id
		)
		SELECT EXISTS (
			SELECT 1
			FROM descendants
			WHERE id = ? AND sot_id = ?
		)
	`, referenceGroupID, sotID, candidateGroupID, sotID).
		Scan(&exists).Error

	if err != nil {
		return false, err
	}

	return exists, nil
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

func (r *repository) GetPermission(
	permissionID string,
	sotID string,
	withUsers bool,
) (*entity.Permission, error) {
	var permission entity.Permission

	query := r.db.
		Where("id = ? AND sot_id = ?", permissionID, sotID)

	if withUsers {
		query = query.Preload("Users")
	}

	err := query.First(&permission).Error
	if err != nil {
		return nil, err
	}

	return &permission, nil
}

func (r *repository) FindPermissionByUserID(
	userID string,
) (*entity.Permission, error) {
	var permission entity.Permission

	err := r.db.
		Joins("JOIN users ON users.permission_id = permissions.id").
		Where("users.id = ?", userID).
		First(&permission).
		Error
	if err != nil {
		return nil, err
	}

	return &permission, nil
}

func (r *repository) FindGroupBySotID(sotID string) ([]entity.PermissionGroup, error) {
	var groups []entity.PermissionGroup

	err := r.db.
		Where("sot_id = ?", sotID).
		Find(&groups).
		Error
	if err != nil {
		return nil, err
	}

	return groups, nil
}

func (r *repository) Transaction(
	fn func(tx *gorm.DB) error,
) error {
	return r.db.Transaction(fn)
}

func (r *repository) Upsert(
	tx *gorm.DB,
	sotID string,
	groups []entity.PermissionGroup,
) error {
	if len(groups) == 0 {
		return nil
	}

	for i := range groups {
		groups[i].SotID = sotID
	}

	return tx.
		Clauses(clause.OnConflict{
			Columns: []clause.Column{
				{Name: "id"},
				{Name: "sot_id"},
			},
			DoUpdates: clause.AssignmentColumns([]string{
				"name",
			}),
		}).
		Create(&groups).
		Error
}

func (r *repository) DeleteMissing(
	tx *gorm.DB,
	sotID string,
	incomingIDs []string,
) error {
	query := tx.Where("sot_id = ?", sotID)

	if len(incomingIDs) > 0 {
		query = query.Where("id NOT IN ?", incomingIDs)
	}

	return query.Delete(&entity.PermissionGroup{}).Error
}
