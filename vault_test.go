package tacpass_core_test

import (
	"testing"

	"github.com/tacenva/tacpass-core/accesscontrol"
	"github.com/tacenva/tacpass-core/auth"
	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/permission"
	"github.com/tacenva/tacpass-core/user"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newTestVaultService(t *testing.T) (*user.Service, *permission.Service, *accesscontrol.Service, *auth.Service) {
	t.Helper()

	db, err := gorm.Open(
		sqlite.Open(":memory:"),
		&gorm.Config{},
	)
	if err != nil {
		t.Fatalf("failed to open test database: %v", err)
	}

	err = db.AutoMigrate(
		&entity.User{},
		&entity.Permission{},
	)
	if err != nil {
		t.Fatalf("failed to migrate test database: %v", err)
	}

	userRepository := user.NewRepository(db)
	userService := user.NewService(userRepository)

	permissionRepository := permission.NewRepository(db)
	permissionService := permission.NewService(permissionRepository)
	accesscontrolService := accesscontrol.NewService(userService, permissionService)

	return userService, permissionService, accesscontrolService, auth.NewService(
		userService,
		permissionService,
	)
}

func TestLocalVault(t *testing.T) {
	_, permissionService, _, authService := newTestAuthService(t)

	_, permissionToken, err := permissionService.Create(entity.PrivilegeAdmin)
	if err != nil {
		t.Fatalf("failed to create permission: %v", err)
	}

	_, err = authService.Access("hostname", permissionToken, entity.UserStatusApproved)
}

func TestRemoteVault(t *testing.T) {
	_, _, accesscontrolService, authService := newTestAuthService(t)

	t.Log("create permission")

	permission, permissionToken, err := accesscontrolService.Create(entity.PrivilegeAdmin)
	if err != nil {
		t.Fatalf("failed to create permission: %v", err)
	}

	t.Logf("created permission: %+v", permission)
	t.Logf("permission ID: %q", permission.ID)
	t.Logf("permission token: %q", permissionToken)

	t.Log("access")

	_, err = authService.Access("hostname", permissionToken, entity.UserStatusPending)
	if err != nil {
		t.Fatalf("failed to create permission: %v", err)
	}

	t.Log("list permissions")

	permissions, err := accesscontrolService.List()
	selectedPermission := permissions[0]

	t.Logf("selected permission: %s", selectedPermission.ID)

	t.Log("list users")

	users, err := accesscontrolService.UserList(selectedPermission.ID)

	t.Logf("user list error: %v", err)
	t.Logf("user list length: %d", len(users))
	t.Logf("users: %+v", users)

	selectedUser := users[0]

	t.Logf("selected user: %s", selectedUser.ID)

	t.Log("approve user")

	_, err = accesscontrolService.ApproveUser(selectedUser.ID)

	t.Log("revoke user")

	// revoked user
	_, err = accesscontrolService.RevokeUser(selectedUser.ID)

	t.Log("change privilege")

	err = accesscontrolService.ChangePrivilege(
		selectedPermission.ID,
		entity.PrivilegeWrite,
	)

	t.Log("revoke permission")

	err = accesscontrolService.Revoke(selectedPermission.ID)
}
