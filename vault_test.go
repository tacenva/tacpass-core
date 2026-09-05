package tacpass_core_test

import (
	"testing"

	"github.com/tacenva/database"
	"github.com/tacenva/tacpass-core/accesscontrol"
	"github.com/tacenva/tacpass-core/auth"
	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/permission"
	"github.com/tacenva/tacpass-core/user"
	"github.com/tacenva/tacpass-core/vault"
	"github.com/tacenva/tacpass-core/vaultaccess"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newTestVaultService(
	t *testing.T,
) (
	*user.Service,
	*permission.Service,
	*accesscontrol.Service,
	*auth.Service,
	*vault.Service,
	*vaultaccess.Service,
) {
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
		&entity.Vault{},
		&entity.VaultAccess{},
	)
	if err != nil {
		t.Fatalf("failed to migrate test database: %v", err)
	}

	// user
	userRepository := user.NewRepository(db)
	userService := user.NewService(userRepository)

	// permission
	permissionRepository := permission.NewRepository(db)
	permissionService := permission.NewService(permissionRepository)

	// access control
	accesscontrolService := accesscontrol.NewService(
		userService,
		permissionService,
	)

	// auth
	authService := auth.NewService(
		userService,
		permissionService,
	)

	// vault access
	vaultaccessRepository := vaultaccess.NewRepository(db)
	vaultaccessService := vaultaccess.NewService(
		vaultaccessRepository,
	)

	// vault
	vaultRepository := vault.NewRepository(db)
	tacenvaDB := database.New("test/")

	vaultService := vault.NewService(
		vaultRepository,
		tacenvaDB,
		permissionService,
		vaultaccessService,
	)

	return userService,
		permissionService,
		accesscontrolService,
		authService,
		vaultService,
		vaultaccessService
}

func TestLocalVault(t *testing.T) {
	_, permissionService, _, authService, vaultService, _ :=
		newTestVaultService(t)

	t.Log("create permission")

	permissionData, keyPair, err :=
		permissionService.Create(entity.PrivilegeAdmin)
	if err != nil {
		t.Fatalf("failed to create permission: %v", err)
	}

	t.Logf("created permission: %+v", permissionData)
	t.Logf("permission ID: %q", permissionData.ID)
	t.Logf("permission public key: %q", keyPair.PublicKey)

	t.Log("request enrollment")

	token, err := authService.RequestEnrollment(
		"hostname",
		keyPair.PublicKey,
		entity.UserStatusApproved,
	)
	if err != nil {
		t.Fatalf("failed to request enrollment: %v", err)
	}

	t.Log("authenticate")

	if err := authService.Authenticate(token); err != nil {
		t.Fatalf("failed to authenticate: %v", err)
	}

	t.Log("create vault")

	vaultData, err := vaultService.Create(
		"vault-1",
		token,
	)
	if err != nil {
		t.Fatalf("failed to create vault: %v", err)
	}

	t.Logf("created vault: %+v", vaultData)
	t.Logf("vault ID: %q", vaultData.ID)
}
