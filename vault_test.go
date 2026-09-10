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
		vaultaccessService,
		permissionService,
	)

	return userService,
		permissionService,
		accesscontrolService,
		authService,
		vaultService,
		vaultaccessService
}
