package app

import (
	"github.com/tacenva/database"
	"github.com/tacenva/tacpass-core/accesscontrol"
	"github.com/tacenva/tacpass-core/auth"
	"github.com/tacenva/tacpass-core/internal/permission"
	"github.com/tacenva/tacpass-core/internal/sync"
	"github.com/tacenva/tacpass-core/internal/user"
	"github.com/tacenva/tacpass-core/internal/vaultaccess"
	"github.com/tacenva/tacpass-core/vault"
	"gorm.io/gorm"
)

type Services struct {
	Auth          *auth.Service
	AccessControl *accesscontrol.Service
	Vault         *vault.Service
	VaultAccess   *vaultaccess.Service
}

func NewServices(
	sqliteDB *gorm.DB,
	tacenvaDB *database.DB,
) *Services {
	userService := user.NewService(
		user.NewRepository(sqliteDB),
	)

	permissionService := permission.NewService(
		permission.NewRepository(sqliteDB),
	)

	vaultAccessService := vaultaccess.NewService(
		vaultaccess.NewRepository(sqliteDB),
	)

	syncService := sync.NewService(sqliteDB)
	vaultService := vault.NewService(
		vault.NewRepository(sqliteDB),
		tacenvaDB,
		vaultAccessService,
		permissionService,
		syncService,
	)

	accessControlService := accesscontrol.NewService(
		userService,
		permissionService,
		vaultAccessService,
		vaultService,
	)

	authService := auth.NewService(
		userService,
		permissionService,
	)

	return &Services{
		Auth:          authService,
		AccessControl: accessControlService,
		Vault:         vaultService,
		VaultAccess:   vaultAccessService,
	}
}
