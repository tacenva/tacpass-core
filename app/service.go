package app

import (
	"github.com/tacenva/database"
	"github.com/tacenva/tacpass-core/accesscontrol"
	"github.com/tacenva/tacpass-core/auth"
	"github.com/tacenva/tacpass-core/permission"
	"github.com/tacenva/tacpass-core/user"
	"github.com/tacenva/tacpass-core/vault"
	"github.com/tacenva/tacpass-core/vaultaccess"
	"gorm.io/gorm"
)

type Services struct {
	Auth          *auth.Service
	User          *user.Service
	Permission    *permission.Service
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

	vaultService := vault.NewService(
		vault.NewRepository(sqliteDB),
		tacenvaDB,
		vaultAccessService,
	)

	accessControlService := accesscontrol.NewService(
		userService,
		permissionService,
	)

	authService := auth.NewService(
		userService,
		permissionService,
	)

	return &Services{
		Auth:          authService,
		User:          userService,
		Permission:    permissionService,
		AccessControl: accessControlService,
		Vault:         vaultService,
		VaultAccess:   vaultAccessService,
	}
}
