package vault

import (
	"errors"
	"strings"

	tacenvaentity "github.com/tacenva/tacenva-core/entity"
	"github.com/tacenva/tacenva-core/genericerror"
)

var (
	errWriterOnly        = errors.New("only users with write access are allowed to perform this action")
	errInvalidAuthorized = genericerror.ErrRequired("authorized user")
)

func (s *SotService) verifyWriterAccess(
	authorizedUser *tacenvaentity.User,
) error {
	if authorizedUser == nil {
		return errInvalidAuthorized
	}

	if err := authorizedUser.ValidateAccess(); err != nil {
		return err
	}

	if !authorizedUser.HasWriteAccess() {
		return errWriterOnly
	}

	return nil
}

func (s *SotService) verifyVaultAccess(
	authorizedUser *tacenvaentity.User,
	vaultID string,
) error {
	if err := s.verifyWriterAccess(authorizedUser); err != nil {
		return err
	}

	vaultID = strings.TrimSpace(vaultID)
	if vaultID == "" {
		return genericerror.ErrRequired("vault id")
	}

	exists, err := s.vaultaccessService.Exists(
		vaultID,
		authorizedUser.AccessUnit.GroupID,
	)
	if err != nil {
		return err
	}

	if !exists {
		return genericerror.ErrPermissionDenied
	}

	return nil
}
