package vault

import (
	"errors"
	"strings"

	tacenvaentity "github.com/tacenva/tacenva-core/entity"
	"github.com/tacenva/tacenva-core/genericerror"
	"github.com/tacenva/tacpass-core/errormessage"
)

var (
	errWriterOnly        = errors.New("only users with write access are allowed to perform this action")
	errInvalidAuthorizer = genericerror.ErrEmptyValue
)

func (s *SotService) verifyWriterAccess(
	authorizedUser *tacenvaentity.User,
) error {
	if authorizedUser == nil {
		return errInvalidAuthorizer
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
		return genericerror.ErrEmptyValue
	}

	exists, err := s.vaultaccessService.Exists(
		vaultID,
		authorizedUser.AccessUnit.GroupID,
	)
	if err != nil {
		return err
	}

	if !exists {
		return errormessage.ErrPermission
	}

	return nil
}
