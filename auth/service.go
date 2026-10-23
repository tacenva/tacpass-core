package auth

import (
	"errors"
	"os"

	"github.com/tacenva/tacpass-core/contract"
	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/internal/permission"
	"github.com/tacenva/tacpass-core/internal/user"
)

var (
	ErrPermission = errors.New("permission denied")
)

type Service struct {
	userService       *user.Service
	permissionService *permission.Service
}

func NewService(
	userService *user.Service,
	permissionService *permission.Service,
) *Service {
	return &Service{
		userService:       userService,
		permissionService: permissionService,
	}
}

func (s *Service) Enroll(
	enrollRequest *contract.EnrollRequest,
	sotID string,
	userStatus entity.UserStatus,
) (*contract.EnrollResponse, error) {
	permission, err := s.permissionService.GetByPublicKey(enrollRequest.PublicKey)
	if err != nil {
		return nil, err
	}

	if userStatus == entity.UserStatusPending && permission.AutoApprove {
		userStatus = entity.UserStatusApproved
	}

	user, token, err := s.userService.Create(enrollRequest.Hostname, permission.ID, userStatus)
	if err != nil {
		return nil, err
	}

	sotHostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	response := contract.EnrollResponse{
		SoTHostname: sotHostname,
		Status:      userStatus,
		AuthToken:   token,
		Privilege:   permission.Privilege,
	}

	if userStatus == entity.UserStatusApproved {
		groups, err := s.permissionService.GroupList(sotID)
		if err != nil {
			return nil, err
		}
		response.GroupAssignment = &contract.GroupAssignment{
			ID:    user.Permission.GroupID,
			Items: groups,
		}
	}

	return &response, nil
}

func (s *Service) GetUserData(token string) (*entity.User, error) {
	userData, err := s.userService.GetByToken(token)
	if err != nil {
		return nil, err
	}

	if userData.Permission.Revoked {
		return nil, permission.ErrRevoked
	}

	switch userData.Status {
	case entity.UserStatusApproved:
		return userData, nil

	case entity.UserStatusPending:
		return nil, user.ErrPending

	case entity.UserStatusRevoked:
		return nil, user.ErrRevoked

	default:
		return nil, user.ErrStatusInvalid
	}
}

func (s *Service) CheckStatus(
	token string,
	sotID string,
) (*contract.AuthData, error) {
	userData, err := s.userService.GetByToken(token)
	if err != nil {
		return nil, err
	}

	authData := contract.AuthData{
		Status:    userData.Status,
		Privilege: userData.Permission.Privilege,
	}

	if userData.Permission.Revoked {
		authData.Status = entity.UserStatusRevoked
		return &authData, permission.ErrRevoked
	}

	if userData.HasWritePermission() {
		groups, err := s.permissionService.GroupList(sotID)
		if err != nil {
			return nil, err
		}

		authData.GroupAssignment = &contract.GroupAssignment{
			ID:    userData.Permission.GroupID,
			Items: groups,
		}
	}

	return &authData, nil
}

func (s *Service) GroupAssignment(
	authUser *entity.User,
	sotID string,
) (*contract.GroupAssignment, error) {
	if !authUser.HasWritePermission() {
		return nil, ErrPermission
	}

	groups, err := s.permissionService.GroupList(sotID)
	if err != nil {
		return nil, err
	}

	return &contract.GroupAssignment{
		ID:    authUser.Permission.GroupID,
		Items: groups,
	}, nil
}
