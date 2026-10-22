package auth

import (
	"os"

	"github.com/tacenva/tacpass-core/contract"
	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/internal/permission"
	"github.com/tacenva/tacpass-core/internal/user"
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
	}

	if userStatus == entity.UserStatusApproved {
		groups, err := s.permissionService.GetGroupDescendants(user.Permission.GroupID)
		if err != nil {
			return nil, err
		}
		response.GroupAssignment = contract.GroupAssignment{
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
