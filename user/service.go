package user

import (
	"errors"
	"strings"

	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/util/credential"
)

var (
	ErrNotFound      = errors.New("user not found")
	ErrHostnameEmpty = errors.New("user hostname cannot be empty")
	ErrTokenEmpty    = errors.New("token cannot be empty")
	ErrStatusInvalid = errors.New("invalid user status")
	ErrPending       = errors.New("user is not approved")
	ErrRevoked       = errors.New("user is revoked")
)

const tokenSize = 32

type Service struct {
	repository *repository
}

func NewService(repository *repository) *Service {
	return &Service{
		repository: repository,
	}
}

func (s *Service) Create(
	hostname string,
	permissionID string,
	userStatus entity.UserStatus,
) (*entity.User, string, error) {
	hostname = strings.TrimSpace(hostname)
	permissionID = strings.TrimSpace(permissionID)

	if hostname == "" {
		return nil, "", ErrHostnameEmpty
	}

	token, err := credential.Generate(tokenSize)
	if err != nil {
		return nil, "", err
	}

	user := &entity.User{
		PermissionID: permissionID,
		Hostname:     hostname,
		Token:        credential.Hash(token),
		Status:       userStatus,
	}

	if err := s.repository.Create(user); err != nil {
		return nil, "", err
	}

	return user, token, nil
}

func (s *Service) Get(id string) (*entity.User, error) {
	id = strings.TrimSpace(id)

	if id == "" {
		return nil, ErrNotFound
	}

	user, err := s.repository.FindByID(id)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, ErrNotFound
	}

	return user, nil
}

func (s *Service) GetByToken(token string) (*entity.User, error) {
	token = strings.TrimSpace(token)

	if token == "" {
		return nil, ErrTokenEmpty
	}

	tokenHash := credential.Hash(token)

	user, err := s.repository.FindByToken(tokenHash)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, ErrNotFound
	}

	switch user.Status {
	case entity.UserStatusPending:
		return nil, ErrPending

	case entity.UserStatusRevoked:
		return nil, ErrRevoked

	case entity.UserStatusApproved:
		return user, nil

	default:
		return nil, ErrStatusInvalid
	}
}

func (s *Service) List() ([]entity.User, error) {
	return s.repository.FindAll()
}

// func (s *Service) Approve(id string) error {
// 	id = strings.TrimSpace(id)

// 	if id == "" {
// 		return ErrNotFound
// 	}

// 	user, err := s.repository.FindByID(id)
// 	if err != nil {
// 		return err
// 	}

// 	if user == nil {
// 		return ErrNotFound
// 	}

// 	if user.Status == entity.UserStatusRevoked {
// 		return ErrRevoked
// 	}

// 	if user.Status == entity.UserStatusApproved {
// 		return nil
// 	}

// 	user.Status = entity.UserStatusApproved

// 	return s.repository.Update(user)
// }

// func (s *Service) Revoke(id string) error {
// 	id = strings.TrimSpace(id)

// 	if id == "" {
// 		return ErrNotFound
// 	}

// 	user, err := s.repository.FindByID(id)
// 	if err != nil {
// 		return err
// 	}

// 	if user == nil {
// 		return ErrNotFound
// 	}

// 	if user.Status == entity.UserStatusRevoked {
// 		return nil
// 	}

// 	user.Status = entity.UserStatusRevoked

// 	return s.repository.Update(user)
// }

func (s *Service) Update(
	id string,
	hostname string,
) (*entity.User, error) {
	id = strings.TrimSpace(id)
	hostname = strings.TrimSpace(hostname)

	if id == "" {
		return nil, ErrNotFound
	}

	if hostname == "" {
		return nil, ErrHostnameEmpty
	}

	user, err := s.repository.FindByID(id)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, ErrNotFound
	}

	user.Hostname = hostname

	if err := s.repository.Update(user); err != nil {
		return nil, err
	}

	return user, nil
}

func (s *Service) UpdateStatus(
	id string,
	status entity.UserStatus,
) (*entity.User, error) {
	id = strings.TrimSpace(id)

	if id == "" {
		return nil, ErrNotFound
	}

	switch status {
	case entity.UserStatusPending,
		entity.UserStatusApproved,
		entity.UserStatusRevoked:
		// valid

	default:
		return nil, ErrStatusInvalid
	}

	user, err := s.repository.FindByID(id)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, ErrNotFound
	}

	user.Status = status

	if err := s.repository.Update(user); err != nil {
		return nil, err
	}

	return user, nil
}

func (s *Service) Delete(id string) error {
	id = strings.TrimSpace(id)

	if id == "" {
		return ErrNotFound
	}

	user, err := s.repository.FindByID(id)
	if err != nil {
		return err
	}

	if user == nil {
		return ErrNotFound
	}

	return s.repository.Delete(id)
}
