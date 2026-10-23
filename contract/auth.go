package contract

import "github.com/tacenva/tacpass-core/entity"

type EnrollRequest struct {
	Hostname  string `json:"hostname"`
	PublicKey string `json:"public_key"`
}

type EnrollResponse struct {
	SoTHostname     string            `json:"sot_hostname"`
	Status          entity.UserStatus `json:"status"`
	Privilege       entity.Privilege  `json:"privilege"`
	AuthToken       string            `json:"auth_token"`
	GroupAssignment *GroupAssignment  `json:"group_assignment,omitempty"`
}

type GroupAssignment struct {
	ID    string                   `json:"group_id,omitempty"`
	Items []entity.PermissionGroup `json:"items,omitempty"`
}

type AuthData struct {
	Status    entity.UserStatus `json:"status"`
	Privilege entity.Privilege  `json:"privilege"`

	GroupAssignment *GroupAssignment `json:"group_assignment,omitempty"`
}
