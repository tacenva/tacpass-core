package errormessage

import "errors"

var (
	ErrNotFound   = errors.New("not found")
	ErrEmptyField = errors.New("field cannot be empty")
)
