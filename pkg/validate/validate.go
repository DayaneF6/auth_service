package validate

import (
	"fmt"

	"github.com/go-playground/validator/v10"
)

var v = validator.New()

func Struct(s any) error {
	if err := v.Struct(s); err != nil {
		return fmt.Errorf("%w: %s", ErrValidation, err.Error())
	}
	return nil
}

var ErrValidation = fmt.Errorf("validation failed")
