package model

import validation "github.com/go-ozzo/ozzo-validation"

func RequiredIF(condition bool) validation.RuleFunc {

	return func(parametr interface{}) error {

		if condition {
			return validation.Validate(parametr, validation.Required)
		}
		return nil
	}

}

func ValidateAny(param interface{}) error {

	return validation.Validate(param, validation.Required)

}
