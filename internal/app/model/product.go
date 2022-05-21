package model

import (
	validation "github.com/go-ozzo/ozzo-validation"
)

type Product struct {
	ID         int     `json:"id"`
	Name       string  `json:"name"`
	Cost       float32 `json:"cost"`
	AlynanBaha float32 `json:"alynanbaha"`
	Sany       int     `json:"sany"`
	ShtrixCode int     `json:"shtrixcode"`
}

type Product2 struct {
	ID          int     `json:"id"`
	Satylansany float32 `json:"satylansany"`
	Totalcost   float32 `json:"totalcost"`
}

type Product3 struct {
	Total float64 `json:"total"`
}

func (p *Product) ValidateProduct() error {

	return validation.ValidateStruct(
		p,
		validation.Field(&p.Name, validation.Required),
		validation.Field(&p.Cost, validation.Required),
		validation.Field(&p.Sany, validation.Required),
		validation.Field(&p.ShtrixCode, validation.Required),
	)
}
