package store

import (
	"cofeeteria/internal/app/model"
)

type UsersRepository interface {
	CreateUser(*model.User) error
	FincByEmail(string) (*model.User, error)
	CreateProduct(*model.Product) error
	FindByShtrix(int) (*model.Product, error)
	Exist(*model.Product) (bool, error)
	AddSany(*model.Product, int) (*model.Product, error)
	Ayyrmak(*model.Product, int, int) (*model.Product, error)
	GivStatic() (*model.Product, error)
}