package store

import (
	"cofeeteria/internal/app/model"
	"database/sql"
)

type UsersRepository interface {
	CreateUser(*model.User) error
	FindByEmail(string) (*model.User, error)
	CreateProduct(*model.Product) error
	FindByShtrix(int) (*model.Product, error)
	Exist(*model.Product) (bool, error)
	AddSany(*model.Product, int) (*model.Product, error)
	Ayyrmak(*model.Product, float32) (*model.Product, error)
	GivStatic() (*model.Product2, error)
	UpdateProduct(*model.Product, string, float32, float32, float32) (*model.Product, error)
	UpdateUser(string, string, string, string, bool, bool, bool, int) (*model.User, error)
	DeletProduct(id int) (*model.Product, error)
	DeletUser(int) error
	GetAllProduct() (*sql.Rows, error)
	GetAllusers() (*sql.Rows, error)
}
