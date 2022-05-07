package sqlstore

import (
	"cofeeteria/internal/app/model"
	"database/sql"
)

type UserRepository struct {
	store *SqlStore
}

func (req *UserRepository) CreateUser(u *model.User) error {

	if err := u.BeforeCreated(); err != nil {
		return err
	}

	return req.store.Db.QueryRow(
		"INSERT INTO users (name, email, encryptedPassword) VALUES ($1,$2,$3) RETURNING id",
		u.Name,
		u.Email,
		u.EncryptedPassword,
	).Scan(&u.ID)
}

func (req *UserRepository) CreateProduct(p *model.Product) error {

	return req.store.Db.QueryRow(
		"INSERT INTO product (name, cost, alynanbaha, sany, shtrixcode) VALUES ($1,$2,$3,$4,$5) RETURNING id",
		p.Name,
		p.Cost,
		p.AlynanBaha,
		p.Sany,
		p.ShtrixCode,
	).Scan(&p.ID)
}

func (req *UserRepository) FindByShtrix(num int) (*model.Product, error) {

	p := &model.Product{}

	err := req.store.Db.QueryRow(
		"SELECT id, name, cost, alynanbaha, sany, shtrixcode FROM product WHERE shtrixcode = $1",
		num,
	).Scan(
		&p.ID,
		&p.Name,
		&p.Cost,
		&p.AlynanBaha,
		&p.Sany,
		&p.ShtrixCode,
	)
	if err != nil {
		return nil, err
	}

	return p, nil

}

func (req *UserRepository) AddSany(p *model.Product, num int) (*model.Product, error) {
	err := req.store.Db.QueryRow(
		"update  product set sany = sany + $1 where shtrixcode = $2 returning *",
		num,
		p.ShtrixCode,
	).Scan(
		&p.ID,
		&p.Name,
		&p.Cost,
		&p.AlynanBaha,
		&p.Sany,
		&p.ShtrixCode,
	)
	if err != nil {
		return nil, err
	}

	return p, nil
}

func (req *UserRepository) Ayyrmak(p *model.Product, num int) (*model.Product, error){
	err := req.store.Db.QueryRow(
		"update product set sany = sany - $1 where shtrixcode = $2 returning *",
		num,
		p.ShtrixCode,
	).Scan(
		&p.ID,
		&p.Name,
		&p.Cost,
		&p.AlynanBaha,
		&p.Sany,
		&p.ShtrixCode,
	)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (req *UserRepository) Exist(p *model.Product) (bool, error) {
	err := req.store.Db.QueryRow(
		"SELECT * from product where shtrixcode = $1", p.ShtrixCode,
	).Scan(
		&p.ID,
		&p.Name,
		&p.Cost,
		&p.AlynanBaha,
		&p.Sany,
		&p.ShtrixCode,
	)
	if err != nil {
		if err == sql.ErrNoRows{
			return false, nil
		}
	}

	return true, nil
}