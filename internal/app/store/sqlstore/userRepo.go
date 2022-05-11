package sqlstore

import (
	"cofeeteria/internal/app/model"
	"cofeeteria/internal/app/store"
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
		"INSERT INTO users (name, email, encryptedPassword, isadmin, isseller, accountant) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id",
		u.Name,
		u.Email,
		u.EncryptedPassword,
		u.IsAdmin,
		u.IsSeller,
		u.Accountantt,
	).Scan(&u.ID)
}

func (req *UserRepository) FincByEmail(email string) (*model.User, error) {
	u := &model.User{}

	if err := req.store.Db.QueryRow(
		"SELECT id, name, email, encryptedPassword, isadmin, isseller, accountant FROM users WHERE email = $1",
		email).Scan(
		&u.ID,
		&u.Name,
		&u.Email,
		&u.EncryptedPassword,
		&u.IsAdmin,
		&u.IsSeller,
		&u.Accountantt,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, store.ErrorNotFoundRecord
		}
		return nil, err
	}

	return u, nil
}

func (req *UserRepository) UpdateUser(name, wezipe, photo string, id int) (*model.User, error) {
	u := &model.User{}

	str := `UPDATE users SET name = $1, wezipe = $2, photo = $3 WHERE id = $4 RETURNING *`
	err := req.store.Db.QueryRow(str, name, wezipe, photo, id).Scan(
		&u.ID,
		&u.Name,
		&u.Email,
		&u.EncryptedPassword,
		&u.IsAdmin,
		&u.IsSeller,
		&u.Accountantt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, store.ErrorNotFoundRecord
		}
		return nil, err
	}

	return u, nil
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
		&p.Satylansany,
		&p.Totalcost,
		
	)
	if err != nil {
		return nil, err
	}

	return p, nil
}

func (req *UserRepository) Ayyrmak(p *model.Product, sany, cost int) (*model.Product, error){
	err := req.store.Db.QueryRow(
		"update product set sany = sany - $1, satylansany = $1 + satylansany, totalcost = $1*$2 + totalcost where shtrixcode = $3 returning *",
		sany,
		cost,
		p.ShtrixCode,
	).Scan(
		&p.ID,
		&p.Name,
		&p.Cost,
		&p.AlynanBaha,
		&p.Sany,
		&p.ShtrixCode,
		&p.Satylansany,
		&p.Totalcost,
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
		&p.Satylansany,
		&p.Totalcost,
	)
	if err != nil {
		if err == sql.ErrNoRows{
			return false, nil
		}
	}

	return true, nil
}

func (req *UserRepository) UpdateProduct(name string, id, cost, alynanbaha, sany int) (*model.Product, error) {
	p := &model.Product{}

	str := `UPDATE product SET name = $1, cost = $2, alynanbaha = $3, sany = $4 WHERE id = $5 RETURNING *`
	err := req.store.Db.QueryRow(str, name, cost, alynanbaha, sany, id).Scan(
		&p.ID,
		&p.Name,
		&p.Cost,
		&p.AlynanBaha,
		&p.Sany,
		&p.ShtrixCode,
		&p.Satylansany,
		&p.Totalcost,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, store.ErrorNotFoundRecord
		}
		return nil, err
	}

	return p, nil
}

func (req *UserRepository) GivStatic() (*model.Product, error) {

	p := &model.Product{}

	err := req.store.Db.QueryRow("SELECT * from product").Scan(
		&p.ID,
		&p.Name,
		&p.Cost,
		&p.AlynanBaha,
		&p.Sany,
		&p.ShtrixCode,
		&p.Satylansany,
		&p.Totalcost,
	)

	if err != nil {
		return nil, err
	}

	return p, nil

}