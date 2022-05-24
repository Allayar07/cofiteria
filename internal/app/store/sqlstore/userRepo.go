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

	if err := u.ValidateUser(); err != nil {
		return err
	}

	if err := u.BeforeCreated(); err != nil {
		return err
	}

	return req.store.Db.QueryRow(
		`INSERT INTO users (
			name,
			email,
			encryptedpassword,
			role,
			photo,
			wezipe,
			qrcode) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
		u.Name,
		u.Email,
		u.EncryptedPassword,
		u.Role,
		u.Photo,
		u.Wezipe,
		u.Qrcode,
	).Scan(&u.ID)
}

func (req *UserRepository) FindByEmail(email string) (*model.User, error) {
	u := &model.User{}

	err := req.store.Db.QueryRow(
		`SELECT
		id,
		photo,
		name,
		wezipe,
		email,
		qrcode,
		role,
		encryptedpassword FROM users WHERE email = $1`, email).Scan(
		&u.ID,
		&u.Photo,
		&u.Name,
		&u.Wezipe,
		&u.Email,
		&u.Qrcode,
		&u.Role,
		&u.EncryptedPassword,
	)

	if err != nil {

		if err == sql.ErrNoRows {
			return nil, store.ErrorNotFoundRecord
		}

		return nil, err
	}

	return u, nil
}

func (req *UserRepository) UpdateUser(name, wezipe, photo, qrcode, role string, id int) (*model.User, error) {

	u := &model.User{}

	str := `UPDATE users SET
	photo = $1,
	name = $2,
	wezipe = $3,
	qrcode = $4,
	role = $5 WHERE id = $6 RETURNING *`

	err := req.store.Db.QueryRow(str, photo, name, wezipe, qrcode, role, id).Scan(
		&u.ID,
		&u.Photo,
		&u.Name,
		&u.Wezipe,
		&u.Email,
		&u.EncryptedPassword,
		&u.Qrcode,
		&u.Role,
	)

	if err != nil {

		if err == sql.ErrNoRows {
			return nil, store.ErrorNotFoundRecord
		}

		return nil, err
	}

	return u, nil
}

func (req *UserRepository) DeletUser(id int) error {

	u := &model.User{}

	err := req.store.Db.QueryRow("DELETE FROM users WHERE id=$1 returning *", id).Scan(
		&u.ID,
		&u.Photo,
		&u.Name,
		&u.Wezipe,
		&u.Email,
		&u.EncryptedPassword,
		&u.Qrcode,
		&u.Role,
	)

	if err != nil {

		if err == sql.ErrNoRows {
			return store.ErrorNotFoundRecord
		}

		return err
	}

	return nil

}

func (req *UserRepository) GetAllusers() (*sql.Rows, error) {

	rows, err := req.store.Db.Query("Select * from users")
	if err != nil {

		if err == sql.ErrNoRows {
			return nil, store.ErrorNotFoundRecord
		}

		return nil, err
	}

	return rows, nil
}

func (req *UserRepository) CreateProduct(p *model.Product) error {

	if err := p.ValidateProduct(); err != nil {
		return err
	}

	return req.store.Db.QueryRow(
		`INSERT INTO product (
			name,
			cost,
			alynanbaha,
			sany,
			shtrixcode
			) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
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
		return nil, store.ErrorNotFoundRecord
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

func (req *UserRepository) Ayyrmak(p *model.Product, sany float32) (*model.Product, error) {

	_, errr := req.store.Db.Query(`
	update statistic set 
	satylansany = $1 + satylansany,
	totalcost= $1*$2 + totalcost where id = 1`,
		sany,
		p.Cost,
	)

	if errr != nil {
		return nil, errr
	}
	err := req.store.Db.QueryRow(
		"update product set sany=sany - $1 where shtrixcode = $2 returning *",
		sany,
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

		if err == sql.ErrNoRows {
			return false, nil
		}
	}

	return true, nil
}

func (req *UserRepository) UpdateProduct(p *model.Product, name string, sany, cost, alynanbaha float32) (*model.Product, error) {

	str := `UPDATE product SET
	name = $1,
	cost = $2,
	alynanbaha = $3,
	sany = $4 WHERE shtrixcode = $5 RETURNING *`

	err := req.store.Db.QueryRow(str, name, cost, alynanbaha, sany, p.ShtrixCode).Scan(
		&p.ID,
		&p.Name,
		&p.Cost,
		&p.AlynanBaha,
		&p.Sany,
		&p.ShtrixCode,
	)
	if err != nil {

		if err == sql.ErrNoRows {
			return nil, store.ErrorNotFoundRecord
		}

		return nil, err
	}

	return p, nil
}

func (req *UserRepository) DeletProduct(id int) (*model.Product, error) {

	p := &model.Product{}

	err := req.store.Db.QueryRow("DELETE FROM product WHERE id=$1 returning *", id).Scan(
		&p.ID,
		&p.Name,
		&p.Cost,
		&p.AlynanBaha,
		&p.Sany,
		&p.ShtrixCode,
	)
	if err != nil {

		if err == sql.ErrNoRows {
			return nil, store.ErrorNotFoundRecord
		}

		return nil, err
	}

	return p, nil

}

func (req *UserRepository) GetAllProduct() (*sql.Rows, error) {

	rows, err := req.store.Db.Query("Select * from product")

	if err != nil {

		if err == sql.ErrNoRows {
			return nil, store.ErrorNotFoundRecord
		}

		return nil, err
	}

	return rows, nil
}

func (req *UserRepository) GivStatic() (*model.Product2, error) {

	p := &model.Product2{}

	err := req.store.Db.QueryRow("SELECT * from statistic").Scan(
		&p.ID,
		&p.Satylansany,
		&p.Totalcost,
	)

	if err != nil {
		return nil, store.ErrorNotFoundRecord
	}

	return p, nil

}
