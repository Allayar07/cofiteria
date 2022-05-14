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
		&u.Photo,
		&u.Wezipe,
		&u.Surname,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, store.ErrorNotFoundRecord
		}
		return nil, err
	}

	return u, nil
}

func (req *UserRepository) DeletUser(id int)  error {

	_, err := req.store.Db.Query("DELETE FROM users WHERE id=$1 returning *", id)

	if err != nil {
		if err == sql.ErrNoRows {
			return store.ErrorNotFoundRecord
		}
		return err
	}

	return  nil

}

func (req *UserRepository) CreateProduct(p *model.Product) error {

	return req.store.Db.QueryRow(
		"INSERT INTO product (name, cost, alynanbaha, sany, shtrixcode, satylansany, totalcost) VALUES ($1,$2,$3,$4,$5,0,0) RETURNING id",
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

func (req *UserRepository) Ayyrmak(p *model.Product, sany float32) (*model.Product, error) {

	_, errr := req.store.Db.Query("update statistic set satylansany = $1 + satylansany, totalcost= $1*$2 + totalcost where id = 1", sany, p.Cost)
	if errr != nil {
		return nil, errr
	}
	err := req.store.Db.QueryRow(
		"update product set sany=sany - $1, satylansany=$1 + satylansany, totalcost=$1*$2 + totalcost where shtrixcode = $3 returning *",
		sany,
		p.Cost,
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
		if err == sql.ErrNoRows {
			return false, nil
		}
	}

	return true, nil
}

func (req *UserRepository) UpdateProduct(p *model.Product, name string, sany, cost, alynanbaha float32) (*model.Product, error) {

	str := `UPDATE product SET name = $1, cost = $2, alynanbaha = $3, sany = $4 WHERE shtrixcode = $5 RETURNING *`
	err := req.store.Db.QueryRow(str, name, cost, alynanbaha, sany, p.ShtrixCode).Scan(
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

func (req *UserRepository) DeletProduct(id int) (*model.Product, error) {
	p := &model.Product{}

	err := req.store.Db.QueryRow("DELETE FROM product WHERE id=$1 returning *", id).Scan(
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

func (req *UserRepository) GivStatic() (*model.Product2, error) {

	p := &model.Product2{}

	err := req.store.Db.QueryRow("SELECT * from statistic").Scan(
		&p.ID,
		&p.Satylansany,
		&p.Totalcost,
	)

	if err != nil {
		return nil, err
	}

	return p, nil

}
