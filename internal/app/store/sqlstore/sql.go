package sqlstore

import (
	store "cofeeteria/internal/app/store"
	"database/sql"
	_ "github.com/lib/pq"
)

type SqlStore struct {
	Db *sql.DB
	userRepositori *UserRepository
}

func NewDb(db *sql.DB) *SqlStore {
	return &SqlStore{
		Db: db,
	}
}

func (s *SqlStore) Users() store.UsersRepository {
	if s.userRepositori != nil {
		return s.userRepositori
	}
	s.userRepositori = &UserRepository{
		store: s,
	}

	return s.userRepositori
}