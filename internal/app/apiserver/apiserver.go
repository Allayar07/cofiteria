package apiserver

import (
	"cofeeteria/internal/app/store/sqlstore"
	"database/sql"
	"net/http"

	_ "github.com/lib/pq"
)

func Start(param *Api) error {
	db, err := NewDB(param.DatabaseURL)
	if err != nil {
		return err
	}

	defer db.Close()

	store := sqlstore.NewDb(db)

	srv:= NewServer(store)

	return http.ListenAndServe(param.BindAdress, srv)
} 

func NewDB(database string) (*sql.DB, error) {
	db, err := sql.Open("postgres", database)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}