package store

type Store interface {
	Users() UsersRepository
}