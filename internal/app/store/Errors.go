package store

import "errors"

type ctxKEY int8

var (
	ErrorNotFoundRecord = errors.New("Record not found")
	ErrorNotAuthenticate = errors.New("Not Authenticate!!!")
)

const (
	CntKey ctxKEY = iota
)