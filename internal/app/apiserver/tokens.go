package apiserver

import (
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type TokenManager interface {
	NewJWT(shtrixcode int, ttl time.Duration) (string, error)
	Parse(accsessToken string) (string, error)
	NewRefreshToken() (string, error)
}

type Manager struct{
	secretkey string
}

func NewManager(secretkey string) (*Manager, error){
	if secretkey == "" {
		return &Manager{secretkey: secretkey}, nil
	}

	return nil, nil
}

func (m *Manager) NewJWT(shtrixcode int, ttl time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		ExpiresAt: time.Now().Add(ttl).Unix(),
		Subject: strconv.Itoa(shtrixcode) ,
	})

	return token.SignedString([]byte(m.secretkey))
}