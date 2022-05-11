package apiserver

import (
	"cofeeteria/internal/app/model"
	"log"
	// "strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var Secretkey = []byte("mysecret")

func CreateToken(u *model.User) (string, error){
	
	claims := jwt.MapClaims{}
	claims["admin"] = u.IsAdmin
	claims["isSeller"] = u.IsSeller
	claims["accountantt"] = u.Accountantt
	claims["user_id"] = u.Email
	claims["exp"] = time.Now().Add(time.Hour*1).Unix()

	at := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := at.SignedString(Secretkey)
	if err != nil {
		log.Fatal(err)
	}

	return token, nil
}