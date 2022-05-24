package apiserver

import (
	"cofeeteria/internal/app/model"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/twinj/uuid"
)

var Secretkey = []byte("mysecret")

type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	AccessUuid   string
	RefreshUuid  string
	AtExpires    int64
	RtExpires    int64
}

func CreateToken(u *model.User) (*TokenDetails, error) {

	td := &TokenDetails{}

	td.AtExpires = time.Now().Add(time.Minute * 15).Unix()
	td.AccessUuid = uuid.NewV4().String()

	td.RtExpires = time.Now().Add(time.Minute * 30).Unix()
	td.RefreshUuid = uuid.NewV4().String()

	var err error
	//Creating Access Token
	os.Setenv("ACCESS_SECRET", "jdnfksdmfksd")

	atClaims := jwt.MapClaims{}

	atClaims["role"] = u.Role
	atClaims["access_uuid"] = td.AccessUuid
	atClaims["user_id"] = u.ID
	atClaims["exp"] = td.AtExpires

	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)

	td.AccessToken, err = at.SignedString([]byte(Secretkey))
	if err != nil {

		return nil, err

	}
	//Creating Refresh Token
	os.Setenv("REFRESH_SECRET", "mcmvmkmsdnfsdmfdsjf")

	rtClaims := jwt.MapClaims{}

	rtClaims["role"] = u.Role
	rtClaims["user_id"] = u.ID
	rtClaims["refresh_uuid"] = td.RefreshUuid
	rtClaims["exp"] = td.RtExpires

	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)

	td.RefreshToken, err = rt.SignedString([]byte(Secretkey))
	if err != nil {

		return nil, err

	}

	return td, nil
}
