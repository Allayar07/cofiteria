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
	atClaims["admin"] = u.IsAdmin
	atClaims["access_uuid"] = td.AccessUuid
	atClaims["isSeller"] = u.IsSeller
	atClaims["accountantt"] = u.Accountantt
	atClaims["user_id"] = u.Email
	atClaims["exp"] = td.AtExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return nil, err
	}
	//Creating Refresh Token
	os.Setenv("REFRESH_SECRET", "mcmvmkmsdnfsdmfdsjf")
	rtClaims := jwt.MapClaims{}
	rtClaims["admin"] = u.IsAdmin
	rtClaims["isSeller"] = u.IsSeller
	rtClaims["accountantt"] = u.Accountantt
	rtClaims["user_id"] = u.Email
	rtClaims["refresh_uuid"] = td.RefreshUuid
	rtClaims["exp"] = td.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
	if err != nil {
		return nil, err
	}
	return td, nil
}

