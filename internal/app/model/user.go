package model

import (
	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID                int    `json:"id"`
	Photo             string `json:"photo"`
	Name              string `json:"name"`
	Wezipe            string `json:"wezipe"`
	Email             string `json:"email"`
	Password          string `json:"password,omitempty"`
	EncryptedPassword string `json:"-"`
	Qrcode            string `json:"qrcode"`
	IsAdmin           bool   `json:"isadmin"`
	IsSeller          bool   `json:"isseller"`
	Accountantt       bool   `json:"accountantt"`
}

func (u *User) BeforeCreated() error {

	if len(u.Password) > 0 {
		encrypt, err := Encryptestring(u.Password)
		if err != nil {
			return err
		}
		u.EncryptedPassword = encrypt

	}

	return nil
}

func (u *User) Parolgizle() {

	u.Password = ""

}

func (u *User) ComparePassWord(password string) bool {

	return bcrypt.CompareHashAndPassword([]byte(u.EncryptedPassword), []byte(password)) == nil

}

func Encryptestring(str string) (string, error) {

	b, err := bcrypt.GenerateFromPassword([]byte(str), bcrypt.MinCost)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func (u *User) ValidateUser() error {

	return validation.ValidateStruct(
		u,
		validation.Field(
			&u.Email,
			validation.Required,
			is.Email),
		validation.Field(
			&u.Password,
			validation.By(RequiredIF(u.EncryptedPassword == "")),
			validation.Length(5, 10)),
	)
}
