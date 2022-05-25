package apiserver

import (
	"cofeeteria/internal/app/middlwear"
	"cofeeteria/internal/app/model"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	store "cofeeteria/internal/app/store"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/twinj/uuid"
)

type Server struct {
	router *mux.Router
	logger *logrus.Logger
	store  store.Store
}

func NewServer(str store.Store) *Server {
	s := &Server{
		router: mux.NewRouter(),
		logger: logrus.New(),
		store:  str,
	}

	s.SettingRouter()

	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *Server) SettingRouter() {

	/*  Users  */

	s.router.Use(s.LogRequest)
	s.router.HandleFunc("/register", middlwear.MultipleMiddleware(
		s.Registirate(),
		s.Authentication,
		s.adminMiddlwear,
	)).Methods("POST")

	s.router.HandleFunc("/updateuser", middlwear.MultipleMiddleware(
		s.UpdateUsers(),
		s.Authentication,
		s.adminMiddlwear)).Methods("POST")

	s.router.HandleFunc("/deletuser", middlwear.MultipleMiddleware(
		s.DeleteUsers(),
		s.Authentication,
		s.adminMiddlwear)).Methods("POST")

	s.router.HandleFunc("/getallusers", middlwear.MultipleMiddleware(
		s.GetAll_Users(),
		s.Authentication,
		s.adminMiddlwear)).Methods("GET")

	s.router.HandleFunc("/login", s.Login()).Methods("POST")

	s.router.HandleFunc("/gettoken", middlwear.MultipleMiddleware(
		s.GetNewAccess(),
		s.RF_Authentication)).Methods("GET")

	/*  Products  */

	s.router.HandleFunc("/addproduct", middlwear.MultipleMiddleware(
		s.AddProduct(),
		s.Authentication,
		s.adminMiddlwear)).Methods("POST")

	s.router.HandleFunc("/sellproduct", middlwear.MultipleMiddleware(
		s.SellProduct(),
		s.Authentication,
		s.sellerMiddlwear,
	)).Methods("POST")

	s.router.HandleFunc("/updateproduct", middlwear.MultipleMiddleware(
		s.UpdateProducts(),
		s.Authentication,
		s.adminMiddlwear)).Methods("POST")

	s.router.HandleFunc("/deletproduct", middlwear.MultipleMiddleware(
		s.DeletProduct(),
		s.Authentication,
		s.adminMiddlwear)).Methods("POST")

	s.router.HandleFunc("/getallprduct", middlwear.MultipleMiddleware(
		s.GetAll_Products(),
		s.accountanttMiddlwear)).Methods("GET")

	s.router.HandleFunc("/static", s.Statics())
}

/*   Handler Functions   */

func (s *Server) Registirate() http.HandlerFunc {

	type Request struct {
		Photo    string `json:"photo"`
		Name     string `json:"name"`
		Wezipe   string `json:"wezipe"`
		Email    string `json:"email"`
		Password string `json:"password,omitempty"`
		Qrcode   string `json:"qrcode"`
		Role     string `json:"role"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		req := &Request{}

		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		err := model.ValidateAny(req.Photo)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("photo can not be blank"))
			return
		}

		err = model.ValidateAny(req.Name)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("name can not be blank"))
			return
		}

		err = model.ValidateAny(req.Wezipe)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("wezipe can not be blank"))
			return
		}

		err = model.ValidateAny(req.Email)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("email can not be blank"))
			return
		}

		err = model.ValidateAny(req.Password)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("password can not be blank"))
			return
		}

		err = model.ValidateAny(req.Qrcode)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("qrcode can not be blank"))
			return
		}

		err = model.ValidateAny(req.Role)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("role can not be blank"))
			return
		}

		u := &model.User{
			Name:     req.Name,
			Email:    req.Email,
			Password: req.Password,
			Role:     req.Role,
			Photo:    req.Photo,
			Qrcode:   req.Qrcode,
			Wezipe:   req.Wezipe,
		}

		if err := s.store.Users().CreateUser(u); err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}

		u.Parolgizle()

		type Result struct {
			Data       interface{} `json:"data"`
			Code       int         `json:"code"`
			StatusText string      `json:"status_text"`
		}

		var result Result

		result.Data = u
		result.Code = http.StatusCreated
		result.StatusText = http.StatusText(http.StatusCreated)

		_ = json.NewEncoder(w).Encode(result)
	}
}

func (s *Server) GetByID() http.HandlerFunc {
	type Request struct {
		ID float64 `json:"id"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		req := &Request{}

		err := json.NewDecoder(r.Body).Decode(req)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		u, err := s.store.Users().FindByID(req.ID)
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		type Result struct {
			Data       interface{} `json:"data"`
			Code       int         `json:"code"`
			StatusText string      `json:"status_text"`
		}

		var result Result

		result.Data = u
		result.Code = http.StatusOK
		result.StatusText = http.StatusText(http.StatusOK)

		_ = json.NewEncoder(w).Encode(result)
		// s.Respond(w, r, http.StatusOK, u)
	}
}

func (s *Server) Login() http.HandlerFunc {

	type Request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		req := &Request{}

		if err := json.NewDecoder(r.Body).Decode(req); err != nil {

			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		err := model.ValidateAny(req.Email)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("email can not be blank"))
			return
		}

		err = model.ValidateAny(req.Password)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("password can not be blank"))
			return
		}

		u, err := s.store.Users().FindByEmail(req.Email)
		if err != nil || !u.ComparePassWord(req.Password) {
			s.error(w, r, http.StatusBadRequest, store.ErrorEmailorPasswd)
			return
		}

		token, err := CreateToken(u)
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		Cookie1 := http.Cookie{
			Name:     "ACCessCFT_Token",
			Value:    token.AccessToken,
			HttpOnly: true,
		}

		http.SetCookie(w, &Cookie1)

		Cookie2 := http.Cookie{
			Name:     "RfrCFT_Token",
			Value:    token.RefreshToken,
			HttpOnly: true,
		}

		http.SetCookie(w, &Cookie2)

		type Result struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			StatusText   string `json:"status_text"`
			StatusCode   int    `json:"status_code"`
		}
		var result Result

		result.AccessToken = token.AccessToken
		result.RefreshToken = token.RefreshToken
		result.StatusCode = http.StatusOK
		result.StatusText = http.StatusText(http.StatusOK)

		_ = json.NewEncoder(w).Encode(result)

	}
}

func (s *Server) RF_Authentication(next http.HandlerFunc) http.HandlerFunc {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		c, err := r.Cookie("RfrCFT_Token")
		if err != nil {
			if err == http.ErrNoCookie {
				s.error(w, r, http.StatusUnauthorized, err)
				return
			}
			s.error(w, r, http.StatusUnauthorized, err)
			return
		}
		cookie := c.Value

		rtclaims := jwt.MapClaims{}

		token, err := jwt.ParseWithClaims(
			cookie,
			rtclaims,
			func(t *jwt.Token) (interface{}, error) {

				return []byte(Secretkey), nil

			})

		if err != nil {
			s.error(w, r, http.StatusUnauthorized, err)
			return
		}

		if !token.Valid {
			s.error(w, r, http.StatusUnauthorized, err)
			return
		}

		next.ServeHTTP(w, r)

	})
}

func (s *Server) Authentication(next http.HandlerFunc) http.HandlerFunc {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		c1, err := r.Cookie("ACCessCFT_Token")
		if err != nil {
			if err == http.ErrNoCookie {
				s.error(w, r, http.StatusUnauthorized, err)
				return
			}
			s.error(w, r, http.StatusUnauthorized, err)
			return
		}

		cookie1 := c1.Value

		atclaims := jwt.MapClaims{}

		token1, err := jwt.ParseWithClaims(
			cookie1,
			atclaims,
			func(t *jwt.Token) (interface{}, error) {

				return []byte(Secretkey), nil

			})

		if err != nil {
			s.error(w, r, http.StatusUnauthorized, err)
			return
		}

		if !token1.Valid {
			s.error(w, r, http.StatusUnauthorized, err)
			return
		}

		next.ServeHTTP(w, r)

	})
}

func (s *Server) GetNewAccess() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		c, err := r.Cookie("RfrCFT_Token")
		if err != nil {

			if err == http.ErrNoCookie {

				s.error(w, r, http.StatusUnauthorized, err)
				return
			}

			s.error(w, r, http.StatusUnauthorized, err)
			return
		}

		cookie := c.Value

		rtclaims := jwt.MapClaims{}

		token, err := jwt.ParseWithClaims(
			cookie,
			rtclaims,
			func(t *jwt.Token) (interface{}, error) {

				return []byte(Secretkey), nil

			})

		if !token.Valid {
			s.error(w, r, http.StatusUnauthorized, errors.New("token is not valid !!!!!"))
			return
		}

		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		id := rtclaims["user_id"].(float64)

		u, err := s.store.Users().FindByID(id)
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}
		td := &TokenDetails{}

		td.AtExpires = time.Now().Add(time.Minute * 15).Unix()
		td.AccessUuid = uuid.NewV4().String()

		atClaims := jwt.MapClaims{}

		atClaims["role"] = u.Role
		atClaims["access_uuid"] = td.AccessUuid
		atClaims["user_id"] = u.ID
		atClaims["exp"] = td.AtExpires

		at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)

		td.AccessToken, err = at.SignedString([]byte(Secretkey))
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		Cookie1 := http.Cookie{
			Name:     "ACCessCFT_Token",
			Value:    td.AccessToken,
			HttpOnly: true,
		}

		http.SetCookie(w, &Cookie1)

		r.Header.Set("ACCessCFT_Token", td.AccessToken)
		type Result struct {
			AccessToken string `json:"access_token"`
			StatusText  string `json:"status_text"`
			StatusCode  int    `json:"status_code"`
		}
		var result Result
		result.StatusCode = http.StatusOK
		result.StatusText = http.StatusText(http.StatusOK)
		result.AccessToken = td.AccessToken
		_ = json.NewEncoder(w).Encode(result)

	}

}

func (s *Server) DeleteUsers() http.HandlerFunc {

	type Request struct {
		ID int `json:"id"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		req := &Request{}

		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		err := model.ValidateAny(req.ID)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("id can not be blank"))
			return
		}

		err = s.store.Users().DeletUser(req.ID)
		if err != nil {
			s.error(w, r, http.StatusNotFound, err)
			return
		}

		type Result struct {
			Code       int    `json:"code"`
			StatusText string `json:"status_text"`
		}

		var result Result

		result.Code = http.StatusOK
		result.StatusText = http.StatusText(http.StatusOK)

		_ = json.NewEncoder(w).Encode(result)

	}
}

func (s *Server) adminMiddlwear(next http.HandlerFunc) http.HandlerFunc {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		c, err := r.Cookie("ACCessCFT_Token")
		if err != nil {

			if err == http.ErrNoCookie {

				s.error(w, r, http.StatusUnauthorized, err)
				return
			}

			s.error(w, r, http.StatusUnauthorized, err)
			return
		}

		cookie := c.Value

		atClaims := jwt.MapClaims{}

		token, err := jwt.ParseWithClaims(
			cookie,
			atClaims,
			func(t *jwt.Token) (interface{}, error) {

				return Secretkey, nil

			})

		if err != nil {
			s.error(w, r, http.StatusUnauthorized, err)
			return
		}

		if !token.Valid {
			s.error(w, r, http.StatusUnauthorized, errors.New("token is not valid !!!!!"))
			return
		}

		if atClaims["role"].(string) != "admin" {
			s.error(w, r, http.StatusForbidden, errors.New("bu sahypa dosdubynyz yok"))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) sellerMiddlwear(next http.HandlerFunc) http.HandlerFunc {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// c, err := r.Cookie("ACCessCFT_Token")
		// if err != nil {
		// 	if err == http.ErrNoCookie {
		// 		s.error(w, r, http.StatusUnauthorized, err)
		// 		return
		// 	}
		// 	s.error(w, r, http.StatusUnauthorized, err)
		// 	return
		// }

		// cookie := c.Value

		a := r.Header.Get("Authorization")

		cookie := a

		atClaims := jwt.MapClaims{}

		token, err := jwt.ParseWithClaims(
			cookie,
			atClaims,
			func(t *jwt.Token) (interface{}, error) {

				return Secretkey, nil

			})

		if err != nil {
			s.error(w, r, http.StatusUnauthorized, err)
			return
		}

		if !token.Valid {
			s.error(w, r, http.StatusUnauthorized, errors.New("token is not valid !!!!!"))
			return
		}

		if atClaims["role"].(string) == "satyjy" || atClaims["role"].(string) == "admin" {

			next.ServeHTTP(w, r)

		} else {
			s.error(w, r, http.StatusForbidden, errors.New("bu sahypa dosdubynyz yok bu statyjy ucn"))
			return
		}
	})
}

func (s *Server) accountanttMiddlwear(next http.HandlerFunc) http.HandlerFunc {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		c, err := r.Cookie("ACCessCFT_Token")
		if err != nil {
			if err == http.ErrNoCookie {
				s.error(w, r, http.StatusUnauthorized, err)
				return
			}
			s.error(w, r, http.StatusUnauthorized, err)
			return
		}

		cookie := c.Value

		claims := jwt.MapClaims{}

		token, err := jwt.ParseWithClaims(
			cookie,
			claims,
			func(t *jwt.Token) (interface{}, error) {

				return Secretkey, nil

			})

		if err != nil {
			s.error(w, r, http.StatusUnauthorized, err)
			return
		}

		if !token.Valid {
			s.error(w, r, http.StatusUnauthorized, errors.New("token is not valid !!!!!"))
			return
		}

		if claims["role"].(string) == "hasapcy" || claims["role"].(string) == "admin" {

			next.ServeHTTP(w, r)

		} else {

			s.error(w, r, http.StatusForbidden, errors.New("bu sahypa dosdubynyz yok bu buhgalter ucn"))
			return

		}

	})
}

func (s *Server) AddProduct() http.HandlerFunc {

	type Request struct {
		Name       string  `json:"name"`
		Cost       float32 `json:"cost"`
		AlynanBaha float32 `json:"alynanbaha"`
		Sany       int     `json:"sany"`
		ShtrixCode int     `json:"shtrixcode"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		req := &Request{}

		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		err := model.ValidateAny(req.Name)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("name can not be blank"))
			return
		}

		err = model.ValidateAny(req.Cost)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("cost can not be blank"))
			return
		}

		err = model.ValidateAny(req.AlynanBaha)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("alynanbaha can not be blank"))
			return
		}

		err = model.ValidateAny(req.Sany)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("sany can not be blank"))
			return
		}

		err = model.ValidateAny(req.ShtrixCode)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("shtrixCode can not be blank"))
			return
		}

		p := &model.Product{
			Name:       req.Name,
			Cost:       req.Cost,
			AlynanBaha: req.AlynanBaha,
			Sany:       req.Sany,
			ShtrixCode: req.ShtrixCode,
		}

		bul, err := s.store.Users().Exist(p)
		if err != nil {
			s.error(w, r, http.StatusNotFound, err)
			return
		}

		if bul == false {
			err := s.store.Users().CreateProduct(p)
			if err != nil {
				s.error(w, r, http.StatusUnprocessableEntity, err)
				return
			}

			type Result struct {
				Data       interface{} `json:"data"`
				Code       int         `json:"code"`
				StatusText string      `json:"status_text"`
			}

			var result Result

			result.Data = p
			result.Code = http.StatusCreated
			result.StatusText = http.StatusText(http.StatusCreated)

			_ = json.NewEncoder(w).Encode(result)
			// s.Respond(w, r, http.StatusCreated, p)

		} else {

			prod, err := s.store.Users().FindByShtrix(p.ShtrixCode)
			if err != nil {
				s.error(w, r, http.StatusNotFound, err)
				return
			}

			product, err := s.store.Users().AddSany(prod, req.Sany)
			if err != nil {
				s.error(w, r, http.StatusUnprocessableEntity, err)
				return
			}

			type Result struct {
				Data       interface{} `json:"data"`
				Code       int         `json:"code"`
				StatusText string      `json:"status_text"`
			}

			var result Result

			result.Data = product
			result.Code = http.StatusCreated
			result.StatusText = http.StatusText(http.StatusCreated)

			_ = json.NewEncoder(w).Encode(result)
		}
	}
}

func (s *Server) SellProduct() http.HandlerFunc {

	type Request struct {
		ShtrixCode int    `json:"shtrixcode"`
		Sany       int    `json:"sany"`
		Alyjy      string `json:"alyjy"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		req := &Request{}

		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		err := model.ValidateAny(req.ShtrixCode)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("shtrixCode can not be blank"))
			return
		}

		err = model.ValidateAny(req.Sany)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("sany can not be blank"))
			return
		}

		err = model.ValidateAny(req.Alyjy)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("alyjy can not be blank"))
			return
		}

		prd, err := s.store.Users().FindByShtrix(req.ShtrixCode)
		if err != nil {
			s.error(w, r, http.StatusNotFound, err)
			return
		}

		prod, err := s.store.Users().Ayyrmak(prd, float32(req.Sany))
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		type Result struct {
			Total   float64     `json:"total_cost"`
			Product interface{} `json:"product"`
			Alyjy   string      `json:"alyjy"`
		}

		var result Result

		result.Total = float64(req.Sany) * float64(prod.Cost)
		result.Product = prod
		result.Alyjy = req.Alyjy

		_ = json.NewEncoder(w).Encode(result)

	}
}

func (s *Server) DeletProduct() http.HandlerFunc {

	type Request struct {
		ID         int `json:"id"`
		ShtrixCode int `json:"shtrixcode"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		req := &Request{}

		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		err := model.ValidateAny(req.ID)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("id can not be blank"))
			return
		}

		_, err = s.store.Users().DeletProduct(req.ID)
		if err != nil {
			s.error(w, r, http.StatusNotFound, err)
			return
		}
		type Result struct {
			Code       int    `json:"code"`
			StatusText string `json:"status_text"`
		}

		var result Result

		result.Code = http.StatusOK
		result.StatusText = http.StatusText(http.StatusOK)

		_ = json.NewEncoder(w).Encode(result)

	}
}

func (s *Server) UpdateProducts() http.HandlerFunc {

	type Request struct {
		ID         int     `json:"id"`
		Name       string  `json:"name"`
		Cost       float32 `json:"cost"`
		AlynanBaha float32 `json:"alynanbaha"`
		Sany       int     `json:"sany"`
		ShtrixCode int     `json:"shtrixcode"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		req := &Request{}

		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		err := model.ValidateAny(req.Name)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("name can not be blank"))
			return
		}

		err = model.ValidateAny(req.Cost)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("cost can not be blank"))
			return
		}

		err = model.ValidateAny(req.AlynanBaha)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("alynanbaha can not be blank"))
			return
		}

		err = model.ValidateAny(req.Sany)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("sany can not be blank"))
			return
		}

		err = model.ValidateAny(req.ShtrixCode)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("shtrixCode can not be blank"))
			return
		}

		prd, err := s.store.Users().FindByShtrix(req.ShtrixCode)
		if err != nil {
			s.error(w, r, http.StatusNotFound, err)
			return
		}

		p, err := s.store.Users().UpdateProduct(
			prd,
			req.Name,
			float32(req.Sany),
			req.Cost,
			req.AlynanBaha,
		)

		if err != nil {
			s.error(w, r, http.StatusNotFound, err)
			return
		}

		type Result struct {
			Data       interface{} `json:"data"`
			Code       int         `json:"code"`
			StatusText string      `json:"status_text"`
		}

		var result Result

		result.Data = p
		result.Code = http.StatusOK
		result.StatusText = http.StatusText(http.StatusOK)

		_ = json.NewEncoder(w).Encode(result)

	}
}

func (s *Server) UpdateUsers() http.HandlerFunc {

	type Request struct {
		ID     int    `json:"id"`
		Photo  string `json:"photo"`
		Name   string `json:"name"`
		Wezipe string `json:"wezipe"`
		Qrcode string `json:"qrcode"`
		Role   string `json:"role"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		req := &Request{}

		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		err := model.ValidateAny(req.Photo)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("photo can not be blank"))
			return
		}

		err = model.ValidateAny(req.Name)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("name can not be blank"))
			return
		}

		err = model.ValidateAny(req.Wezipe)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("wezipe can not be blank"))
			return
		}

		err = model.ValidateAny(req.Qrcode)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("qrcode can not be blank"))
			return
		}
		err = model.ValidateAny(req.Role)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errors.New("role can not be blank"))
			return
		}

		u, err := s.store.Users().UpdateUser(
			req.Name,
			req.Wezipe,
			req.Photo,
			req.Qrcode,
			req.Role,
			req.ID,
		)

		if err != nil {
			s.error(w, r, http.StatusNotFound, err)
			return
		}

		type Result struct {
			Data       interface{} `json:"data"`
			Code       int         `json:"code"`
			StatusText string      `json:"status_text"`
		}

		var result Result

		result.Data = u
		result.Code = http.StatusOK
		result.StatusText = http.StatusText(http.StatusOK)

		_ = json.NewEncoder(w).Encode(result)
	}
}

func (s *Server) GetAll_Users() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		u, err := s.store.Users().GetAllusers()
		if err != nil {
			s.error(w, r, http.StatusNotFound, err)
			return
		}

		Users := make([]model.User, 0)

		defer u.Close()

		for u.Next() {
			user := model.User{}

			err := u.Scan(
				&user.ID,
				&user.Photo,
				&user.Name,
				&user.Wezipe,
				&user.Email,
				&user.Qrcode,
				&user.Qrcode,
				&user.Role,
			)
			if err != nil {
				s.error(w, r, http.StatusNotFound, store.ErrorNotFoundRecord)
				return
			}

			Users = append(Users, user)
		}
		_ = json.NewEncoder(w).Encode(Users)

	}
}

func (s *Server) GetAll_Products() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		p, err := s.store.Users().GetAllProduct()
		if err != nil {
			s.error(w, r, http.StatusNotFound, err)
			return
		}

		Products := make([]model.Product, 0)

		defer p.Close()

		for p.Next() {
			product := model.Product{}

			err := p.Scan(
				&product.ID,
				&product.Name,
				&product.Cost,
				&product.AlynanBaha,
				&product.Sany,
				&product.ShtrixCode,
			)
			if err != nil {
				s.error(w, r, http.StatusNotFound, store.ErrorNotFoundRecord)
				return
			}

			Products = append(Products, product)
		}

		_ = json.NewEncoder(w).Encode(Products)

	}
}

func (s *Server) Statics() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		p, err := s.store.Users().GivStatic()
		if err != nil {
			s.error(w, r, http.StatusNotFound, err)
			return
		}

		type Result struct {
			Data       interface{} `json:"data"`
			Code       int         `json:"code"`
			StatusText string      `json:"status_text"`
		}

		var result Result

		result.Data = p
		result.Code = http.StatusOK
		result.StatusText = http.StatusText(http.StatusOK)

		_ = json.NewEncoder(w).Encode(result)

	}
}

func (s *Server) error(w http.ResponseWriter, r *http.Request, code int, err error) {

	s.Respond(w, r, code, map[string]interface{}{
		"error":       err.Error(),
		"code":        code,
		"Status Text": http.StatusText(code),
	})
}

func (s *Server) Respond(w http.ResponseWriter, r *http.Request, code int, data interface{}) {

	if data != nil {

		json.NewEncoder(w).Encode(data)

	}
}

// func (s *Server) SpecailRespond(w http.ResponseWriter, r *http.Request, code int, data interface{}) {

// 	w.WriteHeader(code)

// 	type Result struct {
// 		Data       interface{} `json:"data"`
// 		StatusText string      `json:"status_text"`
// 		StatusCode int         `json:"status_code"`
// 	}
// 	var result Result
// 	result.StatusCode = code
// 	result.StatusText = http.StatusText(code)
// 	result.Data = data

// 	json.NewEncoder(w).Encode(result)
// }

func (s *Server) LogRequest(param http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		logger := s.logger.WithFields(logrus.Fields{
			"remout_adress": r.RemoteAddr,
		})

		logger.Infof("Started %v RequestURI %v", r.Method, r.RequestURI)

		start := time.Now()

		param.ServeHTTP(w, r)

		logger.Infof("Completed in %v", time.Now().Sub(start))
	})
}
