package apiserver

import (
	"cofeeteria/internal/app/middlwear"
	"cofeeteria/internal/app/model"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	store "cofeeteria/internal/app/store"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
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
	s.router.HandleFunc("/register", s.Registirate()).Methods("POST")
	s.router.HandleFunc("/addproduct", middlwear.MultipleMiddleware(s.AddProduct(), s.accountanttMiddlwear, s.Authentication)).Methods("POST")
	s.router.HandleFunc("/addproduct", middlwear.MultipleMiddleware(s.AddProduct(), s.adminMiddlwear, s.Refreshtoken)).Methods("POST")
	s.router.HandleFunc("/sell", middlwear.MultipleMiddleware(s.SellProduct(), s.sellerMiddlwear, s.Authentication)).Methods("POST")
	s.router.HandleFunc("/sell", middlwear.MultipleMiddleware(s.SellProduct(), s.adminMiddlwear)).Methods("POST")

	s.router.HandleFunc("/login", s.Login()).Methods("POST")
	s.router.HandleFunc("/static", s.Statics())

	s.router.HandleFunc("/whoamI", middlwear.MultipleMiddleware(s.WhoamI(), s.Authentication))

}

func (s *Server) Registirate() http.HandlerFunc {

	type Request struct {
		Name        string `json:"name"`
		Email       string `json:"email"`
		Password    string `json:"password"`
		IsAdmin     bool   `json:"isadmin"`
		IsSeller    bool   `json:"isseller"`
		Accountantt bool   `json:"accountantt"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		req := &Request{}

		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		u := &model.User{
			Name:        req.Name,
			Email:       req.Email,
			Password:    req.Password,
			IsAdmin:     req.IsAdmin,
			IsSeller:    req.IsSeller,
			Accountantt: req.Accountantt,
		}

		if err := s.store.Users().CreateUser(u); err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
		}

		u.Parolgizle()

		s.Respond(w, r, http.StatusCreated, u)
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

		u, err := s.store.Users().FincByEmail(req.Email)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		token, err := CreateToken(u)
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		Cookie := http.Cookie{
			Name:     "CFT_Token",
			Value:    token,
			HttpOnly: true,
		}

		http.SetCookie(w, &Cookie)

		s.Respond(w, r, http.StatusOK, token)
	}
}

func (s *Server) Authentication(next http.HandlerFunc) http.HandlerFunc {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("CFT_Token")
		if err != nil {
			if err == http.ErrNoCookie {
				s.error(w, r, http.StatusUnauthorized, err)
				return
			}
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		cookie := c.Value

		claims := jwt.MapClaims{}

		token, err := jwt.ParseWithClaims(cookie, claims, func(t *jwt.Token) (interface{}, error) {
			return Secretkey, nil
		})
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, errors.New("error su yerde"))
			return
		}

		if !token.Valid {
			s.error(w, r, http.StatusUnauthorized, errors.New("token is not valid !!!!!"))
			return
		}

		email := claims["user_id"].(string)

		u, err := s.store.Users().FincByEmail(email)
		if err != nil {
			s.error(w, r, http.StatusUnauthorized, store.ErrorNotAuthenticate)
			return
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), store.CntKey, u)))

	})
}

func (s *Server) WhoamI() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.Respond(w, r, http.StatusOK, r.Context().Value(store.CntKey).(*model.User))
	}
}

func (s *Server) adminMiddlwear(next http.HandlerFunc) http.HandlerFunc {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("CFT_Token")
		if err != nil {
			if err == http.ErrNoCookie {
				s.error(w, r, http.StatusUnauthorized, err)
				return
			}
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		cookie := c.Value

		claims := jwt.MapClaims{}

		token, err := jwt.ParseWithClaims(cookie, claims, func(t *jwt.Token) (interface{}, error) {
			return Secretkey, nil
		})
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		if !token.Valid {
			s.error(w, r, http.StatusUnauthorized, errors.New("token is not valid !!!!!"))
			return
		}

		if !claims["admin"].(bool) {
			s.error(w, r, http.StatusForbidden, errors.New("bu sahypa dosdubynyz yok"))
			return
		}

		if !claims["isSeller"].(bool) {
			s.error(w, r, http.StatusForbidden, errors.New("bu sahypa dosdubynyz yok bu statyjy ucn"))
			return
		}

		if !claims["accountantt"].(bool) {
			s.error(w, r, http.StatusForbidden, errors.New("bu sahypa dosdubynyz yok bu buhgalter ucn"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) sellerMiddlwear(next http.HandlerFunc) http.HandlerFunc {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("CFT_Token")
		if err != nil {
			if err == http.ErrNoCookie {
				s.error(w, r, http.StatusUnauthorized, err)
				return
			}
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		cookie := c.Value

		claims := jwt.MapClaims{}

		token, err := jwt.ParseWithClaims(cookie, claims, func(t *jwt.Token) (interface{}, error) {
			return Secretkey, nil
		})
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		if !token.Valid {
			s.error(w, r, http.StatusUnauthorized, errors.New("token is not valid !!!!!"))
			return
		}

		if !claims["isSeller"].(bool) {
			s.error(w, r, http.StatusForbidden, errors.New("bu sahypa dosdubynyz yok bu statyjy ucn"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) accountanttMiddlwear(next http.HandlerFunc) http.HandlerFunc {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("CFT_Token")
		if err != nil {
			if err == http.ErrNoCookie {
				s.error(w, r, http.StatusUnauthorized, err)
				return
			}
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		cookie := c.Value

		claims := jwt.MapClaims{}

		token, err := jwt.ParseWithClaims(cookie, claims, func(t *jwt.Token) (interface{}, error) {
			return Secretkey, nil
		})
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		if !token.Valid {
			s.error(w, r, http.StatusUnauthorized, errors.New("token is not valid !!!!!"))
			return
		}

		if !claims["accountantt"].(bool) {
			s.error(w, r, http.StatusForbidden, errors.New("bu sahypa dosdubynyz yok bu buhgalter ucn"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) Refreshtoken(next http.HandlerFunc) http.HandlerFunc {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		c, err := r.Cookie("CFT_Token")
		if err != nil {
			if err == http.ErrNoCookie {
				s.error(w, r, http.StatusUnauthorized, err)
				return
			}
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		cookie := c.Value

		claims := jwt.MapClaims{}

		token, err := jwt.ParseWithClaims(cookie, claims, func(t *jwt.Token) (interface{}, error) {
			return Secretkey, nil
		})
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		if !token.Valid {
			s.error(w, r, http.StatusUnauthorized, errors.New("token is not valid !!!!!"))
			return
		}
		email := claims["user_id"].(string)

		u, err := s.store.Users().FincByEmail(email)
		if err != nil {
			s.error(w, r, http.StatusUnauthorized, store.ErrorNotAuthenticate)
			return
		}
		
		if claims["exp"] == time.Millisecond {
			expirationtime := time.Now().Add(24 * time.Hour)
			claims["exp"] = expirationtime.Unix()
			claims := jwt.MapClaims{}
			claims["admin"] = u.IsAdmin
			claims["isSeller"] = u.IsSeller
			claims["accountantt"] = u.Accountantt
			claims["user_id"] = u.Email

			tkn := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			token, err := tkn.SignedString(Secretkey)
			if err != nil {
				log.Fatal(err)
			}

			http.SetCookie(w, &http.Cookie{
				Name:     "CFT_Token",
				Value:    token,
				HttpOnly: true,
			})

		}

		next.ServeHTTP(w, r)
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

		p := &model.Product{
			Name:       req.Name,
			Cost:       req.Cost,
			AlynanBaha: req.AlynanBaha,
			Sany:       req.Sany,
			ShtrixCode: req.ShtrixCode,
		}
		bul, err := s.store.Users().Exist(p)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}
		if bul == false {
			err := s.store.Users().CreateProduct(p)
			if err != nil {
				s.error(w, r, http.StatusUnprocessableEntity, err)
			}
			s.Respond(w, r, http.StatusCreated, p)
		} else {
			prod, err := s.store.Users().FindByShtrix(p.ShtrixCode)
			if err != nil {
				s.error(w, r, http.StatusUnprocessableEntity, err)
				return
			}
			product, err := s.store.Users().AddSany(prod, req.Sany)
			if err != nil {
				s.error(w, r, http.StatusUnprocessableEntity, err)
				return
			}
			s.Respond(w, r, http.StatusCreated, product)
		}
	}
}

func (s *Server) SellProduct() http.HandlerFunc {

	type Request struct {
		ShtrixCode int     `json:"shtrixcode"`
		Cost       float32 `json:"cost"`
		Sany       int     `json:"sany"`
		Alyjy      string  `json:"alyjy"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		req := &Request{}

		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		p := &model.Product{
			ShtrixCode: req.ShtrixCode,
			Cost:       req.Cost,
			Sany:       req.Sany,
		}

		prod, err := s.store.Users().Ayyrmak(p, req.Sany, int(req.Cost))
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		// p2 := &model.Product2{
		// 	ID:         prod.ID,
		// 	Name:       prod.Name,
		// 	ShtrixCode: req.ShtrixCode,
		// 	Cost:       req.Cost,
		// 	Sany:       req.Sany,
		// 	Total:      float64(float32(req.Sany) * req.Cost),
		// 	Alyjy:      req.Alyjy,
		// }

		s.Respond(w, r, http.StatusOK, prod)
	}
}

func (s *Server) Statics() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		p, err := s.store.Users().GivStatic()
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		prd := &model.Product2{
			Satylansany: p.Satylansany,
			Totalcost:   p.Totalcost,
		}

		s.Respond(w, r, http.StatusOK, prd)
	}
}

func (s *Server) error(w http.ResponseWriter, r *http.Request, code int, err error) {
	s.Respond(w, r, code, map[string]string{"error": err.Error()})
}

func (s *Server) Respond(w http.ResponseWriter, r *http.Request, code int, data interface{}) {
	w.WriteHeader(code)

	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}
