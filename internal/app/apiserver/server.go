package apiserver

import (
	"cofeeteria/internal/app/model"
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	store "cofeeteria/internal/app/store"
)

type Server struct {
	router *mux.Router
	logger *logrus.Logger
	store   store.Store
}

func NewServer(str store.Store) *Server {
	s := &Server{
		router: mux.NewRouter(),
		logger: logrus.New(),
		store: str,
	}
	
	s.SettingRouter()

	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *Server) SettingRouter() {
	s.router.HandleFunc("/register", s.Registirate()).Methods("POST")
	s.router.HandleFunc("/addproduct", s.AddProduct()).Methods("POST")
	s.router.HandleFunc("/sell", s.SellProduct()).Methods("POST")

}

func (s *Server) Registirate() http.HandlerFunc {

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

		u := &model.User{
			Email: req.Email,
			Password: req.Password,
		}

		if err := s.store.Users().CreateUser(u); err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
		}
		
		u.Parolgizle()

		s.Respond(w, r, http.StatusCreated, u)
	}
}

func (s *Server) AddProduct() http.HandlerFunc {

	type Request struct {
		Name 	   string  `json:"name"`
		Cost  	   float32 `json:"cost"`
		AlynanBaha float32 `json:"alynanbaha"`
		Sany 	   int 	   `json:"sany"`
		ShtrixCode int	   `json:"shtrixcode"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		req := &Request{}

		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		p := &model.Product{
			Name: req.Name,
			Cost: req.Cost,
			AlynanBaha: req.AlynanBaha,
			Sany: req.Sany,
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
		ShtrixCode int `json:"shtrixcode"`
		Cost       float32 `json:"cost"`
		Sany 	   int 	   `json:"sany"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		req := &Request{}

		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		p := &model.Product{
			ShtrixCode: req.ShtrixCode,
			Cost: req.Cost,
			Sany: req.Sany,
		}

		prod, err := s.store.Users().Ayyrmak(p, req.Sany)
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		s.Respond(w, r, http.StatusOK, prod)
	}
}

func (s *Server) error (w http.ResponseWriter, r *http.Request, code int, err error) {
	s.Respond(w, r, code, map[string]string{"error": err.Error()})
}

func (s *Server) Respond(w http.ResponseWriter, r *http.Request, code int, data interface{}) {
	w.WriteHeader(code)

	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}