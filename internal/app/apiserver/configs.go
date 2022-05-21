package apiserver

type Api struct {
	DatabaseURL string `toml:"database_url"`
	BindAdress  string `toml:"Bind_adr"`
	LogLev      string `toml:"log_lev"`
}

func NewConfig() *Api {
	return &Api{
		BindAdress: ":8080",
		LogLev:     "debug",
	}
}
