package model

type Product struct {
	ID 		     int     `json:"id"`
	Name 	     string  `json:"name"`
	Cost  	     float32 `json:"cost"`
	AlynanBaha   float32 `json:"alynanbaha"`
	Sany 	     int     `json:"sany"`
	ShtrixCode   int 	 `json:"shtrixcode"`
	Total 		 float64 `json:"total"`
	Satylansany  int     `json:"satylansany"`
	Totalcost    float32 `json:"totalcost"`

}

type Product2 struct {
	Satylansany  int     `json:"satylansany"`
	Totalcost    float32 `json:"totalcost"`
}