package model

type Product struct {
	ID          int     `json:"id"`
	Name        string  `json:"name"`
	Cost        float32 `json:"cost"`
	AlynanBaha  float32 `json:"alynanbaha"`
	Sany        int     `json:"sany"`
	ShtrixCode  int     `json:"shtrixcode"`
	Satylansany int     `json:"satylansany"`
	Totalcost   float32 `json:"totalcost"`
}

type Product2 struct {
	ID          int     `json:"id"`
	Satylansany float32 `json:"satylansany"`
	Totalcost   float32 `json:"totalcost"`
}

type Product3 struct {
	Total float64 `json:"total"`
}
