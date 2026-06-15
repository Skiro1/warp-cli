package warp

type RegisterRequest struct {
	Key         string `json:"key"`
	InstallID   string `json:"install_id"`
	FCMToken    string `json:"fcm_token"`
	Referer     string `json:"referer"`
	WarpEnabled bool   `json:"warp_enabled"`
	Locale      string `json:"locale"`
	License     string `json:"license,omitempty"`
}

type RegisterResponse struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Token     string `json:"token"`
	ClientID  string `json:"client_id"`
	Config    Config `json:"config"`
	WarpPlus  bool   `json:"warp_plus"`
	Account   struct {
		ID string `json:"id"`
	} `json:"account"`
}

type Config struct {
	ClientID  string   `json:"client_id"`
	Peers     []Peer   `json:"peers"`
	Interface Iface    `json:"interface"`
}

type Peer struct {
	PublicKey string   `json:"public_key"`
	Endpoint  Endpoint `json:"endpoint"`
}

type Endpoint struct {
	Host  string `json:"host"`
	V4    string `json:"v4"`
	V6    string `json:"v6"`
	Ports []int  `json:"ports"`
}

type Iface struct {
	Addresses Addresses `json:"addresses"`
	Services  Services  `json:"services"`
}

type Addresses struct {
	V4 string `json:"v4"`
	V6 string `json:"v6"`
}

type Services struct {
	HTTPProxy string `json:"http_proxy"`
}
