module warp-cli

go 1.26.2

require (
	github.com/amnezia-vpn/amneziawg-go v1.0.4
	golang.org/x/crypto v0.53.0
	golang.org/x/sys v0.46.0
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2
)

replace github.com/amnezia-vpn/amneziawg-go => github.com/amnezia-vpn/amneziawg-go v0.2.17-0.20260601143056-948c55579489

require (
	github.com/amnezia-vpn/amneziawg-windows v0.1.9 // indirect
	golang.org/x/net v0.55.0 // indirect
)
