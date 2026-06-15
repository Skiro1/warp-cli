# awarp

CLI tool for creating a **Cloudflare WARP VPN tunnel** via **AmneziaWG** (obfuscated WireGuard fork) on Windows.

## Features

- Cloudflare WARP registration and key management
- AmneziaWG tunnel with obfuscation parameters (jc, jmin, jmax, s1-s4, h1-h4, i1-i5)
- WFP firewall (kill switch)
- Endpoint scanner for finding the fastest WARP server
- Integration with Zapret (winws) via `--wf-iface` binding

## Requirements

- Windows 10/11
- Administrator privileges (for `awarp up`)
- `wintun.dll` in the same directory as the binary

## Build

```cmd
go build -o awarp.exe .
```

## Usage

```
awarp register --profile <name> [--license KEY] [--set-awg KEY=VAL ...] [--sni DOMAIN]
awarp up --profile <name>
awarp down --profile <name>
awarp status --profile <name>
awarp scan
awarp config show --profile <name>
awarp config set --profile <name> [--endpoint IP:PORT] [--set-awg KEY=VAL ...]
awarp config profiles
awarp config delete --profile <name>
awarp help
```

### Examples

```cmd
:: Register and connect
awarp register
awarp up

:: Scan for fastest endpoint
awarp scan

:: Change endpoint
awarp config set --endpoint 162.159.192.179:2408

:: Reconnect with new endpoint
awarp down && awarp up

:: Use with Zapret (winws)
awarp up
zapret-warp.bat
```

## AWG Parameters

| Param | Description |
|-------|-------------|
| `jc` | Junk packet count |
| `jmin`, `jmax` | Junk packet size range |
| `s1`-`s4` | Message padding |
| `h1`-`h4` | Message headers |
| `i1`-`i5` | Custom signature packets |

## Endpoints

Default: `engage.cloudflareclient.com:2408`

WARP WireGuard subnets:
- `162.159.192.0/24`
- `162.159.193.0/24`

Port: UDP 2408 (backup: 500, 1701, 4500)

## License

MIT
