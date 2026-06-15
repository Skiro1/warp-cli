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

## Zapret (winws) Integration

WinDivert (winws) intercepts packets from the TUN interface, causing browsers to show "No internet" because NCSI packets get mangled.

### Solution

Use `--wf-iface=<physical_interface_index>` to bind WinDivert only to the physical interface, excluding TUN.

### Usage

1. Copy `zapret-warp-alt-chrome.bat` to your zapret directory
2. Start WARP: `awarp up`
3. Run zapret: `zapret-warp-alt-chrome.bat`

### How it works

The bat file auto-detects:
- TUN interface index (`warp0`)
- Physical interface index (first connected non-TUN interface)
- Adds `--wf-iface=<physical_index>` to winws arguments

### Manual fix for other bat files

Add before the `start` command:

```bat
set "PHY_IDX="
for /f "skip=1 tokens=1" %%a in ('netsh int ip show interfaces 2^>nul ^| findstr /i "connected"') do (
    if not defined PHY_IDX set "PHY_IDX=%%a"
)
set "IFACE_FILTER="
if defined PHY_IDX set "IFACE_FILTER=--wf-iface=!PHY_IDX!"
```

Then add `%IFACE_FILTER%` before `--wf-tcp` in the winws command:

```bat
start "zapret: %~n0" /min "%BIN%winws.exe" %IFACE_FILTER% --wf-tcp=80,443,443,...
```

## License

MIT
