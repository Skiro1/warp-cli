# awarp

CLI tool for creating a **Cloudflare WARP VPN tunnel** via **AmneziaWG** (obfuscated WireGuard fork) on Windows.

**Русский:** [README.md](README.md)

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

### Problem

When running winws (GoodbyeDPI/Запрет) together with WARP, browsers show "No internet" and websites don't load. This happens because:

1. WinDivert (used by winws) intercepts packets on ALL network interfaces
2. WARP creates a TUN interface (`warp0`) that handles all traffic
3. Windows NCSI (Network Connectivity Status Indicator) sends HTTP probes through the TUN
4. WinDivert mangles these probes → Windows thinks there's no internet
5. curl and Telegram work because they use their own network stack (Winsock)

### Symptoms

- `curl https://youtube.com` works
- Telegram works
- Browser shows "No internet", YouTube doesn't load
- winws + WARP = browser completely broken

### Solution

Use `--wf-iface=<physical_interface_index>` to bind WinDivert only to the physical network interface, excluding the TUN interface.

### Quick Start

1. Copy `zapret-warp-alt-chrome.bat` to your zapret directory (e.g., `D:\zapret\`)
2. Start WARP:
   ```cmd
   awarp up
   ```
3. Run zapret (in a separate terminal):
   ```cmd
   D:\zapret\zapret-warp-alt-chrome.bat
   ```
4. To stop:
   ```cmd
   awarp down
   taskkill /F /IM winws.exe
   ```

### How it works

The bat file auto-detects network interfaces:
1. Finds TUN interface index (`warp0`) via `netsh int ip show interfaces`
2. Finds physical interface index (first connected non-TUN interface)
3. Adds `--wf-iface=<physical_index>` to winws arguments
4. WinDivert captures packets ONLY on the physical interface, ignoring TUN

### Manual Fix for Other bat files

If you want to use a different zapret strategy (ALT1, ALT2, etc.) with WARP:

Ready-made example: [`examples/general (ALT11) + WARP.bat`](examples/general%20%28ALT11%29%20%2B%20WARP.bat)

**Step 1:** Add this code after `set "LISTS=%~dp0lists\"` and before `cd /d %BIN%`:

```bat
setlocal enabledelayedexpansion
set "PHY_IDX="
for /f "skip=1 tokens=1" %%a in ('netsh int ip show interfaces 2^>nul ^| findstr /i "connected"') do (
    if not defined PHY_IDX set "PHY_IDX=%%a"
)
set "IFACE_FILTER="
if defined PHY_IDX set "IFACE_FILTER=--wf-iface=!PHY_IDX!"
```

**Step 2:** Add `%IFACE_FILTER%` before `--wf-tcp` in the winws command:

```bat
:: Before (broken with WARP):
start "zapret: %~n0" /min "%BIN%winws.exe" --wf-tcp=80,443,...

:: After (works with WARP):
start "zapret: %~n0" /min "%BIN%winws.exe" %IFACE_FILTER% --wf-tcp=80,443,...
```

### Troubleshooting

If it still doesn't work:
1. Check that winws is running: `tasklist | find winws`
2. Check physical interface index: `netsh int ip show interfaces`
3. Verify `--wf-iface` is in the winws command line
4. Try running winws manually (not via bat) to see error messages

## License

MIT
