# awarp

CLI tool for creating a **Cloudflare WARP VPN tunnel** via **AmneziaWG** (obfuscated WireGuard fork) on Windows.

**Русский:** [README.md](README.md)

## Features

- Cloudflare WARP registration and key management
- AmneziaWG tunnel with obfuscation parameters (jc, jmin, jmax, s1-s4, h1-h4, i1-i5)
- WFP firewall (kill switch)
- **Endpoint scanner v2** — finds alive WARP servers via real Noise-IK WireGuard handshake
- **Auto-optimization** — `awarp register --auto` registers and finds the best endpoint in one command
- Integration with Zapret (winws) via `--wf-iface` binding

## Requirements

- Windows 10/11
- Administrator privileges (for `awarp up`)
- `wintun.dll` in the same directory as the binary

## Build

```cmd
go build -o awarp.exe .
```

## wintun.dll

The `wintun.dll` library is required for TUN interface creation. Download it from:

- **Official site:** https://www.wintun.net/
- **GitHub:** https://github.com/WireGuard/wintun

Place `wintun.dll` in the same directory as `awarp.exe`.

## Quick Start

```cmd
:: All-in-one: register + find best endpoint
awarp register --auto

:: Connect
awarp up
```

After `awarp register --auto` you get a fully configured profile with the optimal endpoint. The profile is created once and stored next to the binary.

## Commands

```
awarp register --profile <name> [--license KEY] [--set-awg KEY=VAL ...] [--sni DOMAIN] [--i1-mode safe|reorder|legacy] [--auto]
awarp up       --profile <name>
awarp down     --profile <name>
awarp status   --profile <name>
awarp scan     [--community] [--fast] [--awg] [--full-as]
awarp config show    --profile <name>
awarp config set     --profile <name> [--endpoint IP:PORT] [--set-awg KEY=VAL ...]
awarp config profiles
awarp config delete  --profile <name>
awarp help
```

### `awarp register`

Creates a new Cloudflare WARP account.

```cmd
:: Standard registration
awarp register --profile mywarp

:: With WARP+ license
awarp register --profile mywarp --license XXXXXX

:: With custom obfuscation params
awarp register --profile mywarp --set-awg jc=10 --set-awg jmin=50

:: With custom SNI for I1 packet
awarp register --profile mywarp --sni cloudflare.com

:: With I1 strategy (safe, reorder, legacy)
awarp register --profile mywarp --sni cloudflare.com --i1-mode reorder

:: Register + auto-find best endpoint
awarp register --profile mywarp --auto
```

### `awarp register --auto` (key feature)

The `--auto` flag automatically finds the fastest WARP server right after registration:

1. Registers an account (or skips if the profile already exists)
2. Scans 10 Cloudflare WARP subnets (8180 IPs) via a real WireGuard handshake
3. Finds the lowest-latency endpoint
4. Saves it to the profile

After this, just run `awarp up --profile <name>`.

**If the profile already exists**, `--auto` does not re-register — it only runs the scan and updates the endpoint.

### `awarp scan`

Scans Cloudflare WARP subnets to find alive servers.

```cmd
:: Full scan of all subnets
awarp scan

:: With community endpoint lists
awarp scan --community

:: With AmneziaWG obfuscation (warp-plus junk noise)
awarp scan --awg

:: Fast scan (8 ports)
awarp scan --fast

:: Full Cloudflare AS coverage (~60k IPs)
awarp scan --full-as
```

**Important:** The scanner uses a full **Noise-IKpsk2 WireGuard handshake** (148-byte Initiation packet). A **registered profile** (`awarp register`) is required for it to work. Without a profile, it falls back to a MAC1-only probe that **always finds 0 endpoints**, because WARP servers silently drop Initiation packets without a valid MAC1 and registered client key.

Scanning process:
1. **Phase 1:** ICMP ping all IPs across 10 subnets (8180 IPs, or ~60k with `--full-as`)
2. **Phase 2:** WireGuard handshake probe on 54 UDP ports for the top 30 fastest IPs
3. Outputs a table of alive endpoints sorted by latency

Scan parameters:
- **10 subnets (default):** `162.159.192.0/21`, `188.114.96.0/20`, `8.6.112.0/24`, `8.34.70.0/24`, `8.34.146.0/24`, `8.35.211.0/24`, `8.39.125.0/24`, `8.39.204.0/24`, `8.39.214.0/24`, `8.47.69.0/24`
- **26 subnets (`--full-as`):** + `162.159.200.0/21` → `162.159.248.0/21` (7×/21) + `188.114.112.0/20` → `188.114.240.0/20` (8×/20)
- **54 ports:** 2408, 500, 1701, 4500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843, 2371, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886
- **Concurrency:** 50 goroutines
- **Progress bar** for both phases

```cmd
:: Sample output
awarp scan

Results: 29 alive endpoints, top 20:

Distribution: 8.47.69.0/24=3 8.6.112.0/24=2 8.35.211.0/24=2 8.34.70.0/24=8 8.39.214.0/24=2 8.39.204.0/24=2 8.39.125.0/24=6 8.34.146.0/24=4
ENDPOINT           PORT  LATENCY
--------------------------------------------------
8.39.125.5         2408  46ms
8.6.112.245        2408  47ms
8.34.146.142       2408  47ms
...

Use the best endpoint:
  awarp config set --profile <name> --endpoint 8.39.125.5:2408
```

#### `--awg` flag

Uses warp-plus junk noise before WireGuard handshake — for regions where DPI blocks plain WG.

#### `--fast` flag

Quick scan on 8 core ports instead of 54.

#### `--community` flag

Downloads endpoint lists from `ircfspace/endpoint` (GitHub) and uses them as the IP source. If community lists are unavailable (regional block or network issues), the scanner automatically falls back to full scan of all subnets.

#### `--full-as` flag

Maximum Cloudflare AS coverage — 26 subnets (~60k IPs). Adds 7 /21 subnets (162.159.200.0/21 → 162.159.248.0/21) and 8 /20 subnets (188.114.112.0/20 → 188.114.240.0/20). Recommended for users with good bandwidth (Phase 1 takes ~30 minutes).

### `awarp config set --endpoint`

After scanning, set the best endpoint:

```cmd
awarp config set --profile mywarp --endpoint 8.39.125.5:2408
awarp down --profile mywarp
awarp up --profile mywarp
```

Endpoint format: `IP:PORT` or `host:port`.

## Endpoint Scanner — Technical Details

### Why a scanner?

The default endpoint `engage.cloudflareclient.com:2408` may be slow or unreachable in your region. The scanner finds WARP servers closest to you.

### How it works (technical)

The scanner sends a full **Noise-IKpsk2 handshake initiation** — the same packet that WireGuard (and AmneziaWG) sends when establishing a connection:

1. **Ephemeral key generation** — a fresh Curve25519 key per probe
2. **KDF1/KDF2 via HMAC-Blake2s** — key chain computation for encryption
3. **mixHash/mixKey** — avalanche mixing for authenticated encryption
4. **TAI64N timestamp** — replay attack protection
5. **ChaCha20Poly1305 encryption** — of the client's static key and timestamp
6. **MAC1 via Blake2s-128** — server authentication signature

Upon receiving a valid Initiation, the WARP server:
- Decrypts the client's static key via `clientPub`
- Checks if the key is registered in its database
- If OK — sends a Handshake Response (32-byte reply)
- If not — **silently drops the packet**

This is why **scanning without a registered profile always finds 0** — the server doesn't know your key and ignores the request.

### Why this beats a plain UDP scanner?

A plain UDP scanner checks if a port is open (send → receive = "alive"). This causes **false positives**: many servers in WARP subnets have open UDP ports but aren't WARP servers. The Noise-IK handshake gives **100% accuracy** — a response only comes from a real WARP server that knows your registered key.

## I1 Strategies (QUIC Initial)

You can choose the I1 packet generation strategy via `--i1-mode`:

| Mode | mini_quic level | Description |
|------|----------------|-------------|
| `safe` (default) | 4 | Split ClientHello at [0:1]+[38:∞], skip zeroes, 2 CRYPTO frames |
| `reorder` | 1 | Split+reorder frames [38:∞]+[0:38], drop tail 32 bytes |
| `legacy` | 0 | Single CRYPTO frame, no fragmentation |

**AWG 1.5+ `<r N>` tag:** I1 can contain `<b 0x...>` (include) and `<r N>` (skip N bytes) for QUIC packet reconstruction. Algorithm: alternate `<b>` and `<r>`, where `<r>` skips N bytes in the original.

Without `--sni`, a random static I1 mask is selected (from 2 pre-built blobs).

**QUIC Initial generation:** HMAC-SHA256 with salt `38762cf7f55934b3...`, AES-CBC for Header Protection mask (ECB fallback), AES-GCM payload encryption. Algorithm identical to llimonix/mini_quic generator.

## AWG Parameters

| Param | Description |
|-------|-------------|
| `jc` | Junk packet count |
| `jmin`, `jmax` | Junk packet size range |
| `s1`-`s4` | Message padding |
| `h1`-`h4` | Message headers |
| `i1`-`i5` | Custom signature packets |

## Cloudflare WARP Endpoints

### Standard WireGuard subnets
- **IPv4 (broad CIDR):** `162.159.192.0/21` (2046 IPs), `188.114.96.0/20` (4094 IPs), `8.6.112.0/24`, `8.34.70.0/24`, `8.34.146.0/24`, `8.35.211.0/24`, `8.39.125.0/24`, `8.39.204.0/24`, `8.39.214.0/24`, `8.47.69.0/24`
- **IPv6:** `2606:4700:100::/48`, `2606:4700:d0::/48`
- **`--full-as`:** adds `162.159.200.0/21` → `162.159.248.0/21` (7×/21) + `188.114.112.0/20` → `188.114.240.0/20` (8×/20) = ~60k IPs

### Ports (54 ports)
- **Default:** UDP 2408
- **Backup:** 500, 1701, 4500
- **All ports:** 500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886

### Default endpoint
`engage.cloudflareclient.com:2408`

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

Ready-made example: [`examples/general (ALT11) + WARP.bat`](examples/general%20%28ALT11%29%20%2B%20WARP.bat) (based on [Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube))

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

## Plans

- **Warp-in-WARP** — two WARP layers: outer AmneziaWG (obfuscation), inner plain WireGuard. The outer layer bypasses DPI, the inner provides WARP-IP exit. For regions with deep packet inspection blocking.
- **SOCKS5 proxy mode** — replace kernel TUN (admin, wintun, routes, DNS, firewall) with userspace WireGuard via gVisor netstack. SOCKS5 on `127.0.0.1:8086` without admin privileges. No more conflict with WinDivert/zapret. Single binary, no sidecar. (from warp-plus)
- **LCG IP randomization** — ✓ implemented (see cmd/ipgen.go)
- **Expanded CIDR ranges (broad CIDR + `--full-as`)** — ✓ implemented: 10 subnets (8180 IPs) default, 26 subnets (~60k IPs) with `--full-as`. Includes 8 new /24 from warp-generator.github.io and 15 broad CIDR Cloudflare AS prefixes. Finds 29+ endpoints.
- **TLS fingerprint rotation** — 3-tier fallback for WARP API: uTLS (Chrome fingerprint) → stdlib TLS 1.3 → uTLS Chrome_Auto. Fixes keepalive timeout in regions where stdlib TLS is blocked. (from warp-plus)

## Notes

- **Profiles are stored next to the binary**, not in `$HOME`. The `profiles/` folder is created automatically.
- **WARP keepalive** may timeout (TLS to api.cloudflareclient.com) — this doesn't affect tunnel operation.
- **Scanner finds more endpoints without Zapret** (29 vs 20) — Zapret may rate-limit UDP probe packets.
- **`awarp up`** automatically configures: DNS (1.1.1.1), IPv6 disable on physical adapter, metrics, NCSI disable, zombie adapter cleanup.
- **`awarp down`** restores all settings to their original state.

## License

MIT
