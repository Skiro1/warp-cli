# Release Notes

**English** | [Русский](#русский)

## English

### awarp — WARP tunnel via AmneziaWG

CLI tool for creating Cloudflare WARP VPN tunnel via AmneziaWG (obfuscated WireGuard) on Windows.

### Features

- **Cloudflare WARP** — registration and key management
- **AmneziaWG** — tunnel with obfuscation parameters (jc, jmin, jmax, s1-s4, h1-h4, i1-i5)
- **WFP firewall** — kill switch via `SERVICE_SID_TYPE_UNRESTRICTED`
- **Endpoint scanner** — `awarp scan` finds fastest IPs in 162.159.192.0/24 and 162.159.193.0/24
- **Endpoint change** — `awarp config set --endpoint IP:PORT`
- **Zapret (winws)** — integration via `--wf-iface` binding to physical interface

### Requirements

- Windows 10/11
- `wintun.dll` (download: https://www.wintun.net/)
- Administrator privileges (for `awarp up`)

### Quick start

```cmd
awarp register
awarp up
```

---

## Русский

### awarp — WARP-тоннель через AmneziaWG

CLI-утилита для создания Cloudflare WARP VPN-тоннеля через AmneziaWG (обфусцированный WireGuard) на Windows.

### Возможности

- **Cloudflare WARP** — регистрация и управление ключами
- **AmneziaWG** — туннель с параметрами обфускации (jc, jmin, jmax, s1-s4, h1-h4, i1-i5)
- **WFP firewall** — kill switch через `SERVICE_SID_TYPE_UNRESTRICTED`
- **Сканер эндпоинтов** — `awarp scan` находит быстрые IP в подсетях 162.159.192.0/24 и 162.159.193.0/24
- **Смена endpoint** — `awarp config set --endpoint IP:PORT`
- **Запрет (winws)** — интеграция через `--wf-iface` привязку к физическому интерфейсу

### Требования

- Windows 10/11
- `wintun.dll` (скачать: https://www.wintun.net/)
- Права администратора (для `awarp up`)

### Быстрый старт

```cmd
awarp register
awarp up
```

### Ссылки

- [README (English)](https://github.com/Skiro1/warp-cli/blob/master/README-en.md)
- [README (Русский)](https://github.com/Skiro1/warp-cli/blob/master/README.md)
