# AGENTS.md — warp-cli

## Что это

Go CLI для создания **Cloudflare WARP VPN-тоннеля** через **AmneziaWG** (обфусцированный форк WireGuard). Только Windows — зависит от `wintun.dll` и IPC через именованные каналы с бинарником `awarp.exe`.

## Сборка и запуск

```
go build -o awarp.exe .
```

Требует `wintun.dll` рядом с бинарником. Тестов, линтера, CI нет.

CLI команды:

```
awarp register [-p профиль] [-l лицензия] [-a awg_param=значение ...] [--sni домен]
awarp up       [-p профиль]
awarp down     [-p профиль]
awarp status   [-p профиль]
awarp scan
awarp config show|set|profiles|delete [-p профиль] [-a awg_param ...] [-e endpoint]
```

Профиль по умолчанию: `"warp"`. Команда `up` требует прав администратора.

## Архитектура

```
main.go          — ручной роутер CLI (без cobra/flag), парсинг в parseFlags()
cmd/             — по одному файлу на команду: register, up, down, status, config_cmd, scan
config/          — структура Profile, JSON-хранилище в <dir_бинарника>/profiles/
warp/            — клиент WARP API (регистрация + keepalive), генерация ключей
tunnel/          — управление тоннелем AmneziaWG через именованный канал к awarp.exe
profiles/        — JSON-файлы профилей (по одному на зарегистрированную учётку)
awarp.exe        — sidecar-бинарник, управляющий TUN-интерфейсом
wintun.dll       — Windows TUN-драйвер, должен лежать рядом с awarp.exe
```

## Текущий статус

### Работает
- Handshake AmneziaWG успешен
- IPv4 и IPv6 трафик через туннель
- `curl` работает через туннель
- Telegram работает через туннель
- **Браузер (Chrome/Edge) работает через туннель** — YouTube грузится
- DNS настроен на 1.1.1.1 (оба адаптера)
- Persistent route корректно удаляется при остановке
- **Ctrl+C корректно очищает все настройки за 3 сек** — timeout на device.Close()
- **WARP + Zapret (winws)** работает — zapret-warp.bat с `--wf-iface` привязывает WinDivert к физическому интерфейсу, исключая TUN
- **WFP firewall (kill switch)** — работает через `SERVICE_SID_TYPE_UNRESTRICTED`
- **Сканер эндпоинтов** — `awarp scan` находит быстрые IP в подсетях 162.159.192.0/24 и 162.159.193.0/24
- **Смена endpoint** — `awarp config set --profile <name> --endpoint IP:PORT`

### Не работает
- **WARP keepalive** — таймаут TLS к api.cloudflareclient.com (не критично для работы туннеля)

## Эндпоинты Cloudflare WARP

### Стандартные подсети
- **WireGuard IPv4**: `162.159.193.0/24` и `162.159.192.0/24`
- **WireGuard IPv6**: `2606:4700:100::/48`
- **Стандартный порт**: UDP 2408 (резервные: 500, 1701, 4500)
- **Дефолтный endpoint**: `engage.cloudflareclient.com:2408`

### Смена endpoint
```cmd
awarp scan
awarp config set --profile 1 --endpoint 162.159.192.179:2408
awarp down --profile 1 && awarp up --profile 1
```

## Проблема: Браузер не работает через туннель

### Симптомы
- `curl https://youtube.com` — работает
- Telegram — работает
- Браузер — "Нет интернета", YouTube не грузится
- winws + WARP — браузер完全 не работает

### Корневая причина
**WinDivert (winws) перехватывает пакеты Wintun (TUN-интерфейс).** Браузер через WinINet проверяет NCSI → WinDivert мажет пакеты → "Нет интернета". curl и Telegram работают потому что используют свой стек (Winsock).

### Что уже пробовали (НЕ помогло)
- DNS 1.1.1.1 на обоих адаптерах
- Отключение Smart Multi-Homed Name Resolution
- Отключение NCSI (EnableActiveProbing=0, NoActiveProbe=1, ConnectivityStatus=2)
- Отключение прокси (ProxyEnable=0, AutoDetect=0)
- Отключение IPv6 на физическом адаптере
- Отключение QUIC и DoH в браузере
- Отключение Post-Quantum TLS (Kyber) в Chrome flags
- Правила Windows Firewall для TUN-интерфейса
- MTU=1280
- netsh winhttp reset proxy
- ipconfig /flushdns

### Решение
1. **Запускать winws ПОСЛЕ WARP** — иначе winws перехватывает пакеты до TUN
2. **Использовать `--wf-iface=<индекс>`** — привязать WinDivert к физическому интерфейсу, исключая TUN
3. **Или отказаться от winws** когда работает WARP (WARP сам обходит DPI)

### zapret-warp.bat
Модифицированный bat-файл для совместимости с WARP:
- Авто-определение индекса TUN-интерфейса warp0
- Авто-определение индекса физического интерфейса
- Добавление `--wf-iface=<индекс_физического>` к winws
- WinDivert захватывает пакеты ТОЛЬКО на физическом интерфейсе, не на TUN

Использование:
```cmd
:: 1. Запусти WARP
awarp up --profile 1

:: 2. Запусти zapret с поддержкой WARP
zapret-warp.bat
```

## Тестирование стратегий winws

```powershell
# 1. Запусти WARP
awarp up --profile 1

# 2. Тестируй стратегии (одну за раз)

# Тест 1: Минимальная
winws.exe --dpi-desync=split --dpi-desync-split-pos=1 --dpi-desync-ttl=5

# Тест 2: Fake
winws.exe --dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-repeats=6

# Тест 3: Split + Fake
winws.exe --dpi-desync=split,fake --dpi-desync-split-pos=1 --dpi-desync-ttl=5

# Тест 4: Multi-segment
winws.exe --dpi-desync=split --dpi-desync-split-pos=2 --dpi-desync-split-seqovl=1 --dpi-desync-ttl=5

# Тест 5: Fooling
winws.exe --dpi-desync=fake,split --dpi-desync-fooling=badseq --dpi-desync-ttl=5

# Тест 6: Remote blacklist
winws.exe --dpi-desync=fake --dpi-desync-remote-bl --dpi-desync-ttl=1 --dpi-desync-repeats=6

# Тест 7: С фиксированным размером
winws.exe --dpi-desync=fake --dpi-desync-foolsize=1 --dpi-desync-ttl=1

# Тест 8: Aggressive split
winws.exe --dpi-desync=split --dpi-desync-split-pos=midsplit --dpi-desync-ttl=5

# Тест 9: С отключением TFO
netsh int tcp set global fastopen=disabled
winws.exe --dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-repeats=6

# 3. Если не работает — останови winws
taskkill /F /IM winws.exe
```

## Что было исправлено (баги)

1. **Дублирующий вызов `configure()`** — конфигурация отправлялась дважды. Убран дубликат.
2. **Хардкод порта `:943`** — заменён на `:2408` (стандартный порт WireGuard WARP).
3. **Двойной вызов `t.dev.Up()`** — первый вызов был до конфигурации. Оставлен один `Up()` после `configure()`.
4. **Persistent route не удалялся** — при остановке `0.0.0.0 → 172.16.0.2` оставался. Добавлено удаление.
5. **Ctrl+C не очищал всё** — Close() не закрывал named pipe, cleanupRoutes() выполнялся последовательно. Исправлено: параллельная очистка, полное восстановление настроек.
6. **Медленный запуск** — netsh команды шли последовательно (~40 сек). Запущены параллельно (~10 сек).
7. **Persistent route при запуске** — `netsh interface ip add route` без `store=active` создавал persistent route, который переживал остановку и блокировал восстановление шлюза. Исправлено: добавлен `store=active`.
8. **WFP firewall не работал** — `getCurrentProcessSecurityDescriptor()` не находил NT SERVICE SID в токене. Исправлено: при создании сервиса добавлен `SidType: SERVICE_SID_TYPE_UNRESTRICTED`.
9. **Дефолтный порт 943** — заменён на 2408 (стандартный порт WireGuard WARP).
10. **`config set --endpoint` без валидации** — принимал мусор типа `not-a-port`. Добавлена проверка `host:port`.
11. **`config set` без изменений** — писал "Profile updated" когда ничего не менялось. Теперь: "Nothing to change."
12. **`--set-awg jc=abc`** — молча ставил `jc=0` из-за `_` в `strconv.Atoi`. Теперь ошибка: "is not a number".
13. **Help: "s1-s2"** — исправлено на "s1-s4" (поддерживается 4 параметра).

## Что добавлено (улучшения)

### Сканер эндпоинтов
- Команда `awarp scan` — сканирует подсети 162.159.192.0/24 и 162.159.193.0/24
- ICMP ping для измерения latency (парсит вывод `ping` на русском и английском)
- Проверяет UDP порты 2408, 500, 1701, 4500
- Выводит топ-20 быстрых эндпоинтов
- Конкурентное сканирование (50 goroutines)

### Смена endpoint
- Флаг `--endpoint` / `-e` для `config set`
- Поддержка прямых IP: `162.159.193.1:2408` (без DNS-резолва)
- Поддержка DNS-имён: `engage.cloudflareclient.com:2408`

### WFP firewall (kill switch)
- Работает через `SERVICE_SID_TYPE_UNRESTRICTED` при создании сервиса
- `EnableFirewall(luid, false, []net.IP{dnsIP})` — restricted mode (block all + DNS leak protection)
- Fallback на unrestricted mode если restricted не работает

### Настройки сети при запуске туннеля
- DNS физического адаптера переключается на 1.1.1.1
- DNS на warp0: 1.1.1.1 (register=primary)
- Отключение IPv6 на физическом адаптере
- Метрики: warp0=0, физический=25
- Отключение прокси (WinINet + WinHTTP)
- Отключение WPAD (AutoDetect=0)
- Сброс WinHTTP прокси
- Правила Windows Firewall для TUN
- Отключение NCSI (3 уровня)
- Отключение Smart Multi-Homed Name Resolution
- Сброс кэша DNS

### Очистка при остановке
- Восстановление DNS физического адаптера
- Восстановление IPv6 на физическом адаптере
- Удаление маршрутов (включая persistent route)
- Восстановление реестра (NCSI, Smart DNS)
- Удаление правил Firewall
- Закрытие named pipe

### Очистка zombie-адаптеров
- При каждом `awarp up` удаляются zombie Wintun-адаптеры через `SetupDiRemoveDevice` (API Windows)
- Ищет адаптеры с именами "Wintun Userspace Tunnel" / "Wintun Userspace Tunnel #2" / "WireGuard Tunnel"
- Пропускает активный туннель (проверка IP 172.16.0.x)
- Логирует instance ID удалённых адаптеров

### Структуры данных
- `tunnelState` — сохраняется в `tunnel.state` для cross-process cleanup
- `Tunnel.phyIntf`, `Tunnel.phyDNS` — для восстановления настроек физического адаптера

## Неочевидные нюансы

- **Профили хранятся рядом с бинарником**, не в `$HOME`.
- **Парсинг флагов ручной** (`main.go:parseFlags`), не пакет `flag`.
- **Флаг `-a`** передаёт параметры обфускации AmneziaWG. s3/s4 игнорируются.
- **Флаг `--sni`** генерирует I1 из домена через `warp/quic.go:GenerateI1FromSNI`.
- **Флаг `--endpoint`** / `-e` — смена endpoint в профиле.
- **API версия** `v0a2158`. User-Agent: `okhttp/3.12.1`.
- **Interface name всегда `warp0`** — захардкожен.
- **Дефолтный порт 2408** — стандартный порт WireGuard WARP.
- **WARP keepalive может таймаутиться** — это нормально, туннель работает через UDP, а keepalive через TCP к api.cloudflareclient.com.
- **winws конфликтует с TUN** — WinDivert перехватывает пакеты Wintun. Нужно подбирать стратегию или не использовать winws с WARP.
- **Сканер требует `ping`** — использует `cmd /c chcp 65001` для UTF-8 вывода на русской Windows.
