# awarp

CLI-утилита для создания **Cloudflare WARP VPN-тоннеля** через **AmneziaWG** (обфусцированный форк WireGuard) на Windows.

**English:** [README-en.md](README-en.md)

## Возможности

- Регистрация в Cloudflare WARP и управление ключами
- AmneziaWG-тоннель с параметрами обфускации (jc, jmin, jmax, s1-s4, h1-h4, i1-i5)
- WFP firewall (kill switch)
- Сканер эндпоинтов для поиска самого быстрого сервера WARP
- Интеграция с Запретом (winws) через привязку `--wf-iface`

## Требования

- Windows 10/11
- Права администратора (для `awarp up`)
- `wintun.dll` рядом с бинарником

## Сборка

```cmd
go build -o awarp.exe .
```

## Использование

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

### Примеры

```cmd
:: Регистрация и подключение
awarp register
awarp up

:: Сканирование быстрого эндпоинта
awarp scan

:: Смена эндпоинта
awarp config set --endpoint 162.159.192.179:2408

:: Переподключение с новым эндпоинтом
awarp down && awarp up

:: Использование с Запретом (winws)
awarp up
zapret-warp.bat
```

## Параметры AWG

| Параметр | Описание |
|----------|----------|
| `jc` | Количество junk-пакетов |
| `jmin`, `jmax` | Диапазон размеров junk-пакетов |
| `s1`-`s4` | Заполнение сообщений |
| `h1`-`h4` | Заголовки сообщений |
| `i1`-`i5` | Пользовательские пакеты подписи |

## Эндпоинты

Дефолтный: `engage.cloudflareclient.com:2408`

Подсети WARP WireGuard:
- `162.159.192.0/24`
- `162.159.193.0/24`

Порт: UDP 2408 (резервные: 500, 1701, 4500)

## Интеграция с Запретом (winws)

### Проблема

При запуске winws (GoodbyeDPI/Запрет) вместе с WARP браузеры показывают "Нет интернета" и сайты не грузятся. Причина:

1. WinDivert (используется winws) перехватывает пакеты на ВСЕХ сетевых интерфейсах
2. WARP создаёт TUN-интерфейс (`warp0`), который обрабатывает весь трафик
3. Windows NCSI отправляет HTTP-запросы через TUN
4. WinDivert ломает эти запросы → Windows думает, что интернета нет
5. curl и Telegram работают, потому что используют свой стек (Winsock)

### Симптомы

- `curl https://youtube.com` работает
- Telegram работает
- Браузер показывает "Нет интернета", YouTube не грузится
- winws + WARP = браузер полностью не работает

### Решение

Использовать `--wf-iface=<индекс_физического_интерфейса>` для привязки WinDivert только к физическому сетевому интерфейсу, исключая TUN.

### Быстрый старт

1. Скопируйте `zapret-warp-alt-chrome.bat` в директорию запрета (например, `D:\zapret\`)
2. Запустите WARP:
   ```cmd
   awarp up
   ```
3. Запустите запрет (в отдельном терминале):
   ```cmd
   D:\zapret\zapret-warp-alt-chrome.bat
   ```
4. Остановка:
   ```cmd
   awarp down
   taskkill /F /IM winws.exe
   ```

### Как это работает

Bat-файл автоматически определяет сетевые интерфейсы:
1. Находит индекс TUN-интерфейса (`warp0`) через `netsh int ip show interfaces`
2. Находит индекс физического интерфейса (первый подключённый не-TUN интерфейс)
3. Добавляет `--wf-iface=<индекс_физического>` к аргументам winws
4. WinDivert захватывает пакеты ТОЛЬКО на физическом интерфейсе, игнорируя TUN

### Ручное исправление других bat-файлов

Если вы хотите использовать другую стратегию запрета (ALT1, ALT2 и т.д.) с WARP:

**Шаг 1:** Добавьте этот код после `set "LISTS=%~dp0lists\"` и перед `cd /d %BIN%`:

```bat
setlocal enabledelayedexpansion
set "PHY_IDX="
for /f "skip=1 tokens=1" %%a in ('netsh int ip show interfaces 2^>nul ^| findstr /i "connected"') do (
    if not defined PHY_IDX set "PHY_IDX=%%a"
)
set "IFACE_FILTER="
if defined PHY_IDX set "IFACE_FILTER=--wf-iface=!PHY_IDX!"
```

**Шаг 2:** Добавьте `%IFACE_FILTER%` перед `--wf-tcp` в команде winws:

```bat
:: До (ломается с WARP):
start "zapret: %~n0" /min "%BIN%winws.exe" --wf-tcp=80,443,...

:: После (работает с WARP):
start "zapret: %~n0" /min "%BIN%winws.exe" %IFACE_FILTER% --wf-tcp=80,443,...
```

### Траблшутинг

Если всё ещё не работает:
1. Проверьте, что winws запущен: `tasklist | find winws`
2. Проверьте индекс физического интерфейса: `netsh int ip show interfaces`
3. Убедитесь, что `--wf-iface` есть в командной строке winws
4. Попробуйте запустить winws вручную (не через bat), чтобы увидеть сообщения об ошибках

## Лицензия

MIT
