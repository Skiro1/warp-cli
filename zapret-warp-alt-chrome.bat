@echo off
chcp 65001 > nul
setlocal enabledelayedexpansion

cd /d "%~dp0"
call service.bat status_zapret
call service.bat check_updates
call service.bat load_game_filter
call service.bat load_user_lists
echo:

set "BIN=%~dp0bin\"
set "LISTS=%~dp0lists\"
cd /d "%BIN%"

:: Detect WARP TUN interface index
set "WARP_IDX="
for /f "tokens=1" %%i in ('netsh int ip show interfaces 2^>nul ^| findstr /i "warp0\|WireGuard Tunnel"') do set "WARP_IDX=%%i"

:: Detect physical interface index (first connected non-TUN interface with gateway)
set "PHY_IDX="
for /f "tokens=1,5" %%a in ('netsh int ip show interfaces 2^>nul ^| findstr /i "connected"') do (
    set "CANDIDATE_IDX=%%a"
    set "CANDIDATE_NAME=%%b"
    if /i not "!CANDIDATE_NAME!"=="warp0" if /i not "!CANDIDATE_NAME!"=="WireGuard" (
        if not defined PHY_IDX set "PHY_IDX=!CANDIDATE_IDX!"
    )
)

:: Build interface filter for WinDivert
set "IFACE_FILTER="
if defined WARP_IDX (
    echo [zapret-warp] WARP TUN interface index: %WARP_IDX%
    if defined PHY_IDX (
        echo [zapret-warp] Physical interface index: %PHY_IDX%
        echo [zapret-warp] Binding WinDivert to physical interface only (excluding TUN)
        set "IFACE_FILTER=--wf-iface=!PHY_IDX!"
    ) else (
        echo [zapret-warp] WARNING: Could not detect physical interface index
        echo [zapret-warp] WinDivert will capture on ALL interfaces including TUN
        echo [zapret-warp] To fix manually: run "netsh int ip show int" and add --wf-iface^=<physical_index^> to winws command below
    )
) else (
    echo [zapret-warp] WARP TUN not found, running without interface binding
)

echo [zapret-warp] Starting winws (ALT strategy, Chrome-compatible)...
echo [zapret-warp] Google/YouTube uses fake (not fakedsplit) for Chrome compatibility
start "zapret: %~n0" /min "%BIN%winws.exe" %IFACE_FILTER% --wf-tcp=80,443,2053,2083,2087,2096,8443,%GameFilterTCP% --wf-udp=443,19294-19344,50000-50100,%GameFilterUDP% ^
--filter-udp=443 --hostlist="%LISTS%list-general.txt" --hostlist="%LISTS%list-general-user.txt" --hostlist-exclude="%LISTS%list-exclude.txt" --hostlist-exclude="%LISTS%list-exclude-user.txt" --ipset-exclude="%LISTS%ipset-exclude.txt" --ipset-exclude="%LISTS%ipset-exclude-user.txt" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic="%BIN%quic_initial_www_google_com.bin" --new ^
--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-fake-discord="%BIN%quic_initial_dbankcloud_ru.bin" --dpi-desync-fake-stun="%BIN%quic_initial_dbankcloud_ru.bin" --dpi-desync-repeats=6 --new ^
--filter-tcp=2053,2083,2087,2096,8443 --hostlist-domains=discord.media --dpi-desync=fake,fakedsplit --dpi-desync-repeats=6 --dpi-desync-fooling=ts --dpi-desync-fakedsplit-pattern=0x00 --dpi-desync-fake-tls="%BIN%tls_clienthello_www_google_com.bin" --new ^
--filter-tcp=443 --hostlist="%LISTS%list-google.txt" --ip-id=zero --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-tls="%BIN%tls_clienthello_www_google_com.bin" --new ^
--filter-tcp=80,443 --hostlist="%LISTS%list-general.txt" --hostlist="%LISTS%list-general-user.txt" --hostlist-exclude="%LISTS%list-exclude.txt" --hostlist-exclude="%LISTS%list-exclude-user.txt" --ipset-exclude="%LISTS%ipset-exclude.txt" --ipset-exclude="%LISTS%ipset-exclude-user.txt" --dpi-desync=fake,fakedsplit --dpi-desync-repeats=6 --dpi-desync-fooling=ts --dpi-desync-fakedsplit-pattern=0x00 --dpi-desync-fake-tls="%BIN%stun.bin" --dpi-desync-fake-tls="%BIN%tls_clienthello_www_google_com.bin" --dpi-desync-fake-http="%BIN%tls_clienthello_max_ru.bin" --new ^
--filter-udp=443 --ipset="%LISTS%ipset-all.txt" --hostlist-exclude="%LISTS%list-exclude.txt" --hostlist-exclude="%LISTS%list-exclude-user.txt" --ipset-exclude="%LISTS%ipset-exclude.txt" --ipset-exclude="%LISTS%ipset-exclude-user.txt" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic="%BIN%quic_initial_www_google_com.bin" --new ^
--filter-tcp=80,443,8443 --ipset="%LISTS%ipset-all.txt" --hostlist-exclude="%LISTS%list-exclude.txt" --hostlist-exclude="%LISTS%list-exclude-user.txt" --ipset-exclude="%LISTS%ipset-exclude.txt" --ipset-exclude="%LISTS%ipset-exclude-user.txt" --dpi-desync=fake,fakedsplit --dpi-desync-repeats=6 --dpi-desync-fooling=ts --dpi-desync-fakedsplit-pattern=0x00 --dpi-desync-fake-tls="%BIN%stun.bin" --dpi-desync-fake-tls="%BIN%tls_clienthello_www_google_com.bin" --dpi-desync-fake-http="%BIN%tls_clienthello_max_ru.bin" --new ^
--filter-tcp=%GameFilterTCP% --ipset="%LISTS%ipset-all.txt" --ipset-exclude="%LISTS%ipset-exclude.txt" --ipset-exclude="%LISTS%ipset-exclude-user.txt" --dpi-desync=fake,fakedsplit --dpi-desync-repeats=6 --dpi-desync-any-protocol=1 --dpi-desync-cutoff=n4 --dpi-desync-fooling=ts --dpi-desync-fakedsplit-pattern=0x00 --dpi-desync-fake-tls="%BIN%stun.bin" --dpi-desync-fake-tls="%BIN%tls_clienthello_www_google_com.bin" --dpi-desync-fake-http="%BIN%tls_clienthello_max_ru.bin" --new ^
--filter-udp=%GameFilterUDP% --ipset="%LISTS%ipset-all.txt" --ipset-exclude="%LISTS%ipset-exclude.txt" --ipset-exclude="%LISTS%ipset-exclude-user.txt" --dpi-desync=fake --dpi-desync-repeats=12 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp="%BIN%quic_initial_dbankcloud_ru.bin" --dpi-desync-cutoff=n3
