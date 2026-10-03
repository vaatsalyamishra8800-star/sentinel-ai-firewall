@echo off
title Sentinel AI Firewall - Allow Port 8080
color 0b
echo =========================================================================
echo   SENTINEL AI GATEWAY v3.0 - MULTI-DEVICE FIREWALL CONFIGURATOR
echo =========================================================================
echo.
echo Attempting to add Inbound Windows Firewall Rule for Port 8080...
echo.

netsh advfirewall firewall add rule name="Sentinel Gateway 8080" dir=in action=allow protocol=TCP localport=8080 profile=any

if %ERRORLEVEL% EQU 0 (
    color 0a
    echo.
    echo =========================================================================
    echo  [SUCCESS] Windows Defender Firewall has allowed inbound traffic on 8080!
    echo =========================================================================
    echo.
    echo  You can now access the Sentinel Dashboard from any device on your Wi-Fi:
    echo.
    echo    URL: http://172.16.27.250:8080/
    echo.
    echo =========================================================================
) else (
    color 0c
    echo.
    echo =========================================================================
    echo  [ERROR] Administrative permissions required!
    echo =========================================================================
    echo  Please right-click "allow_firewall.bat" and select:
    echo  "Run as administrator"
    echo =========================================================================
)
echo.
pause
