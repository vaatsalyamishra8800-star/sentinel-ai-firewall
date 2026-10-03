@echo off
title Sentinel AI Gateway - Cloudflare Online Tunnel
color 0b
echo =========================================================================
echo   SENTINEL AI GATEWAY v3.0 - PUBLIC INTERNET TUNNEL LAUNCHER
echo =========================================================================
echo.

if not exist "%~dp0cloudflared.exe" (
    color 0c
    echo [ERROR] cloudflared.exe not found in this folder!
    pause
    exit /b 1
)

where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    python "%~dp0tunnel_manager.py"
) else (
    echo [NOTE] Python not found on PATH. Launching cloudflared directly...
    echo [NOTE] Watch the console below for your https://*.trycloudflare.com link!
    echo.
    "%~dp0cloudflared.exe" tunnel --url http://127.0.0.1:8080
)

pause
