@echo off
title Push Sentinel to GitHub
color 0b
echo =========================================================================
echo   SENTINEL AI GATEWAY - 1-CLICK GITHUB SYNC
echo =========================================================================
echo.
echo Target Repository: https://github.com/vaatsalyamishra8800-star/sentinel-ai-firewall.git
echo.
set "DEFAULT_URL=https://github.com/vaatsalyamishra8800-star/sentinel-ai-firewall.git"
set /p REPO_URL="Press Enter to push to default repository (or enter a custom URL): "

if "%REPO_URL%"=="" set "REPO_URL=%DEFAULT_URL%"

echo.
echo [*] Staging all files...
git add .
git commit -m "Update Sentinel AI Gateway" >nul 2>nul
git remote set-url origin %REPO_URL%
git branch -M main

echo [*] Pushing to %REPO_URL%...
git push -u origin main

if %ERRORLEVEL% EQU 0 (
    echo.
    echo =========================================================================
    echo   [SUCCESS] Code synchronized with GitHub successfully!
    echo =========================================================================
    echo.
    echo Render will automatically pick up changes and redeploy within 60 seconds!
    echo.
) else (
    echo.
    echo [ERROR] Git push failed. Please check your GitHub permissions or network.
)

pause
