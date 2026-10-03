@echo off
title Push Sentinel to GitHub
color 0b
echo =========================================================================
echo   SENTINEL AI GATEWAY - PUSH TO GITHUB FOR 24/7 CLOUD HOSTING
echo =========================================================================
echo.
echo 1. Go to https://github.com/new and create a new repository
echo    (Name it: sentinel-ai-firewall, keep it Public or Private)
echo.
set /p REPO_URL="Enter your GitHub Repository URL (e.g. https://github.com/username/sentinel-ai-firewall.git): "

if "%REPO_URL%"=="" (
    echo [ERROR] No URL entered.
    pause
    exit /b 1
)

git remote remove origin >nul 2>nul
git remote add origin %REPO_URL%
git branch -M main
git push -u origin main

if %ERRORLEVEL% EQU 0 (
    echo.
    echo =========================================================================
    echo   [SUCCESS] Code pushed to GitHub successfully!
    echo =========================================================================
    echo.
    echo Next step:
    echo 1. Go to https://dashboard.render.com
    echo 2. Click "New +" -> "Web Service"
    echo 3. Select this repository and click "Deploy Web Service"!
    echo.
) else (
    echo.
    echo [ERROR] Git push failed. Please check your GitHub permissions or URL.
)

pause
