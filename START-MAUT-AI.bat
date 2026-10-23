
@echo off
setlocal
cd /d "%~dp0"
title Maut AI - Local Ollama

echo.
echo ========================================
echo       MAUT AI - FREE LOCAL AI
echo ========================================
echo.

if not exist "package.json" (
  echo ERROR: package.json was not found.
  echo Extract the entire ZIP archive first.
  goto finish
)

where node >nul 2>nul
if errorlevel 1 (
  echo ERROR: Node.js is not installed.
  echo Install it from https://nodejs.org/
  goto finish
)

where ollama >nul 2>nul
if errorlevel 1 (
  echo ERROR: Ollama is not installed or not in PATH.
  goto finish
)

if not exist ".env" (
  copy ".env.example" ".env" >nul
)

echo Checking Qwen 2.5 0.5B model...
ollama list | findstr /i "qwen2.5:0.5b" >nul
if errorlevel 1 (
  echo ERROR: Model qwen2.5:0.5b was not found.
  echo Open CMD and run: ollama run qwen2.5:0.5b
  goto finish
)

echo Installing app packages if needed...
call npm.cmd install
if errorlevel 1 (
  echo ERROR: Package installation failed.
  goto finish
)

echo.
echo Starting Maut AI at http://localhost:3000
echo Keep this window open while using Maut AI.
start "" "http://localhost:3000"
call npm.cmd start

echo.
echo Maut AI has stopped.

:finish
echo.
pause
