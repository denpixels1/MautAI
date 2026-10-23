@echo off
setlocal
 title Maut AI - Download local model
 echo.
echo ========================================
echo      DOWNLOAD FREE LOCAL AI MODEL
echo ========================================
echo.
where ollama >nul 2>nul
if errorlevel 1 (
  echo Ollama is not installed or not in PATH.
  echo Download and install it from https://ollama.com/download/windows
  echo After installation, close this window and run this file again.
  goto finish
)
echo Downloading Qwen 2.5 3B. This is several GB and may take a while.
echo You only need to do this once.
echo.
ollama pull qwen2.5:3b
if errorlevel 1 (
  echo Model download failed. Check your internet connection and try again.
  goto finish
)
echo.
echo Model downloaded successfully!
echo Now double-click START-MAUT-AI.bat.
:finish
echo.
pause
