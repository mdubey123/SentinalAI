@echo off
title SentinelAI v2 - Development Mode
echo.
echo ========================================
echo    SentinelAI v2 - Development Mode
echo ========================================
echo.

REM Activate virtual environment
if exist "env\Scripts\activate.bat" (
    call env\Scripts\activate.bat
)

REM Start in development mode with auto-reload
python -m streamlit run app.py --server.port 8501 --server.address localhost --server.runOnSave true

pause
