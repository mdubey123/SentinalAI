@echo off
title SentinelAI v2
echo Starting SentinelAI v2...
echo.

REM Check if virtual environment exists
if exist "env\Scripts\activate.bat" (
    echo Activating virtual environment...
    call env\Scripts\activate.bat
)

REM Start SentinelAI
echo Launching SentinelAI v2...
python -m streamlit run app.py --server.port 8501 --server.address localhost

echo.
echo SentinelAI v2 has stopped.
pause
