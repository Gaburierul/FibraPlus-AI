@echo off
title FibraPlus NOC - Painel de Investigacao Local (Porta 8090)

cd /d C:\FibraPlus-AI

echo Iniciando Painel Local de Investigacao NOC (http://127.0.0.1:8090)...
echo Este servico roda isolado da porta 8089 (Webhook / Ngrok).
echo.

start "" cmd /c "timeout /t 2 /nobreak > nul && start http://127.0.0.1:8090"
.\.venv\Scripts\python.exe -m uvicorn server.painel:app --host 127.0.0.1 --port 8090
