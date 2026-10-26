@echo off
title Inicializador NOC FibraPlus - Telegram / Webhook

cd /d C:\FibraPlus-AI

echo [1/3] Iniciando Servidor Webhook (Porta 8089)...
start "1. NOC - Servidor Webhook (Porta 8089)" cmd /k "cd /d C:\FibraPlus-AI && .\.venv\Scripts\python.exe -m uvicorn server.webhook:app --host 127.0.0.1 --port 8089 --reload"
timeout /t 4 /nobreak > nul

echo [2/3] Iniciando Tunel Ngrok (Porta 8089)...
start "2. NOC - Tunel Ngrok" cmd /k "cd /d C:\FibraPlus-AI && ngrok http 8089"
timeout /t 5 /nobreak > nul

echo [3/3] Iniciando Poller do Zabbix com Envio Real...
start "3. NOC - Poller Zabbix (Envio Real)" cmd /k "cd /d C:\FibraPlus-AI && .\.venv\Scripts\python.exe scripts\poller_zabbix.py --permitir-envio-real"

echo.
echo Todos os 3 servicos foram iniciados em janelas separadas!
timeout /t 5
