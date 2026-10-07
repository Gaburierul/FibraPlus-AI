"""
Diagnóstico do Ravicor — mostra o corpo da resposta mesmo em caso de erro.
"""

import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()

RAVICOR_URL = os.getenv("RAVICOR_URL")
RAVICOR_TOKEN = os.getenv("RAVICOR_TOKEN")

data = {
    "token": RAVICOR_TOKEN,
    "action": "dispositivo",
    "operation": "list_groups",
}

print(f"URL: {RAVICOR_URL}")
print(f"Token length: {len(RAVICOR_TOKEN)} chars")
print(f"Payload: action=dispositivo, operation=list_groups")
print()

response = requests.post(RAVICOR_URL, data=data, timeout=15)

print(f"HTTP: {response.status_code}")
print(f"Content-Type: {response.headers.get('Content-Type', '?')}")
print(f"Body length: {len(response.text)} chars")
print()
print("--- RESPOSTA COMPLETA ---")
print(response.text[:2000])
