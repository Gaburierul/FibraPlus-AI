"""
Teste de autenticação e consulta à API do Ravicor.

Usa action=dispositivo + operation=list_groups (somente leitura)
para listar grupos de dispositivos e validar que o token funciona.

A API do Ravicor NÃO usa Authorization: Bearer.
O token é enviado como parâmetro POST junto com action e operation.
"""

import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()

RAVICOR_URL = os.getenv("RAVICOR_URL")
RAVICOR_TOKEN = os.getenv("RAVICOR_TOKEN")

if not RAVICOR_URL or not RAVICOR_TOKEN:
    raise SystemExit(
        "❌  RAVICOR_URL e/ou RAVICOR_TOKEN não definidos no .env"
    )

OPERATION = "list_groups"

data = {
    "token": RAVICOR_TOKEN,
    "action": "dispositivo",
    "operation": OPERATION,
}

print(f"→ POST {RAVICOR_URL}")
print(f"  action: dispositivo")
print(f"  operation: {OPERATION}\n")

try:
    response = requests.post(
        RAVICOR_URL,
        data=data,
        timeout=15,
    )
    print(f"HTTP: {response.status_code}")
    response.raise_for_status()
    print(json.dumps(response.json(), indent=4, ensure_ascii=False))

except requests.exceptions.HTTPError as exc:
    print(f"\n❌  HTTP Error: {exc}")
except requests.exceptions.ConnectionError:
    print("\n❌  Não foi possível conectar ao Ravicor. Verifique a URL.")
except requests.exceptions.Timeout:
    print("\n❌  Timeout — o servidor não respondeu em 15 s.")
except json.JSONDecodeError:
    print(f"\n⚠️  Resposta não é JSON válido:")
    print(response.text[:500])
except Exception as exc:
    print(f"\n❌  Erro inesperado: {exc}")
