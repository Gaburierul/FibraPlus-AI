"""
Teste de autenticação e consulta à API do Zabbix.

Faz host.get (recurso protegido) para validar que o token
realmente funciona — diferente de apiinfo.version que não exige auth.
"""

import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()

ZABBIX_URL = os.getenv("ZABBIX_URL")
ZABBIX_TOKEN = os.getenv("ZABBIX_TOKEN")

if not ZABBIX_URL or not ZABBIX_TOKEN:
    raise SystemExit(
        "❌  ZABBIX_URL e/ou ZABBIX_TOKEN não definidos no .env"
    )

payload = {
    "jsonrpc": "2.0",
    "method": "host.get",
    "params": {
        "output": ["hostid", "host", "name"],
        "limit": 10,
    },
    "id": 1,
}

headers = {
    "Authorization": f"Bearer {ZABBIX_TOKEN}",
    "Content-Type": "application/json-rpc",
}

print(f"→ POST {ZABBIX_URL}")
print(f"  method: host.get  (limit 10)\n")

try:
    response = requests.post(
        ZABBIX_URL,
        headers=headers,
        json=payload,
        timeout=15,
    )
    print(f"HTTP: {response.status_code}")
    response.raise_for_status()

    data = response.json()
    print(json.dumps(data, indent=4, ensure_ascii=False))

    # Resumo rápido
    if "result" in data:
        hosts = data["result"]
        print(f"\n✅  Sucesso! {len(hosts)} host(s) retornado(s).")
    elif "error" in data:
        err = data["error"]
        print(f"\n❌  Erro da API: {err.get('message', '')} — {err.get('data', '')}")
    else:
        print("\n⚠️  Resposta inesperada (sem 'result' nem 'error').")

except requests.exceptions.HTTPError as exc:
    print(f"\n❌  HTTP Error: {exc}")
except requests.exceptions.ConnectionError:
    print("\n❌  Não foi possível conectar ao Zabbix. Verifique a URL.")
except requests.exceptions.Timeout:
    print("\n❌  Timeout — o servidor não respondeu em 15 s.")
except Exception as exc:
    print(f"\n❌  Erro inesperado: {exc}")
