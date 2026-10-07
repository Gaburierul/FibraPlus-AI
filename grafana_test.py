"""
Teste de autenticação e descoberta de dashboards no Grafana.

Etapa 1 — /api/user       → valida o Service Account Token.
Etapa 2 — /api/search      → lista dashboards/pastas disponíveis.
"""

import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()

GRAFANA_URL = os.getenv("GRAFANA_URL")
GRAFANA_TOKEN = os.getenv("GRAFANA_TOKEN")

if not GRAFANA_URL or not GRAFANA_TOKEN:
    raise SystemExit(
        "❌  GRAFANA_URL e/ou GRAFANA_TOKEN não definidos no .env"
    )

headers = {
    "Authorization": f"Bearer {GRAFANA_TOKEN}",
    "Accept": "application/json",
}


def test_user():
    """Etapa 1 — testar autenticação via /api/user."""
    url = f"{GRAFANA_URL}/api/user"
    print(f"═══ Etapa 1: GET {url}")
    resp = requests.get(url, headers=headers, timeout=15)
    print(f"HTTP: {resp.status_code}")
    resp.raise_for_status()
    data = resp.json()
    print(json.dumps(data, indent=4, ensure_ascii=False))

    login = data.get("login", "?")
    print(f"\n✅  Autenticado como: {login}\n")
    return True


def test_search():
    """Etapa 2 — listar dashboards via /api/search."""
    url = f"{GRAFANA_URL}/api/search"
    print(f"═══ Etapa 2: GET {url}")
    resp = requests.get(url, headers=headers, timeout=15)
    print(f"HTTP: {resp.status_code}")
    resp.raise_for_status()
    data = resp.json()
    print(json.dumps(data, indent=4, ensure_ascii=False))

    if isinstance(data, list):
        print(f"\n✅  {len(data)} item(ns) encontrado(s) (dashboards + pastas).")
        for item in data[:15]:
            kind = item.get("type", "?")
            title = item.get("title", "sem título")
            print(f"    [{kind}]  {title}")
    else:
        print("\n⚠️  Resposta inesperada (esperava uma lista).")


# ── Execução ──────────────────────────────────────────────
try:
    if test_user():
        test_search()
except requests.exceptions.HTTPError as exc:
    print(f"\n❌  HTTP Error: {exc}")
except requests.exceptions.ConnectionError:
    print("\n❌  Não foi possível conectar ao Grafana. Verifique a URL.")
except requests.exceptions.Timeout:
    print("\n❌  Timeout — o servidor não respondeu em 15 s.")
except Exception as exc:
    print(f"\n❌  Erro inesperado: {exc}")
