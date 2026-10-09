"""
Simula o Zabbix enviando alertas ao webhook — para testar sem mexer no Zabbix.

Uso (com o servidor rodando em outro terminal):
    python scripts/simular_webhook.py                 # cenário padrão (queda + resolução)
    python scripts/simular_webhook.py --url http://127.0.0.1:8089/zabbix/webhook
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import requests
from dotenv import load_dotenv

RAIZ = Path(__file__).resolve().parent.parent
load_dotenv(RAIZ / ".env")


def evento(eid: int, host: str, ip: str, nome: str, nsev: int, inicio: datetime,
           tags: list[dict], fim: datetime | None = None) -> dict:
    return {
        "event_id": str(eid),
        "event_value": "0" if fim else "1",
        "event_update_status": "0",
        "host_name": host,
        "host_ip": ip,
        "event_name": nome,
        "event_nseverity": str(nsev),
        "event_severity": "",
        "event_date": inicio.strftime("%Y.%m.%d"),
        "event_time": inicio.strftime("%H:%M:%S"),
        "recovery_date": fim.strftime("%Y.%m.%d") if fim else "{EVENT.RECOVERY.DATE}",
        "recovery_time": fim.strftime("%H:%M:%S") if fim else "{EVENT.RECOVERY.TIME}",
        "event_duration": f"{int((fim - inicio).total_seconds())}s" if fim else "",
        "event_tags_json": json.dumps(tags),
    }


def cenario() -> list[dict]:
    t0 = datetime.now().replace(microsecond=0) - timedelta(minutes=2)
    bb1 = [{"tag": "backbone", "value": "1"}]
    return [
        evento(1001, "EXEMPLO-IDC-HUAWEI-PE01", "192.0.2.1", "Interface 100GE0/0/3(): Link down", 3, t0, bb1),
        evento(1002, "EXEMPLO-IDC-HUAWEI-PE02", "192.0.2.2", "Interface 100GE0/0/1(): Link down", 3,
               t0 + timedelta(seconds=8), bb1),
        evento(1003, "EXEMPLO-IDC-HUAWEI-PE02", "192.0.2.2", "OSPF: Interface 192.0.2.249 em estado Down", 2,
               t0 + timedelta(seconds=12), [{"tag": "backbone", "value": "2"}, {"tag": "component", "value": "ospf"}]),
        evento(1004, "CPE-EXEMPLO-HUAWEI-EDGE01", "192.0.2.10", "198.51.100.205 não está ESTABLISHED", 5,
               t0 + timedelta(seconds=20), [{"tag": "edge", "value": "1"}]),
        evento(1004, "CPE-EXEMPLO-HUAWEI-EDGE01", "192.0.2.10", "198.51.100.205 não está ESTABLISHED", 5,
               t0 + timedelta(seconds=20), [{"tag": "edge", "value": "1"}]),  # duplicata proposital
        evento(1005, "EXEMPLO-ZTE-OLT01", "192.0.2.5", "Cliente: Exemplo -> Esta down : -80", 3,
               t0 + timedelta(seconds=25), [{"tag": "Application", "value": "ONU"}]),
        evento(1003, "EXEMPLO-IDC-HUAWEI-PE02", "192.0.2.2", "OSPF: Interface 192.0.2.249 em estado Down", 2,
               t0 + timedelta(seconds=12), [{"tag": "backbone", "value": "2"}, {"tag": "component", "value": "ospf"}],
               fim=t0 + timedelta(seconds=70)),
    ]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8089/zabbix/webhook")
    ap.add_argument("--intervalo", type=float, default=1.0, help="segundos entre envios")
    args = ap.parse_args()

    partes_url = urlsplit(args.url)
    health_url = urlunsplit((partes_url.scheme, partes_url.netloc, "/health", "", ""))
    try:
        health = requests.get(health_url, timeout=5)
        health.raise_for_status()
        estado = health.json()
    except (requests.RequestException, ValueError):
        print("Não foi possível confirmar o modo de teste do webhook; simulação cancelada.", file=sys.stderr)
        return 1
    if not isinstance(estado, dict) or estado.get("modo_teste") is not True:
        print("O webhook não está em MODO_TESTE=true; simulação cancelada para evitar envio real.", file=sys.stderr)
        return 1

    token = os.getenv("WEBHOOK_TOKEN", "")
    if not token:
        print("WEBHOOK_TOKEN ausente no .env", file=sys.stderr)
        return 1
    for ev in cenario():
        r = requests.post(args.url, json=ev, headers={"X-Webhook-Token": token}, timeout=10)
        print(f"{r.status_code} {ev['event_value']} {ev['host_name']}: {ev['event_name']} -> {r.text}")
        time.sleep(args.intervalo)
    print("\nEnvios concluídos. A análise sai no log do servidor após o tempo de silêncio (DEBOUNCE_SILENCIO_S).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
