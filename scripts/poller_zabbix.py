"""Consulta eventos do Zabbix e os encaminha ao webhook local do NOC.

Esta ponte não precisa de Media Type nem de uma Action no Zabbix. O token da
API precisa apenas ter acesso de leitura aos eventos/hosts monitorados.

Por segurança, o processo se recusa a operar contra o webhook em modo real sem
o argumento explícito --permitir-envio-real.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import requests
from dotenv import load_dotenv

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
load_dotenv(RAIZ / ".env")

from clients.zabbix import ZabbixClient  # noqa: E402
from noc.zabbix_event import payload_para_alerta, severidade_minima_ok  # noqa: E402

LOG = logging.getLogger("noc.zabbix_poller")
SEVERIDADES = {
    0: "Not classified", 1: "Information", 2: "Warning",
    3: "Average", 4: "High", 5: "Disaster",
}

try:
    FUSO = ZoneInfo("America/Campo_Grande")
except ZoneInfoNotFoundError:  # Windows sem a base IANA instalada
    FUSO = timezone(timedelta(hours=-4))


class EstadoPoller:
    """Cursor e início do primeiro backfill; persistidos entre reinicializações."""

    def __init__(self, caminho: Path, lookback_min: int):
        caminho.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(caminho, timeout=10)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS estado (chave TEXT PRIMARY KEY, valor TEXT NOT NULL)")
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS problemas_abertos (
                   objectid TEXT PRIMARY KEY, payload TEXT NOT NULL
               )"""
        )
        self.db.commit()
        if self.obter("inicio_backfill") is None and self.obter("ultimo_eventid") is None:
            self.gravar("inicio_backfill", str(int(time.time()) - lookback_min * 60))

    def obter(self, chave: str) -> str | None:
        row = self.db.execute("SELECT valor FROM estado WHERE chave=?", (chave,)).fetchone()
        return row[0] if row else None

    def gravar(self, chave: str, valor: str) -> None:
        self.db.execute("INSERT OR REPLACE INTO estado(chave, valor) VALUES(?, ?)", (chave, valor))
        self.db.commit()

    def problema_aberto(self, objectid: str) -> dict[str, Any] | None:
        row = self.db.execute(
            "SELECT payload FROM problemas_abertos WHERE objectid=?", (objectid,)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def salvar_problema_aberto(self, objectid: str, payload: dict[str, Any]) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO problemas_abertos(objectid, payload) VALUES(?, ?)",
            (objectid, json.dumps(payload, ensure_ascii=False)),
        )
        self.db.commit()

    def remover_problema_aberto(self, objectid: str) -> None:
        self.db.execute("DELETE FROM problemas_abertos WHERE objectid=?", (objectid,))
        self.db.commit()

    def fechar(self) -> None:
        self.db.close()


def _timestamp(valor: Any, campo: str) -> int:
    try:
        timestamp = int(valor)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Evento Zabbix com {campo} inválido") from exc
    if timestamp < 0:
        raise ValueError(f"Evento Zabbix com {campo} negativo")
    return timestamp


def _data_hora(timestamp: int) -> datetime:
    return datetime.fromtimestamp(timestamp, FUSO)


def _duracao(inicio: int, fim: int) -> str:
    segundos = max(0, fim - inicio)
    horas, resto = divmod(segundos, 3600)
    minutos, segundos = divmod(resto, 60)
    partes = []
    if horas:
        partes.append(f"{horas}h")
    if minutos or horas:
        partes.append(f"{minutos}m")
    partes.append(f"{segundos}s")
    return " ".join(partes)


def evento_para_payload(evento: dict[str, Any], aberto: dict[str, Any] | None = None) -> dict[str, Any]:
    event_id = str(evento.get("eventid", "")).strip()
    if not event_id.isdigit():
        raise ValueError("Evento Zabbix sem eventid numérico")
    valor = str(evento.get("value", "")).strip()
    if valor not in {"0", "1"}:
        raise ValueError(f"Evento {event_id} com value inválido")

    horario_evento = _data_hora(_timestamp(evento.get("clock"), "clock"))
    hosts = evento.get("hosts") or []
    host = next((h for h in hosts if isinstance(h, dict)), {})
    host_name = str(host.get("name") or host.get("host") or "Host não identificado").strip()
    event_name = str(evento.get("name") or "").strip()
    if not event_name:
        raise ValueError(f"Evento {event_id} sem nome de trigger")

    try:
        severidade = int(evento.get("severity", 0))
    except (TypeError, ValueError):
        severidade = 0
    if not 0 <= severidade <= 5:
        severidade = 0

    data_inicio = horario_evento if valor == "1" or aberto else None
    tags = evento.get("tags") or []
    tags_json = json.dumps(tags, ensure_ascii=False)
    duracao = ""
    if valor == "0" and aberto:
        try:
            data_inicio = _data_hora(int(aberto["_event_clock"]))
            severidade = int(aberto["event_nseverity"])
            event_name = str(aberto.get("event_name") or event_name)
            host_name = str(aberto.get("host_name") or host_name)
            tags_json = str(aberto.get("event_tags_json") or tags_json)
            duracao = _duracao(int(aberto["_event_clock"]), int(evento["clock"]))
        except (KeyError, TypeError, ValueError, OverflowError):
            # Um estado parcial não deve bloquear a entrega da resolução.
            data_inicio = None
            duracao = ""

    data_fim = horario_evento if valor == "0" else None
    return {
        "event_id": event_id,
        "event_value": valor,
        # event.get devolve transições de estado, não as atualizações/ACKs.
        "event_update_status": "0",
        "host_name": host_name,
        "host_ip": str(host.get("ip") or ""),
        "event_name": event_name,
        "event_nseverity": str(severidade),
        "event_severity": SEVERIDADES[severidade],
        "event_date": data_inicio.strftime("%Y.%m.%d") if data_inicio else "",
        "event_time": data_inicio.strftime("%H:%M:%S") if data_inicio else "",
        "recovery_date": data_fim.strftime("%Y.%m.%d") if data_fim else "",
        "recovery_time": data_fim.strftime("%H:%M:%S") if data_fim else "",
        "event_duration": duracao,
        "event_tags_json": tags_json,
    }


def validar_config(url: str, token: str) -> None:
    partes = urlsplit(url)
    if (partes.scheme not in {"http", "https"} or not partes.hostname or partes.username
            or partes.password or partes.query or partes.fragment):
        raise ValueError("URL do webhook deve ser HTTP(S), sem credenciais, query ou fragmento")
    if not url.rstrip("/").endswith("/zabbix/webhook"):
        raise ValueError("URL do webhook deve terminar em /zabbix/webhook")
    if not token.strip():
        raise ValueError("WEBHOOK_TOKEN ausente no .env")


def confirmar_modo_teste(url: str, permitir_real: bool) -> None:
    health_url = url.rsplit("/zabbix/webhook", 1)[0].rstrip("/") + "/health"
    try:
        resposta = requests.get(health_url, timeout=5)
        resposta.raise_for_status()
        health = resposta.json()
    except (requests.RequestException, ValueError) as exc:
        raise RuntimeError(f"Webhook indisponível ou resposta inválida ({type(exc).__name__})") from None
    if not isinstance(health, dict) or health.get("status") != "ok":
        raise RuntimeError("Webhook não confirmou estado saudável")
    if health.get("modo_teste") is not True and not permitir_real:
        raise RuntimeError(
            "Webhook está em modo real; use --permitir-envio-real somente quando quiser autorizar envios"
        )
    LOG.info("Webhook acessível | modo_teste=%s | IA no teste=%s",
             health.get("modo_teste"), health.get("ia_no_teste"))


def enviar_evento(url: str, token: str, payload: dict[str, Any]) -> str:
    try:
        resposta = requests.post(
            url, json=payload, headers={"X-Webhook-Token": token}, timeout=15
        )
    except requests.RequestException as exc:
        # A confirmação pode ter se perdido depois de o servidor aceitar o POST;
        # o cursor não avança, então a próxima leitura prioriza não perder evento.
        raise RuntimeError(f"Falha de conexão com webhook ({type(exc).__name__})") from None
    if resposta.status_code != 202:
        raise RuntimeError(f"Webhook recusou evento (HTTP {resposta.status_code})")
    try:
        corpo = resposta.json()
    except ValueError:
        raise RuntimeError("Webhook respondeu 202 sem JSON de confirmação") from None
    estado = corpo.get("status") if isinstance(corpo, dict) else None
    if estado not in {"na_fila", "duplicado", "ignorado"}:
        raise RuntimeError("Webhook retornou confirmação inesperada")
    return estado


def processar_pagina(client: ZabbixClient, estado: EstadoPoller, url: str, token: str,
                     limite: int, severidade_minima: int) -> tuple[int, int, bool]:
    cursor = estado.obter("ultimo_eventid")
    if cursor is None:
        inicio = int(estado.obter("inicio_backfill") or int(time.time()))
        eventos = client.get_trigger_events(limit=limite, time_from=inicio)
    else:
        eventos = client.get_trigger_events(limit=limite, eventid_from=int(cursor) + 1)

    enviados = ignorados = 0
    for evento in eventos:
        event_id = str(evento.get("eventid", "")).strip()
        if not event_id.isdigit():
            raise RuntimeError("Zabbix retornou evento sem eventid; cursor preservado")
        objectid = str(evento.get("objectid", "")).strip()
        valor = str(evento.get("value", "")).strip()
        if valor not in {"0", "1"}:
            raise RuntimeError(f"Evento {event_id} tem estado inválido; cursor preservado")

        aberto = estado.problema_aberto(objectid) if valor == "0" and objectid else None
        payload = evento_para_payload(evento, aberto=aberto)
        alerta = payload_para_alerta(payload)
        severidade_referencia = alerta.severidade
        if aberto and valor == "0":
            try:
                severidade_referencia = int(aberto["event_nseverity"])
            except (KeyError, TypeError, ValueError):
                pass

        # Um evento ignorado por severidade ainda avança o cursor. Resolução de
        # alerta previamente aceito usa a severidade original do problema.
        deve_enviar = severidade_referencia >= severidade_minima
        if deve_enviar:
            estado_envio = enviar_evento(url, token, payload)
            enviados += estado_envio != "ignorado"
            ignorados += estado_envio == "ignorado"
            LOG.info("eventid=%s valor=%s host=%s severidade=%s resultado=%s",
                     event_id, valor, alerta.equipamento, severidade_referencia, estado_envio)
        else:
            ignorados += 1
            LOG.info("eventid=%s ignorado pela severidade mínima (%s < %s)",
                     event_id, severidade_referencia, severidade_minima)

        if valor == "1" and objectid:
            payload_aberto = dict(payload)
            payload_aberto["_event_clock"] = _timestamp(evento.get("clock"), "clock")
            estado.salvar_problema_aberto(objectid, payload_aberto)
        elif valor == "0" and objectid:
            estado.remover_problema_aberto(objectid)
        estado.gravar("ultimo_eventid", event_id)

    return enviados, ignorados, len(eventos) >= limite


def _inteiro_env(nome: str, padrao: int, minimo: int, maximo: int) -> int:
    bruto = os.getenv(nome)
    try:
        valor = int(bruto) if bruto and bruto.strip() else padrao
    except ValueError as exc:
        raise ValueError(f"{nome} deve ser um inteiro") from exc
    if not minimo <= valor <= maximo:
        raise ValueError(f"{nome} deve estar entre {minimo} e {maximo}")
    return valor


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, OSError):
            pass
    parser = argparse.ArgumentParser(description="Encaminha transições de trigger do Zabbix ao webhook NOC.")
    parser.add_argument("--uma-vez", action="store_true", help="consulta uma página e encerra")
    parser.add_argument("--permitir-envio-real", action="store_true",
                        help="permite operar se o webhook estiver em MODO_TESTE=false")
    parser.add_argument("--url", default=os.getenv(
        "NOC_WEBHOOK_URL", "http://127.0.0.1:8089/zabbix/webhook"))
    parser.add_argument("--intervalo", type=int, default=_inteiro_env(
        "NOC_ZABBIX_POLL_INTERVAL_S", 30, 5, 3600), help="intervalo entre consultas, em segundos")
    parser.add_argument("--lookback", type=int, default=_inteiro_env(
        "NOC_ZABBIX_INITIAL_LOOKBACK_MIN", 5, 0, 1440),
        help="minutos consultados na primeira execução sem cursor")
    parser.add_argument("--severidade-minima", type=int, default=_inteiro_env(
        "NOC_ZABBIX_SEVERIDADE_MINIMA", 2, 0, 5))
    parser.add_argument("--limite", type=int, default=500, help="eventos por consulta (1 a 10000)")
    parser.add_argument("--estado", type=Path, default=RAIZ / "logs" / "zabbix_poller.sqlite3",
                        help="arquivo SQLite do cursor e problemas abertos")
    args = parser.parse_args()

    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if not 5 <= args.intervalo <= 3600:
        parser.error("--intervalo deve estar entre 5 e 3600")
    if not 0 <= args.lookback <= 1440:
        parser.error("--lookback deve estar entre 0 e 1440")
    if not 0 <= args.severidade_minima <= 5:
        parser.error("--severidade-minima deve estar entre 0 e 5")
    if not 1 <= args.limite <= 10000:
        parser.error("--limite deve estar entre 1 e 10000")

    token = os.getenv("WEBHOOK_TOKEN", "")
    try:
        validar_config(args.url, token)
        confirmar_modo_teste(args.url, args.permitir_envio_real)
        client = ZabbixClient()
    except Exception as exc:
        LOG.error("Configuração/conectividade inicial inválida: %s", exc)
        return 2

    estado = EstadoPoller(args.estado, args.lookback)
    LOG.info("Polling iniciado | intervalo=%ss | severidade mínima=%s | cursor=%s",
             args.intervalo, args.severidade_minima, estado.obter("ultimo_eventid") or "backfill")
    try:
        while True:
            try:
                enviados, ignorados, pagina_cheia = processar_pagina(
                    client, estado, args.url, token, args.limite, args.severidade_minima
                )
                LOG.info("Consulta concluída | encaminhados=%d | ignorados=%d",
                         enviados, ignorados)
                if args.uma_vez:
                    if pagina_cheia:
                        LOG.warning("Página cheia; execute novamente para continuar o backlog")
                    return 0
                time.sleep(1 if pagina_cheia else args.intervalo)
            except Exception as exc:
                LOG.error("Falha na consulta/entrega; cursor preservado no último evento confirmado (%s)",
                          type(exc).__name__)
                if args.uma_vez:
                    return 1
                time.sleep(min(args.intervalo, 60))
    except KeyboardInterrupt:
        LOG.info("Polling interrompido pelo operador")
        return 0
    finally:
        estado.fechar()


if __name__ == "__main__":
    raise SystemExit(main())
