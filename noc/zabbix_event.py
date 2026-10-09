"""
Conversão do payload JSON do webhook do Zabbix em `Alerta`.

O webhook (ver `zabbix/webhook_fibraplus_ia.js`) envia um JSON com as macros
do evento. Aqui transformamos isso no MESMO objeto `Alerta` que o parser de
texto do WhatsApp produz — assim correlator e analyzer funcionam sem mudanças.

Campos esperados (todos string, como o Zabbix envia):
    event_id, event_value ("1" problema / "0" resolvido), event_update_status,
    host_name, host_ip, event_name, event_nseverity (0..5), event_severity,
    event_date ("2026.10.07"), event_time ("09:45:12"),
    recovery_date, recovery_time, event_duration, event_tags_json
"""
from __future__ import annotations

import json
from typing import Any, Optional

from noc.parser import PROBLEMA, RESOLVIDO, Alerta, _MACRO_RE, _parse_datahora

_NOME_SEVERIDADE = {0: "Not classified", 1: "Information", 2: "Warning",
                    3: "Average", 4: "High", 5: "Disaster"}


class PayloadInvalido(ValueError):
    """O JSON recebido não tem os campos mínimos para virar um alerta."""


def _texto(payload: dict[str, Any], chave: str) -> str:
    valor = payload.get(chave)
    if valor is None:
        return ""
    valor = str(valor).strip()
    # Macro que o Zabbix não conseguiu resolver chega literal, ex.: "{EVENT.RECOVERY.DATE}"
    if valor.startswith("{") and valor.endswith("}") and _MACRO_RE.fullmatch(valor):
        return ""
    return valor


def _tags(bruto: Any) -> dict[str, str]:
    """Aceita a string de {EVENT.TAGSJSON}, uma lista já decodificada ou um dict."""
    if not bruto:
        return {}
    if isinstance(bruto, str):
        try:
            bruto = json.loads(bruto)
        except json.JSONDecodeError:
            return {}
    if isinstance(bruto, dict):
        return {str(k).strip().lower(): str(v).strip() for k, v in bruto.items()}
    tags: dict[str, str] = {}
    if isinstance(bruto, list):
        for item in bruto:
            if isinstance(item, dict) and item.get("tag"):
                tags[str(item["tag"]).strip().lower()] = str(item.get("value", "")).strip()
    return tags


def eh_atualizacao(payload: dict[str, Any]) -> bool:
    """True para eventos de 'update' (ack, comentário) — não são problema nem resolução."""
    return _texto(payload, "event_update_status") == "1"


def chave_evento(payload: dict[str, Any]) -> tuple[str, str]:
    """Identidade do envio, para descartar duplicatas (ex.: passos de escalonamento)."""
    event_id = _texto(payload, "event_id")
    event_value = _texto(payload, "event_value")
    if not event_id.isdigit() or event_value not in {"0", "1"}:
        raise PayloadInvalido("event_id e event_value válidos são necessários para deduplicação")
    return (event_id, event_value)


def payload_para_alerta(payload: dict[str, Any]) -> Alerta:
    event_id = _texto(payload, "event_id")
    if not event_id.isdigit():
        raise PayloadInvalido("event_id ausente ou inválido (esperado ID numérico do Zabbix)")

    equipamento = _texto(payload, "host_name")
    problema = _texto(payload, "event_name")
    if not equipamento or not problema:
        raise PayloadInvalido("campos obrigatórios ausentes: host_name e event_name")

    valor = _texto(payload, "event_value")
    if valor not in {"0", "1"}:
        raise PayloadInvalido(f"event_value inválido: {valor!r} (esperado '0' ou '1')")
    status = RESOLVIDO if valor == "0" else PROBLEMA

    alerta = Alerta(status=status, equipamento=equipamento, problema=problema,
                    ip=_texto(payload, "host_ip") or None)

    nsev = _texto(payload, "event_nseverity")
    if nsev.isdigit() and int(nsev) in _NOME_SEVERIDADE:
        alerta.severidade = int(nsev)
        alerta.nivel = _NOME_SEVERIDADE[alerta.severidade]
    else:
        alerta.nivel = _texto(payload, "event_severity") or "Desconhecido"
        alerta.avisos.append(f"Severidade numérica ausente/inválida: {nsev!r}")

    inicio = f"{_texto(payload, 'event_date')} {_texto(payload, 'event_time')}".strip()
    alerta.inicio = _parse_datahora(inicio) if inicio else None
    if alerta.inicio is None:
        alerta.avisos.append(f"Horário de início ilegível: {inicio!r}")

    if status == RESOLVIDO:
        fim = f"{_texto(payload, 'recovery_date')} {_texto(payload, 'recovery_time')}".strip()
        alerta.fim = _parse_datahora(fim) if fim else None
        if alerta.fim is None:
            alerta.avisos.append("Resolução sem horário de término")
        alerta.duracao = _texto(payload, "event_duration") or None

    alerta.tags = _tags(payload.get("event_tags_json"))

    macros = _MACRO_RE.findall(problema)
    if macros:
        alerta.avisos.append(
            f"Macro não resolvida no nome do problema: {', '.join(sorted(set(macros)))} "
            "(revisar template/ação do Zabbix)"
        )
    return alerta


def resumo_curto(alerta: Alerta) -> str:
    """Linha de log legível."""
    simbolo = "RESOLVIDO" if alerta.status == RESOLVIDO else "PROBLEMA"
    return f"{simbolo} | {alerta.equipamento} | {alerta.problema} | {alerta.nivel}"


def severidade_minima_ok(alerta: Alerta, minima: Optional[int]) -> bool:
    # Resoluções precisam ser comunicadas mesmo quando a severidade atual do
    # evento de recuperação vem como zero ou abaixo do filtro configurado.
    if alerta.status == RESOLVIDO or minima is None or alerta.severidade < 0:
        return True
    return alerta.severidade >= minima
