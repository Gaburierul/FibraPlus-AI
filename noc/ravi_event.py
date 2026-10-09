"""
Módulo para conversão de Webhooks do Ravicor para o formato interno Alerta.

Exemplo de Payload esperado:
{
  "origem": "ravi-monitor",
  "mensagem": "❌ PROBLEMA ENCONTRADO\\n\\nDispositivo: SERVIDOR-EXEMPLO (ROTAS)\\nSensor: Ping\\nIP: 192.0.2.10\\nProblema: Offline\\nData: 07/10/2026 12:37:00",
  "evento": "incidente",
  "data": "..."
}
"""

import re
from datetime import datetime
from typing import Any
from noc.parser import Alerta, PROBLEMA, RESOLVIDO, _parse_datahora, normalizar

_NIVEIS_SEVERIDADE = {
    "not classified": (0, "Not classified"),
    "nao classificada": (0, "Not classified"),
    "nao classificado": (0, "Not classified"),
    "information": (1, "Information"),
    "informacao": (1, "Information"),
    "informativo": (1, "Information"),
    "warning": (2, "Warning"),
    "atencao": (2, "Warning"),
    "aviso": (2, "Warning"),
    "average": (3, "Average"),
    "media": (3, "Average"),
    "medio": (3, "Average"),
    "high": (4, "High"),
    "alta": (4, "High"),
    "alto": (4, "High"),
    "disaster": (5, "Disaster"),
    "desastre": (5, "Disaster"),
}

class PayloadRaviInvalido(ValueError):
    pass


class PayloadRaviIgnorado(PayloadRaviInvalido):
    """Payload válido para transporte, mas que não representa um alerta acionável."""

def _extrair_campo(regex: str, texto: str) -> str:
    m = re.search(regex, texto, re.IGNORECASE)
    return m.group(1).strip() if m else ""


def _valor_payload(payload: dict, *chaves: str) -> Any:
    for chave in chaves:
        valor = payload.get(chave)
        if valor not in (None, ""):
            return valor
    return None


def chave_evento_ravi(payload: dict) -> tuple[str, str] | None:
    """Retorna uma chave idempotente apenas quando o Ravi fornece um ID de evento."""
    valor = _valor_payload(
        payload, "eventid", "event_id", "eventId", "notification_id", "notificationId", "id_evento"
    )
    if valor is None or isinstance(valor, (dict, list, bool)):
        return None
    identificador = str(valor).strip()
    if not identificador or len(identificador) > 200:
        return None
    return ("RAVI", identificador)


def _estado_explicito_payload(payload: dict) -> str | None:
    problemas = {"problem", "problem detected", "problema encontrado", "alert", "alerta",
                 "down", "active", "ativo", "aberto"}
    resolvidos = {"resolved", "resolution", "resolvido", "normalizado", "recovered",
                  "recovery", "up", "cleared", "closed", "fechado"}
    for chave in ("event_status", "status", "state", "evento"):
        valor = payload.get(chave)
        if not isinstance(valor, str):
            continue
        estado = normalizar(valor)
        if estado in problemas:
            return PROBLEMA
        if estado in resolvidos:
            return RESOLVIDO
    return None


def _combinar_data_hora(payload: dict, chaves_data: tuple[str, ...],
                        chaves_hora: tuple[str, ...]) -> str | None:
    data = _valor_payload(payload, *chaves_data)
    hora = _valor_payload(payload, *chaves_hora)
    if data is None or hora is None:
        return None
    return f"{data} {hora}"


def _parse_datahora_ravi(valor: Any) -> datetime | None:
    """Interpreta datas usuais do webhook e timestamps Unix, sem inventar horários."""
    if isinstance(valor, bool) or valor in (None, ""):
        return None
    if isinstance(valor, (int, float)):
        try:
            timestamp = float(valor)
            if timestamp > 10_000_000_000:  # milissegundos Unix
                timestamp /= 1000
            if timestamp < 0:
                return None
            return datetime.fromtimestamp(timestamp).replace(microsecond=0)
        except (OverflowError, OSError, ValueError):
            return None

    texto = str(valor).strip()
    if not texto:
        return None
    parseado = _parse_datahora(texto)
    if parseado:
        return parseado
    for formato in ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M",
                    "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M",
                    "%Y.%m.%d %H:%M:%S", "%Y.%m.%d %H:%M"):
        try:
            return datetime.strptime(texto, formato)
        except ValueError:
            pass
    if not re.search(r"\d[T ]\d{1,2}:\d{2}", texto):
        return None
    iso = texto[:-1] + "+00:00" if texto.endswith(("Z", "z")) else texto
    try:
        parseado = datetime.fromisoformat(iso)
    except ValueError:
        return None
    if parseado.tzinfo is not None:
        parseado = parseado.astimezone().replace(tzinfo=None)
    return parseado.replace(microsecond=0)


def _duracao_payload(payload: dict, texto: str) -> str | None:
    valor = _valor_payload(payload, "event_duration", "duration", "duracao", "duração")
    if valor is None:
        valor = _extrair_campo(r"(?:Duração|Duracao|Duration):\s*([^\n]+)", texto)
    return str(valor).strip() or None if valor is not None else None


def _severidade_explicita(payload: dict, texto: str) -> tuple[int, str] | None:
    """Lê severidade fornecida pelo Ravi; nunca a deduz do tipo de equipamento."""
    bruto = next((payload.get(chave) for chave in
                  ("event_nseverity", "severidade", "severity", "nivel", "level")
                  if payload.get(chave) not in (None, "")), None)
    if bruto is None:
        bruto = _extrair_campo(r"(?:Severidade|Severity|Nível|Nivel|Level):\s*([^\n]+)", texto)
    if isinstance(bruto, bool) or bruto is None:
        return None

    valor = str(bruto).strip()
    numero = re.fullmatch(r"([0-5])(?:\s*[-–:]\s*.*)?", valor)
    if numero:
        n = int(numero.group(1))
        nomes = {0: "Not classified", 1: "Information", 2: "Warning",
                 3: "Average", 4: "High", 5: "Disaster"}
        return n, nomes[n]

    nome = normalizar(valor).split("(", 1)[0].strip()
    return _NIVEIS_SEVERIDADE.get(nome)

def payload_para_alerta_ravi(payload: dict) -> Alerta:
    """Converte o payload JSON do Ravi em um objeto Alerta."""

    if not isinstance(payload, dict) or "mensagem" not in payload:
        raise PayloadRaviInvalido("Campo 'mensagem' ausente no payload do Ravi")

    texto = payload["mensagem"]
    if not isinstance(texto, str) or not texto.strip():
        raise PayloadRaviInvalido("Campo 'mensagem' deve ser texto não vazio")

    # Ignora mensagens puramente de teste
    if "teste do ravicor" in texto.casefold():
        raise PayloadRaviIgnorado("MENSAGEM DE TESTE")


    # O campo "Problema:" aparece também em mensagens resolvidas. O estado é
    # determinado pelo campo de status do payload ou pelo cabeçalho, nunca pelo
    # texto inteiro do problema.
    estado_payload = _estado_explicito_payload(payload)
    marcador_problema = bool(re.search(
        r"(?:🔴|🛑|❌).{0,100}\b(?:ATIVO|PROBLEMA(?:\s+ENCONTRADO)?|OFFLINE|FALHA|DOWN)\b",
        texto, re.IGNORECASE,
    ))
    marcador_resolvido = bool(re.search(
        r"(?:✅|🟢).{0,100}\b(?:RESOLVIDO|NORMALIZADO|RECUPERAD\w*|ONLINE|UP)\b",
        texto, re.IGNORECASE,
    ))
    if marcador_problema and marcador_resolvido:
        raise PayloadRaviIgnorado("Payload contém alertas ativos e resolvidos; não é um evento único")
    cabecalho = next((linha.strip().upper() for linha in texto.splitlines() if linha.strip()), "")
    palavras_problema = (
        "PROBLEMA ENCONTRADO", "PROBLEM DETECTED", "ALERTA", "OFFLINE", "FALHA",
        "CRÍTICO", "CRITICO", "DEGRADADO", "❌", "🔴",
    )
    palavras_resolvido = ("RECUPERAD", "RESOLVIDO", "NORMALIZADO", "ONLINE", "✅", "🟢")
    eh_problema = marcador_problema or any(p in cabecalho for p in palavras_problema) or bool(
        re.search(r"\bDOWN\b", cabecalho)
    )
    eh_resolvido = marcador_resolvido or any(p in cabecalho for p in palavras_resolvido) or bool(
        re.search(r"\bUP\b", cabecalho)
    )
    if estado_payload is not None:
        eh_problema, eh_resolvido = estado_payload == PROBLEMA, estado_payload == RESOLVIDO

    severidade_explicita = _severidade_explicita(payload, texto)
    problema_desc = _extrair_campo(r"Problema:\s*([^\n]+)", texto)
    if (not eh_problema and not eh_resolvido and problema_desc
            and severidade_explicita is not None and severidade_explicita[0] >= 2):
        # Syslog sem palavras de estado: só aceitar como problema se trouxer
        # descrição e severidade operacional explícita.
        eh_problema = True

    if not eh_problema and not eh_resolvido:
        raise PayloadRaviIgnorado("Mensagem sem estado de alerta/resolução reconhecível")
    if eh_problema and eh_resolvido:
        raise PayloadRaviIgnorado("Estado conflitante no cabeçalho do alerta Ravi")

    status = RESOLVIDO if (eh_resolvido and not eh_problema) else PROBLEMA

    # Extrai os campos do texto (Ex: "Dispositivo: CDN STAR (ROTAS)")
    dispositivo = _extrair_campo(r"Dispositivo:\s*([^\n]+)", texto)
    if not dispositivo:
        # Se não tiver 'Dispositivo:', tenta 'OLT:' ou 'Equipamento:'
        dispositivo = _extrair_campo(r"(?:OLT|Equipamento):\s*([^\n]+)", texto)

    if not dispositivo:
        dispositivo = "Desconhecido (Ravi)"

    ip = _extrair_campo(r"IP:\s*([^\n]+)", texto)
    sensor = _extrair_campo(r"Sensor:\s*([^\n]+)", texto)

    descricao = problema_desc
    if sensor and problema_desc:
        descricao = f"Sensor {sensor}: {problema_desc}"
    elif sensor:
        descricao = f"Sensor {sensor}"
    if not descricao:
        descricao = "Queda/Indisponibilidade detectada"

    # Aceita início e resolução separados. O campo genérico "data" costuma
    # representar o horário do evento notificado pelo Ravi.
    inicio_valor = _valor_payload(
        payload, "event_start", "started_at", "start_time", "inicio", "iniciado_em"
    )
    inicio = _parse_datahora_ravi(inicio_valor)
    if inicio is None:
        datas_inicio = ("start_date", "event_date") if status == PROBLEMA else ("start_date",)
        inicio = _parse_datahora_ravi(_combinar_data_hora(
            payload, datas_inicio, ("start_time", "event_time")
        ))
    fim_valor = _valor_payload(
        payload, "resolved_at", "end_time", "fim", "resolvido_em"
    )
    fim = _parse_datahora_ravi(fim_valor)
    if fim is None:
        fim = _parse_datahora_ravi(_combinar_data_hora(
            payload, ("recovery_date", "resolved_date"), ("recovery_time", "resolved_time")
        ))
    if inicio is None:
        inicio_txt = _extrair_campo(
            r"(?:Iniciado(?:\s+às|\s+em)?|In[ií]cio|Started at):\s*([^\n]+)", texto
        )
        inicio = _parse_datahora_ravi(inicio_txt) if inicio_txt else None
    if fim is None:
        fim_txt = _extrair_campo(
            r"(?:Resolvido(?:\s+às|\s+em)?|Normalizado(?:\s+às|\s+em)?|Resolved at):\s*([^\n]+)", texto
        )
        fim = _parse_datahora_ravi(fim_txt) if fim_txt else None

    evento_valor = _valor_payload(
        payload, "event_timestamp", "occurred_at", "timestamp", "datetime", "data", "date"
    )
    evento = _parse_datahora_ravi(evento_valor)
    if evento is None:
        evento = _parse_datahora_ravi(_combinar_data_hora(
            payload, ("event_date", "date_event"), ("event_time", "time_event")
        ))
    if evento is None:
        evento_txt = _extrair_campo(r"(?:Data|Data e hora|Date):\s*([^\n]+)", texto)
        evento = _parse_datahora_ravi(evento_txt) if evento_txt else None
    if evento is not None:
        if status == RESOLVIDO and fim is None:
            fim = evento
        elif status == PROBLEMA and inicio is None:
            inicio = evento

    # Tipo ajuda a descrever o equipamento; não substitui severidade ausente.
    tipo = ""
    if "ROTAS" in dispositivo.upper() or "BGP" in descricao.upper() or "CDN" in dispositivo.upper():
        tipo = "rota"
    elif "OLT" in dispositivo.upper():
        tipo = "olt"
    elif "LINK" in dispositivo.upper() or "DEDICADO" in dispositivo.upper():
        tipo = "link"

    # O helper retorna primeiro o valor numérico, depois o rótulo textual.
    severidade, nivel = severidade_explicita or (-1, "Desconhecido")

    alerta = Alerta(
        status=status,
        equipamento=dispositivo,
        problema=descricao,
        ip=ip if ip else None,
        nivel=nivel,
        severidade=severidade,
        inicio=inicio,
        fim=fim,
        duracao=_duracao_payload(payload, texto),
        origem="RAVI"
    )

    if tipo:
        alerta.tags["tipo"] = tipo
    if severidade_explicita is None:
        alerta.avisos.append("Severidade não fornecida pelo Ravi; classificação mantida conservadora")
    if not problema_desc:
        alerta.avisos.append("Descrição do problema ausente; usado texto genérico")
    if not ip:
        alerta.avisos.append("IP ausente no payload do Ravi")
    if inicio is None and fim is None:
        alerta.avisos.append("Data/hora ausente ou ilegível no payload do Ravi")
    if dispositivo == "Desconhecido (Ravi)":
        alerta.avisos.append("Equipamento ausente no payload do Ravi")

    return alerta
