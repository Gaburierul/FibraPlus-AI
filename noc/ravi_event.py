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
from noc.parser import Alerta, PROBLEMA, RESOLVIDO, normalizar

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


    texto_upper = texto.upper()
    palavras_problema = ["PROBLEMA ENCONTRADO", "OFFLINE", "FALHA", "CRÍTICO", "DEGRADADO", "❌", "PROBLEMA"]
    palavras_resolvido = ["RECUPERAD", "RESOLVIDO", "ONLINE", "NORMALIZADO", "✅"]
    
    eh_problema = any(p in texto_upper for p in palavras_problema) or bool(re.search(r"\bDOWN\b", texto_upper))
    eh_resolvido = any(p in texto_upper for p in palavras_resolvido) or bool(
        re.search(r"\bUP\b", texto_upper)
    )
    
    severidade_explicita = _severidade_explicita(payload, texto)
    problema_desc = _extrair_campo(r"Problema:\s*([^\n]+)", texto)
    if (not eh_problema and not eh_resolvido and problema_desc
            and severidade_explicita is not None and severidade_explicita[0] >= 2):
        # Syslog sem palavras de estado: só aceitar como problema se trouxer
        # descrição e severidade operacional explícita.
        eh_problema = True

    if not eh_problema and not eh_resolvido:
        raise PayloadRaviIgnorado("Mensagem sem estado de alerta/resolução reconhecível")

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

    # Tenta extrair a data (Data: 07/10/2026 12:37:00)
    data_str = _extrair_campo(r"Data:\s*([\d/]+\s+[\d:]+)", texto)
    inicio = None
    if data_str:
        try:
            inicio = datetime.strptime(data_str, "%d/%m/%Y %H:%M:%S")
        except ValueError:
            pass

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
    if inicio is None:
        alerta.avisos.append("Data/hora ausente ou ilegível no payload do Ravi")
    if dispositivo == "Desconhecido (Ravi)":
        alerta.avisos.append("Equipamento ausente no payload do Ravi")

    return alerta

