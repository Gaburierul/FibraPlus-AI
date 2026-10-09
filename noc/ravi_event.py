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
from noc.parser import Alerta, PROBLEMA, RESOLVIDO

class PayloadRaviInvalido(ValueError):
    pass


class PayloadRaviIgnorado(PayloadRaviInvalido):
    """Payload válido para transporte, mas que não representa um alerta acionável."""

def _extrair_campo(regex: str, texto: str) -> str:
    m = re.search(regex, texto, re.IGNORECASE)
    return m.group(1).strip() if m else ""

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
    
    if not eh_problema and not eh_resolvido:
        raise PayloadRaviIgnorado("Mensagem genérica/métrica sem alerta claro")

    status = RESOLVIDO if (eh_resolvido and not eh_problema) else PROBLEMA

    # Extrai os campos do texto (Ex: "Dispositivo: CDN STAR (ROTAS)")
    dispositivo = _extrair_campo(r"Dispositivo:\s*([^\n]+)", texto)
    if not dispositivo:
        # Se não tiver 'Dispositivo:', tenta 'OLT:' ou 'Equipamento:'
        dispositivo = _extrair_campo(r"(?:OLT|Equipamento):\s*([^\n]+)", texto)

    if not dispositivo:
        dispositivo = "Desconhecido (Ravi)"

    ip = _extrair_campo(r"IP:\s*([^\n]+)", texto)
    problema_desc = _extrair_campo(r"Problema:\s*([^\n]+)", texto)
    sensor = _extrair_campo(r"Sensor:\s*([^\n]+)", texto)
    
    descricao = problema_desc
    if sensor:
        descricao = f"Sensor {sensor}: {problema_desc}"
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

    # Converte regras operacionais conhecidas em severidade determinística; a IA não classifica.
    tipo = ""
    if "ROTAS" in dispositivo.upper() or "BGP" in descricao.upper() or "CDN" in dispositivo.upper():
        tipo = "rota"
    elif "OLT" in dispositivo.upper():
        tipo = "olt"
    elif "LINK" in dispositivo.upper() or "DEDICADO" in dispositivo.upper():
        tipo = "link"

    nivel, severidade = "Average", 3
    if status == PROBLEMA:
        texto_degradacao = f"{dispositivo} {descricao}".upper()
        termos_degradacao = (
            "DEGRADAD", "ATENUA", "PACKET LOSS", "PERDA DE PACOTE", "OSCIL", "FLAPPING"
        )
        if any(termo in texto_degradacao for termo in termos_degradacao):
            nivel, severidade = "High", 4
        elif tipo in {"rota", "olt", "link"}:
            nivel, severidade = "Disaster", 5

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

    return alerta
