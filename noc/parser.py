"""
Parser das mensagens de alerta do Zabbix (formato enviado ao WhatsApp).

Formato esperado (tolerante a variações, emojis, acentos e espaços extras):

    🛑🛑 Problema: 🛑🛑
    Equipamento: CPE-MSD-HUAWEI-BNG01
    IP: 10.1.1.4
    Nome do problema: ...
    Nível: High
    Iniciado às: 15:42:47 em 2026.10.06
    Tags: backbone: 1, component: bgp        (opcional)

    ✅✅ Resolvido: ✅✅
    ...
    Resolvido às: 15:42:49 em 2026.10.06
    Duração: 1m 0s
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

PROBLEMA = "PROBLEMA"
RESOLVIDO = "RESOLVIDO"

# Severidades do Zabbix (inglês e português) -> 0..5
_SEVERIDADES = {
    "not classified": 0, "nao classificada": 0, "nao classificado": 0,
    "information": 1, "informacao": 1, "informativo": 1,
    "warning": 2, "atencao": 2, "aviso": 2,
    "average": 3, "media": 3, "medio": 3,
    "high": 4, "alta": 4, "alto": 4,
    "disaster": 5, "desastre": 5,
}

# Mapeamento de rótulos de campo (normalizados, sem acento) -> atributo
_CAMPOS = {
    "equipamento": "equipamento", "host": "equipamento", "hostname": "equipamento",
    "ip": "ip", "endereco ip": "ip", "endereco": "ip",
    "nome do problema": "problema", "problem name": "problema", "trigger": "problema",
    "nivel": "nivel", "severidade": "nivel", "severity": "nivel",
    "iniciado as": "inicio", "iniciado em": "inicio", "inicio": "inicio", "started at": "inicio",
    "resolvido as": "fim", "resolvido em": "fim", "resolved at": "fim",
    "duracao": "duracao", "duration": "duracao",
    "tags": "tags", "etiquetas": "tags",
}

_HEADER_RE = re.compile(r"^\W*(problema|problem|resolvido|resolved)\W*$", re.IGNORECASE)
_DT_HORA_DATA = re.compile(
    r"(\d{1,2}:\d{2}(?::\d{2})?)\s*(?:em|on|de)?\s*(\d{4})[.\-/](\d{1,2})[.\-/](\d{1,2})"
)
_DT_DATA_HORA = re.compile(
    r"(\d{4})[.\-/](\d{1,2})[.\-/](\d{1,2})\D+(\d{1,2}:\d{2}(?::\d{2})?)"
)
_MACRO_RE = re.compile(r"\{[A-Z#$][A-Z0-9_.#:]*\}")
_TAG_RE = re.compile(r"([\w\-.]+)\s*[:=]\s*([^,;]+)")


def normalizar(texto: str) -> str:
    """Remove acentos, espaços extras e converte para minúsculas."""
    sem_acento = unicodedata.normalize("NFKD", texto).encode("ascii", "ignore").decode()
    return re.sub(r"\s+", " ", sem_acento).strip().lower()


@dataclass
class Alerta:
    """Um bloco de alerta individual (problema ou resolução)."""

    status: str
    equipamento: str
    problema: str
    ip: Optional[str] = None
    nivel: str = "Desconhecido"
    severidade: int = -1
    inicio: Optional[datetime] = None
    fim: Optional[datetime] = None
    duracao: Optional[str] = None
    tags: dict[str, str] = field(default_factory=dict)
    avisos: list[str] = field(default_factory=list)

    @property
    def chave(self) -> tuple[str, str]:
        """Identidade lógica do alerta: (equipamento, problema)."""
        return (self.equipamento.strip().lower(), normalizar(self.problema))


@dataclass
class ResultadoParse:
    alertas: list[Alerta] = field(default_factory=list)
    ignorados: list[tuple[str, str]] = field(default_factory=list)  # (motivo, trecho)


def _parse_datahora(valor: str) -> Optional[datetime]:
    """Converte '15:42:47 em 2026.10.06' (ou '2026-10-06 15:42:47') em datetime."""
    m = _DT_HORA_DATA.search(valor)
    if m:
        hora, ano, mes, dia = m.groups()
    else:
        m = _DT_DATA_HORA.search(valor)
        if not m:
            return None
        ano, mes, dia, hora = m.groups()
    partes = [int(p) for p in hora.split(":")]
    while len(partes) < 3:
        partes.append(0)
    try:
        return datetime(int(ano), int(mes), int(dia), *partes)
    except ValueError:
        return None


def _parse_tags(valor: str) -> dict[str, str]:
    return {k.strip().lower(): v.strip() for k, v in _TAG_RE.findall(valor)}


def _montar_alerta(status: str, campos: dict[str, str]) -> tuple[Optional[Alerta], Optional[str]]:
    equipamento = campos.get("equipamento", "").strip()
    problema = campos.get("problema", "").strip()
    if not equipamento:
        return None, "bloco sem campo 'Equipamento'"
    if not problema:
        return None, "bloco sem campo 'Nome do problema'"

    alerta = Alerta(status=status, equipamento=equipamento, problema=problema,
                    ip=(campos.get("ip") or "").strip() or None)

    nivel = campos.get("nivel", "").strip()
    if nivel:
        alerta.nivel = nivel
        alerta.severidade = _SEVERIDADES.get(normalizar(nivel), -1)
        if alerta.severidade < 0:
            alerta.avisos.append(f"Nível desconhecido: '{nivel}'")
    else:
        alerta.avisos.append("Nível ausente")

    if "inicio" in campos:
        alerta.inicio = _parse_datahora(campos["inicio"])
        if alerta.inicio is None:
            alerta.avisos.append(f"Horário de início ilegível: '{campos['inicio']}'")
    else:
        alerta.avisos.append("Horário de início ausente")

    if "fim" in campos:
        alerta.fim = _parse_datahora(campos["fim"])
    if status == RESOLVIDO and alerta.fim is None:
        alerta.avisos.append("Resolução sem horário de término")

    alerta.duracao = (campos.get("duracao") or "").strip() or None
    if "tags" in campos:
        alerta.tags = _parse_tags(campos["tags"])

    macros = _MACRO_RE.findall(problema)
    if macros:
        alerta.avisos.append(
            f"Macro não resolvida no nome do problema: {', '.join(sorted(set(macros)))} "
            "(revisar template/ação do Zabbix)"
        )
    return alerta, None


def parse_alertas(texto: str) -> ResultadoParse:
    """Converte o texto bruto (vários alertas concatenados) em uma lista de `Alerta`."""
    resultado = ResultadoParse()
    blocos: list[tuple[str, list[str]]] = []
    orfas: list[str] = []

    _WHATSAPP_PREAMBLE_RE = re.compile(r"^\[\d{2}:\d{2}(?::\d{2})?[, ]+\d{2}[/-]\d{2}[/-]\d{2,4}\][^:]+:\s*")

    for linha in texto.splitlines():
        if not linha.strip():
            continue
        # Remove o prefixo do WhatsApp Web se houver
        linha = _WHATSAPP_PREAMBLE_RE.sub("", linha).strip()
        cab = _HEADER_RE.match(linha)
        if cab:
            tipo = normalizar(cab.group(1))
            blocos.append((RESOLVIDO if tipo.startswith("resol") else PROBLEMA, []))
        elif blocos:
            blocos[-1][1].append(linha)
        else:
            orfas.append(linha.strip())

    if orfas:
        resultado.ignorados.append(("linhas antes do primeiro cabeçalho", " | ".join(orfas)[:200]))

    for status, linhas in blocos:
        campos: dict[str, str] = {}
        for linha in linhas:
            if ":" not in linha:
                continue
            rotulo, valor = linha.split(":", 1)
            attr = _CAMPOS.get(normalizar(rotulo))
            if attr and attr not in campos:
                campos[attr] = valor.strip()
        alerta, motivo = _montar_alerta(status, campos)
        if alerta:
            resultado.alertas.append(alerta)
        else:
            resultado.ignorados.append((motivo or "bloco inválido", " | ".join(l.strip() for l in linhas)[:200]))

    return resultado
