"""
Correlação determinística de alertas (sem IA).

Faz o "trabalho braçal" antes de chamar a IA, para que ela receba dados já
organizados e para termos um diagnóstico de fallback caso a IA esteja indisponível:

* Casa problemas com suas resoluções e detecta oscilação (flapping).
* Extrai o site/POP e a função do equipamento a partir do hostname.
* Classifica cada alerta em uma categoria técnica (BGP, OSPF, PPPoE, SNMP...).
* Agrupa alertas próximos no tempo em "incidentes" (janelas).
* Aplica a regra de negócio das tags (backbone/edge = 1 Crítico, 2 Alerta, 3 Informativo).
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from noc.parser import PROBLEMA, RESOLVIDO, Alerta, normalizar

# --------------------------------------------------------------------------- #
# Regras de negócio
# --------------------------------------------------------------------------- #
CLASSIFICACAO_POR_PESO = {1: "CRITICO", 2: "ALERTA", 3: "INFORMATIVO"}
ORDEM_CLASSIFICACAO = {"CRITICO": 0, "ALERTA": 1, "INFORMATIVO": 2, "NORMALIZADO": 3}

# Tags que NÃO representam custo topológico, mesmo que tenham valor 1..3
_TAGS_NAO_TOPOLOGICAS = {
    "scope", "component", "interface", "neighbor", "class", "target", "port",
    "vlan", "ifindex", "item", "application", "service", "olt", "pon", "slot",
}

_FABRICANTES = {
    "HUAWEI", "DATACOM", "ZTE", "RAISECOM", "MIKROTIK", "JUNIPER", "CISCO",
    "NOKIA", "FIBERHOME", "PARKS", "INTELBRAS", "UBIQUITI", "TPLINK", "VSOL", "CDATA",
}

_CATEGORIAS: list[tuple[str, re.Pattern]] = [
    ("CLIENTE", re.compile(r"^cliente\b")),
    ("BGP", re.compile(r"\bbgp\b|established|peer")),
    ("LINK", re.compile(r"link down|operational status")),
    ("OSPF", re.compile(r"\bospf\b|adjacen")),
    ("PPPOE/BNG", re.compile(r"pppoe|sess(oes|ao|ion)s? (pppoe|ativas)|\bbng\b")),
    ("OPTICO", re.compile(r"atenua|rx power|tx power|optic|optica|\bdbm\b|gbic|sfp|transceiver")),
    ("LINK", re.compile(r"interface .* down|\bport\b.*down")),
    ("DISPONIBILIDADE", re.compile(r"icmp|ping|unreachable|unavailable|indisponi|esta down|is down|sem resposta")),
    ("COLETA/SNMP", re.compile(r"snmp|no data|missing data|nodata|zabbix agent|sem coleta|items have been")),
    ("HARDWARE", re.compile(r"\bcpu\b|memor|temperat|\bfan\b|ventoinha|power supply|fonte|disk|disco|reboot|reinici|uptime")),
    ("CONGESTIONAMENTO", re.compile(r"discard|errors?\b|erros?\b|utiliza|bandwidth|banda|saturac|crc")),
]


def categorizar(problema: str) -> str:
    texto = normalizar(problema)
    for nome, padrao in _CATEGORIAS:
        if padrao.search(texto):
            return nome
    return "OUTROS"


def decompor_hostname(host: str) -> tuple[str, str, Optional[str]]:
    """
    Separa o hostname no padrão FibraPlus em (site, funcao, fabricante).

    Ex.: 'CPE-EXEMPLO-HUAWEI-VS02-RR01' -> ('CPE-EXEMPLO', 'VS02-RR01', 'HUAWEI')
         'EXEMPLO-POP-DATACOM-PE01'     -> ('EXEMPLO-POP', 'PE01', 'DATACOM')
    """
    partes = [p for p in re.split(r"[-_\s]+", host.strip().upper()) if p]
    for i, parte in enumerate(partes):
        if parte in _FABRICANTES:
            site = "-".join(partes[:i]) or partes[0]
            funcao = "-".join(partes[i + 1:]) or "?"
            return site, funcao, parte
    if len(partes) >= 2:
        return "-".join(partes[:-1]), partes[-1], None
    return host.strip().upper(), "?", None


def peso_topologico(tags: dict[str, str]) -> Optional[tuple[int, str]]:
    """Retorna (peso, 'tag=valor') da tag topológica mais crítica (1 é o mais crítico)."""
    melhor: Optional[tuple[int, str]] = None
    for chave, valor in tags.items():
        if chave in _TAGS_NAO_TOPOLOGICAS:
            continue
        v = valor.strip()
        if v in {"1", "2", "3"}:
            peso = int(v)
            if melhor is None or peso < melhor[0]:
                melhor = (peso, f"{chave}={v}")
    return melhor


def classificar_por_severidade_zabbix(sev: int) -> str:
    if sev < 0:
        return "ALERTA"  # nível desconhecido: conservador, nunca descartar como informativo
    if sev >= 4:
        return "CRITICO"
    if sev >= 2:
        return "ALERTA"
    return "INFORMATIVO"


# --------------------------------------------------------------------------- #
# Estruturas
# --------------------------------------------------------------------------- #
@dataclass
class Ocorrencia:
    """Estado consolidado de um mesmo (equipamento, problema) dentro do lote."""

    equipamento: str
    problema: str
    ip: Optional[str]
    nivel: str
    severidade: int
    categoria: str
    site: str
    funcao: str
    fabricante: Optional[str]
    inicio: Optional[datetime]
    estado: str  # ATIVO | RESOLVIDO | OSCILANDO
    vezes: int
    ultima_resolucao: Optional[datetime]
    duracoes: list[str]
    tags: dict[str, str]
    avisos: list[str]
    ultimo_evento: Optional[datetime] = None  # último início/resolução visto no lote
    ativo_no_zabbix: Optional[bool] = None  # preenchido pelo enriquecimento
    origens: list[str] = field(default_factory=list)

    @property
    def peso(self) -> Optional[tuple[int, str]]:
        return peso_topologico(self.tags)

    @property
    def classificacao(self) -> str:
        p = self.peso
        return CLASSIFICACAO_POR_PESO[p[0]] if p else classificar_por_severidade_zabbix(self.severidade)

    def to_dict(self) -> dict:
        p = self.peso
        return {
            "equipamento": self.equipamento,
            "ip": self.ip,
            "site": self.site,
            "funcao": self.funcao,
            "fabricante": self.fabricante,
            "problema": self.problema,
            "categoria": self.categoria,
            "nivel_zabbix": self.nivel,
            "estado_no_lote": self.estado,
            "ocorrencias_no_lote": self.vezes,
            "inicio": self.inicio.strftime("%Y-%m-%d %H:%M:%S") if self.inicio else None,
            "ultima_resolucao": self.ultima_resolucao.strftime("%H:%M:%S") if self.ultima_resolucao else None,
            "duracoes": self.duracoes,
            "tags": self.tags,
            "peso_topologico": p[1] if p else None,
            "classificacao_regra": self.classificacao,
            "classificacao_origem": "tag" if p else "severidade_zabbix",
            "ativo_no_zabbix_agora": self.ativo_no_zabbix,
            "origens": self.origens,
            "avisos": self.avisos,
        }


@dataclass
class Incidente:
    """Grupo de ocorrências próximas no tempo (provável evento único)."""

    id: int
    ocorrencias: list[Ocorrencia] = field(default_factory=list)

    @property
    def inicio(self) -> Optional[datetime]:
        datas = [o.inicio for o in self.ocorrencias if o.inicio]
        return min(datas) if datas else None

    @property
    def fim(self) -> Optional[datetime]:
        datas = [o.ultimo_evento or o.inicio for o in self.ocorrencias if o.ultimo_evento or o.inicio]
        return max(datas) if datas else None

    @property
    def ativos(self) -> list[Ocorrencia]:
        return [o for o in self.ocorrencias if o.estado != "RESOLVIDO"]

    @property
    def classificacao(self) -> str:
        if not self.ativos:
            return "NORMALIZADO"
        return min((o.classificacao for o in self.ativos), key=lambda c: ORDEM_CLASSIFICACAO[c])

    @property
    def sites(self) -> list[str]:
        return sorted({o.site for o in self.ocorrencias})

    @property
    def categorias(self) -> list[str]:
        return sorted({o.categoria for o in self.ocorrencias})

    def to_dict(self) -> dict:
        return {
            "incidente": self.id,
            "janela": {
                "inicio": self.inicio.strftime("%Y-%m-%d %H:%M:%S") if self.inicio else None,
                "fim": self.fim.strftime("%Y-%m-%d %H:%M:%S") if self.fim else None,
            },
            "classificacao_regra": self.classificacao,
            "sites": self.sites,
            "categorias": self.categorias,
            "total_ocorrencias": len(self.ocorrencias),
            "ativos": len(self.ativos),
            "ocorrencias": [o.to_dict() for o in sorted(
                self.ocorrencias, key=lambda o: o.inicio or datetime.min)],
        }


@dataclass
class Correlacao:
    incidentes: list[Incidente]
    clientes_filtrados: int
    observacoes: list[str]

    @property
    def ocorrencias(self) -> list[Ocorrencia]:
        return [o for inc in self.incidentes for o in inc.ocorrencias]


# --------------------------------------------------------------------------- #
# Lógica principal
# --------------------------------------------------------------------------- #
def _consolidar(alertas: list[Alerta]) -> list[Ocorrencia]:
    por_chave: dict[tuple[str, str], list[Alerta]] = defaultdict(list)
    for a in alertas:
        por_chave[a.chave].append(a)

    ocorrencias: list[Ocorrencia] = []
    for grupo in por_chave.values():
        problemas = [a for a in grupo if a.status == PROBLEMA]
        resolucoes = [a for a in grupo if a.status == RESOLVIDO]
        inicios_resolvidos = {r.inicio for r in resolucoes if r.inicio}
        inicios_todos = {a.inicio for a in grupo if a.inicio} or {None}
        pendentes = [p for p in problemas if p.inicio not in inicios_resolvidos]

        vezes = len(inicios_todos)
        if vezes >= 2:
            estado = "OSCILANDO" if pendentes else "RESOLVIDO"
            if not pendentes and vezes >= 3:
                estado = "OSCILANDO"
        else:
            estado = "ATIVO" if pendentes else "RESOLVIDO"

        base = max(grupo, key=lambda a: a.severidade)
        site, funcao, fabricante = decompor_hostname(base.equipamento)
        tags: dict[str, str] = {}
        avisos: list[str] = []
        for a in grupo:
            tags.update(a.tags)
            for av in a.avisos:
                if av not in avisos:
                    avisos.append(av)

        datas_validas = [a.inicio for a in grupo if a.inicio]
        fins = [r.fim for r in resolucoes if r.fim]
        ocorrencias.append(Ocorrencia(
            equipamento=base.equipamento,
            problema=base.problema,
            ip=next((a.ip for a in grupo if a.ip), None),
            nivel=base.nivel,
            severidade=base.severidade,
            categoria=categorizar(base.problema),
            site=site, funcao=funcao, fabricante=fabricante,
            inicio=min(datas_validas) if datas_validas else None,
            estado=estado,
            vezes=vezes if datas_validas else len(grupo),
            ultima_resolucao=max(fins) if fins else None,
            duracoes=[r.duracao for r in resolucoes if r.duracao],
            tags=tags,
            avisos=avisos,
            ultimo_evento=max(datas_validas + fins) if (datas_validas or fins) else None,
            origens=sorted({a.origem.strip().upper() for a in grupo if a.origem.strip()}),
        ))
    return ocorrencias


def _agrupar_por_tempo(ocorrencias: list[Ocorrencia], janela_min: int) -> list[Incidente]:
    com_data = sorted((o for o in ocorrencias if o.inicio), key=lambda o: o.inicio)
    sem_data = [o for o in ocorrencias if not o.inicio]

    incidentes: list[Incidente] = []
    inicio_janela: Optional[datetime] = None
    for o in com_data:
        if inicio_janela is None or (o.inicio - inicio_janela).total_seconds() > janela_min * 60:
            incidentes.append(Incidente(id=len(incidentes) + 1))
            inicio_janela = o.inicio
        incidentes[-1].ocorrencias.append(o)
    if sem_data:
        incidentes.append(Incidente(id=len(incidentes) + 1, ocorrencias=sem_data))
    return incidentes


def correlacionar(alertas: list[Alerta], janela_min: int = 10,
                  incluir_clientes: bool = False) -> Correlacao:
    observacoes: list[str] = []
    clientes = [a for a in alertas if categorizar(a.problema) == "CLIENTE"]
    if not incluir_clientes:
        alertas = [a for a in alertas if categorizar(a.problema) != "CLIENTE"]

    ocorrencias = _consolidar(alertas)

    # Macro não resolvida faz itens diferentes colapsarem no mesmo nome
    for o in ocorrencias:
        if any("Macro não resolvida" in av for av in o.avisos) and o.vezes >= 2:
            observacoes.append(
                f"{o.equipamento}: '{o.problema}' contém macro não resolvida; as {o.vezes} "
                "ocorrências podem ser itens DIFERENTES (ex.: interfaces/slots distintos) "
                "com o mesmo nome — não necessariamente oscilação do mesmo item."
            )

    incidentes = _agrupar_por_tempo(ocorrencias, janela_min)
    incidentes.sort(key=lambda i: (ORDEM_CLASSIFICACAO[i.classificacao],
                                   -(i.inicio.timestamp() if i.inicio else 0)))
    for n, inc in enumerate(incidentes, 1):
        inc.id = n
    return Correlacao(incidentes=incidentes,
                      clientes_filtrados=0 if incluir_clientes else len(clientes),
                      observacoes=observacoes)
