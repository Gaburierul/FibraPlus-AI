"""
Consulta genérica de problemas e eventos do Zabbix.

Ponto único de busca para qualquer recorte — equipamento, cliente, cidade,
interface, tag, protocolo — evitando scripts avulsos por assunto ou por data.

Dois modos:
    * ativos:    problemas abertos agora (``problem.get``);
    * histórico: transições problema/resolução numa janela (``event.get``).

Os termos de busca são comparados sem acento e sem diferenciar maiúsculas
contra nome visível e técnico do host, nome do problema e tags do evento.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from noc.parser import PROBLEMA, RESOLVIDO, Alerta, normalizar

try:
    from zoneinfo import ZoneInfo
    FUSO = ZoneInfo("America/Campo_Grande")
except Exception:  # Windows sem a base IANA instalada
    FUSO = timezone(timedelta(hours=-4))

SEVERIDADES = {0: "Not classified", 1: "Information", 2: "Warning",
               3: "Average", 4: "High", 5: "Disaster"}
ESCOPOS = ("todos", "infra", "clientes")
LIMITE_POR_CHAMADA = 5000
MIN_FATIA_S = 60
FLAPPING_MIN_PROBLEMAS = 3

_CLIENTE_RE = re.compile(r"^cliente\b|\bonu\b|esta down : -\d+", re.IGNORECASE)


@dataclass
class Evento:
    """Transição de trigger (ou problema ativo) normalizada."""

    eventid: str
    objectid: str
    clock: int
    problema_ativo: bool
    severidade: int
    host: str
    host_tecnico: str
    problema: str
    tags: dict[str, str] = field(default_factory=dict)

    @property
    def horario(self) -> datetime:
        return datetime.fromtimestamp(self.clock, FUSO)

    @property
    def eh_cliente(self) -> bool:
        return bool(_CLIENTE_RE.search(normalizar(self.problema)))

    def texto_busca(self) -> str:
        partes = [self.host, self.host_tecnico, self.problema]
        partes += [f"{k} {v}" for k, v in self.tags.items()]
        return normalizar(" ".join(partes))


@dataclass
class Grupo:
    """Todas as transições de um mesmo trigger no host durante a janela."""

    host: str
    problema: str
    eventos: list[Evento] = field(default_factory=list)

    @property
    def problemas(self) -> int:
        return sum(e.problema_ativo for e in self.eventos)

    @property
    def resolucoes(self) -> int:
        return sum(not e.problema_ativo for e in self.eventos)

    @property
    def primeiro(self) -> Evento:
        return self.eventos[0]

    @property
    def ultimo(self) -> Evento:
        return self.eventos[-1]

    @property
    def ativo(self) -> bool:
        return self.ultimo.problema_ativo

    @property
    def severidade(self) -> int:
        return max(e.severidade for e in self.eventos)

    @property
    def flapping(self) -> bool:
        return self.problemas >= FLAPPING_MIN_PROBLEMAS

    @property
    def eh_cliente(self) -> bool:
        return self.primeiro.eh_cliente


@dataclass
class Resumo:
    titulo: str
    inicio: Optional[datetime]
    fim: datetime
    grupos: list[Grupo]
    total_eventos: int
    avisos: list[str] = field(default_factory=list)

    @property
    def ativos(self) -> list[Grupo]:
        return sorted((g for g in self.grupos if g.ativo),
                      key=lambda g: (-g.severidade, g.primeiro.clock))

    @property
    def _relevantes(self) -> list[Grupo]:
        """Infraestrutura quando houver; senão (ex.: --escopo clientes) todos os grupos."""
        infra = [g for g in self.grupos if not g.eh_cliente]
        return infra or self.grupos

    @property
    def flapping(self) -> list[Grupo]:
        return sorted((g for g in self._relevantes if g.flapping), key=lambda g: -g.problemas)

    def top_hosts(self, limite: int = 10) -> list[tuple[str, int, int]]:
        """(host, problemas, severidade máxima) ordenado por volume."""
        contagem: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for g in self._relevantes:
            contagem[g.host][0] += g.problemas
            contagem[g.host][1] = max(contagem[g.host][1], g.severidade)
        ordenado = sorted(contagem.items(), key=lambda item: -item[1][0])
        return [(host, p, s) for host, (p, s) in ordenado[:limite] if p]


# ---------------------------------------------------------------------------
# Coleta
# ---------------------------------------------------------------------------

def _tags(bruto: Any) -> dict[str, str]:
    if not isinstance(bruto, list):
        return {}
    return {str(t.get("tag", "")).strip().lower(): str(t.get("value", "")).strip()
            for t in bruto if isinstance(t, dict) and t.get("tag")}


def _severidade(valor: Any) -> int:
    try:
        sev = int(valor)
    except (TypeError, ValueError):
        return 0
    return sev if 0 <= sev <= 5 else 0


def _evento(bruto: dict[str, Any], host: Optional[dict[str, Any]] = None) -> Evento:
    if host is None:
        host = next((h for h in bruto.get("hosts") or [] if isinstance(h, dict)), {})
    return Evento(
        eventid=str(bruto.get("eventid", "")),
        objectid=str(bruto.get("objectid", "")),
        clock=int(bruto.get("clock", 0)),
        problema_ativo=str(bruto.get("value", "1")) == "1",
        severidade=_severidade(bruto.get("severity")),
        host=str(host.get("name") or host.get("host") or "Desconhecido"),
        host_tecnico=str(host.get("host") or ""),
        problema=str(bruto.get("name") or "Sem descrição"),
        tags=_tags(bruto.get("tags")),
    )


def buscar_ativos(client, severidade_min: int = 0) -> tuple[list[Evento], list[str]]:
    """Problemas abertos agora, com o host resolvido via trigger."""
    avisos: list[str] = []
    problemas = client._call("problem.get", {
        "output": ["eventid", "objectid", "clock", "name", "severity"],
        "source": 0,
        "object": 0,
        "selectTags": "extend",
        "severities": list(range(severidade_min, 6)),
        "sortfield": ["eventid"],
        "sortorder": "DESC",
        "limit": LIMITE_POR_CHAMADA,
    })
    if len(problemas) >= LIMITE_POR_CHAMADA:
        avisos.append(f"Limite de {LIMITE_POR_CHAMADA} problemas atingido; resultado pode estar incompleto.")

    trigger_ids = sorted({p["objectid"] for p in problemas if p.get("objectid")})
    hosts_por_trigger: dict[str, dict[str, Any]] = {}
    if trigger_ids:
        triggers = client._call("trigger.get", {
            "triggerids": trigger_ids,
            "output": ["triggerid"],
            "selectHosts": ["hostid", "host", "name"],
        })
        for t in triggers:
            hosts = t.get("hosts") or []
            if hosts:
                hosts_por_trigger[t["triggerid"]] = hosts[0]

    eventos = [_evento(p, hosts_por_trigger.get(p.get("objectid"), {})) for p in problemas]
    eventos.sort(key=lambda e: e.clock)
    return eventos, avisos


def buscar_historico(client, inicio_ts: int, fim_ts: int,
                     severidade_min: int = 0) -> tuple[list[Evento], list[str]]:
    """Transições de trigger na janela; fatias que lotam o limite são subdivididas."""
    if fim_ts < inicio_ts:
        raise ValueError("O fim da janela deve ser posterior ao início.")
    avisos: list[str] = []
    vistos: dict[str, Evento] = {}
    pendentes = [(inicio_ts, fim_ts)]
    while pendentes:
        de, ate = pendentes.pop()
        lote = client._call("event.get", {
            "output": ["eventid", "objectid", "clock", "value", "name", "severity"],
            "source": 0,
            "object": 0,
            "selectHosts": ["hostid", "host", "name"],
            "selectTags": "extend",
            "severities": list(range(severidade_min, 6)),
            "time_from": de,
            "time_till": ate,
            "sortfield": ["clock", "eventid"],
            "sortorder": "ASC",
            "limit": LIMITE_POR_CHAMADA,
        })
        if len(lote) >= LIMITE_POR_CHAMADA:
            if ate - de > MIN_FATIA_S:
                meio = (de + ate) // 2
                pendentes += [(de, meio), (meio + 1, ate)]
                continue
            avisos.append(f"Mais de {LIMITE_POR_CHAMADA} eventos em {MIN_FATIA_S}s a partir de "
                          f"{datetime.fromtimestamp(de, FUSO):%d/%m %H:%M}; parte pode ter ficado de fora.")
        for bruto in lote:
            evento = _evento(bruto)
            vistos[evento.eventid] = evento
    eventos = sorted(vistos.values(), key=lambda e: (e.clock, e.eventid))
    return eventos, avisos


# ---------------------------------------------------------------------------
# Filtro e agrupamento
# ---------------------------------------------------------------------------

def filtrar(eventos: Iterable[Evento], termos: Iterable[str] = (), excluir: Iterable[str] = (),
            escopo: str = "todos") -> list[Evento]:
    """Mantém eventos que contêm TODOS os termos e nenhum termo excluído."""
    if escopo not in ESCOPOS:
        raise ValueError(f"escopo deve ser um de {ESCOPOS}")
    incluir_n = [normalizar(t) for t in termos if t.strip()]
    excluir_n = [normalizar(t) for t in excluir if t.strip()]
    resultado = []
    for e in eventos:
        if escopo == "infra" and e.eh_cliente:
            continue
        if escopo == "clientes" and not e.eh_cliente:
            continue
        texto = e.texto_busca()
        if all(t in texto for t in incluir_n) and not any(t in texto for t in excluir_n):
            resultado.append(e)
    return resultado


def agrupar(eventos: Iterable[Evento]) -> list[Grupo]:
    grupos: dict[tuple[str, str], Grupo] = {}
    for e in sorted(eventos, key=lambda ev: (ev.clock, ev.eventid)):
        chave = (e.objectid or e.problema, e.host)
        if chave not in grupos:
            grupos[chave] = Grupo(host=e.host, problema=e.problema)
        grupos[chave].eventos.append(e)
    return list(grupos.values())


def para_alertas(grupos: Iterable[Grupo]) -> list[Alerta]:
    """Converte grupos em `Alerta` para reaproveitar correlator e analyzer."""
    alertas = []
    for g in grupos:
        ult = g.ultimo
        inicio_ev = next((e for e in reversed(g.eventos) if e.problema_ativo), g.primeiro)
        alerta = Alerta(
            status=PROBLEMA if g.ativo else RESOLVIDO,
            equipamento=g.host,
            problema=g.problema,
            severidade=g.severidade,
            nivel=SEVERIDADES[g.severidade],
            inicio=inicio_ev.horario.replace(tzinfo=None),
            tags=dict(ult.tags),
        )
        if not g.ativo:
            alerta.fim = ult.horario.replace(tzinfo=None)
        alertas.append(alerta)
    return alertas


# ---------------------------------------------------------------------------
# Formatação
# ---------------------------------------------------------------------------

def _periodo(resumo: Resumo) -> str:
    if resumo.inicio is None:
        return f"situação em {resumo.fim:%d/%m/%Y %H:%M:%S}"
    return f"{resumo.inicio:%d/%m/%Y %H:%M:%S} até {resumo.fim:%d/%m/%Y %H:%M:%S}"


def formatar_texto(resumo: Resumo, max_linhas: int = 30) -> str:
    infra = [g for g in resumo.grupos if not g.eh_cliente]
    clientes = [g for g in resumo.grupos if g.eh_cliente]
    linhas = [
        f"📡 {resumo.titulo}",
        f"🕒 {_periodo(resumo)}",
        f"📊 {resumo.total_eventos} evento(s) | {len(infra)} problema(s) de infraestrutura | "
        f"{len(clientes)} de clientes/ONU | {len(resumo.ativos)} ativo(s)",
    ]
    linhas += [f"⚠️ {a}" for a in resumo.avisos]

    ativos_infra = [g for g in resumo.ativos if not g.eh_cliente]
    linhas.append(f"\n🔴 ATIVOS — INFRAESTRUTURA ({len(ativos_infra)})")
    if not ativos_infra:
        linhas.append("  Nenhum.")
    for g in ativos_infra[:max_linhas]:
        linhas.append(f"  • [{SEVERIDADES[g.severidade]}] {g.host} — {g.problema} "
                      f"(desde {g.ultimo.horario:%d/%m %H:%M})")
    if len(ativos_infra) > max_linhas:
        linhas.append(f"  ... e mais {len(ativos_infra) - max_linhas}.")

    ativos_cli = [g for g in resumo.ativos if g.eh_cliente]
    if ativos_cli:
        linhas.append(f"\n👥 ATIVOS — CLIENTES/ONU ({len(ativos_cli)})")
        for g in ativos_cli[:10]:
            linhas.append(f"  • {g.host} — {g.problema}")
        if len(ativos_cli) > 10:
            linhas.append(f"  ... e mais {len(ativos_cli) - 10}.")

    if resumo.inicio is not None:
        if resumo.flapping:
            linhas.append(f"\n🟠 OSCILAÇÕES (≥ {FLAPPING_MIN_PROBLEMAS} quedas)")
            for g in resumo.flapping[:max_linhas]:
                linhas.append(f"  • {g.host} — {g.problema}: {g.problemas}x "
                              f"({g.primeiro.horario:%H:%M} → {g.ultimo.horario:%H:%M})")
        resolvidos = [g for g in infra if not g.ativo and not g.flapping]
        if resolvidos:
            linhas.append(f"\n✅ RESOLVIDOS NA JANELA — INFRAESTRUTURA ({len(resolvidos)})")
            for g in sorted(resolvidos, key=lambda x: (-x.severidade, x.primeiro.clock))[:max_linhas]:
                linhas.append(f"  • [{SEVERIDADES[g.severidade]}] {g.host} — {g.problema} "
                              f"({g.primeiro.horario:%d/%m %H:%M} → {g.ultimo.horario:%H:%M})")
            if len(resolvidos) > max_linhas:
                linhas.append(f"  ... e mais {len(resolvidos) - max_linhas}.")
        top = resumo.top_hosts()
        if top:
            linhas.append("\n🏷️ HOSTS COM MAIS PROBLEMAS")
            for host, qtd, sev in top:
                linhas.append(f"  • {host}: {qtd} (máx. {SEVERIDADES[sev]})")
    return "\n".join(linhas)


def _md(valor: str) -> str:
    return valor.replace("|", "\\|")


def formatar_markdown(resumo: Resumo) -> str:
    linhas = [
        f"# {resumo.titulo}",
        "",
        f"* **Período:** {_periodo(resumo)}",
        f"* **Eventos analisados:** {resumo.total_eventos}",
        f"* **Problemas ativos no fim:** {len(resumo.ativos)}",
        "* **Fuso:** America/Campo_Grande",
        "",
    ]
    linhas += [f"> ⚠️ {a}" for a in resumo.avisos]
    linhas += ["## Problemas ativos", "",
               "| Severidade | Host | Problema | Desde | Tipo |", "|---|---|---|---|---|"]
    for g in resumo.ativos:
        tipo = "Cliente/ONU" if g.eh_cliente else "Infra"
        linhas.append(f"| {SEVERIDADES[g.severidade]} | `{_md(g.host)}` | {_md(g.problema)} | "
                      f"{g.ultimo.horario:%d/%m %H:%M:%S} | {tipo} |")
    if not resumo.ativos:
        linhas.append("| - | *Nenhum* | - | - | - |")

    if resumo.inicio is not None:
        linhas += ["", "## Oscilações", "", "| Host | Problema | Quedas | Primeira | Última |",
                   "|---|---|---|---|---|"]
        for g in resumo.flapping:
            linhas.append(f"| `{_md(g.host)}` | {_md(g.problema)} | {g.problemas} | "
                          f"{g.primeiro.horario:%H:%M:%S} | {g.ultimo.horario:%H:%M:%S} |")
        if not resumo.flapping:
            linhas.append("| *Nenhuma* | - | - | - | - |")

        linhas += ["", "## Todos os problemas da janela", "",
                   "| Severidade | Host | Problema | Quedas | Primeira | Última | Situação |",
                   "|---|---|---|---|---|---|---|"]
        for g in sorted(resumo.grupos, key=lambda x: (x.eh_cliente, -x.severidade, x.primeiro.clock)):
            situacao = "ATIVO" if g.ativo else "Resolvido"
            linhas.append(f"| {SEVERIDADES[g.severidade]} | `{_md(g.host)}` | {_md(g.problema)} | "
                          f"{g.problemas} | {g.primeiro.horario:%d/%m %H:%M:%S} | "
                          f"{g.ultimo.horario:%d/%m %H:%M:%S} | {situacao} |")

        linhas += ["", "## Hosts com mais problemas", "", "| Host | Problemas | Severidade máx. |",
                   "|---|---|---|"]
        for host, qtd, sev in resumo.top_hosts():
            linhas.append(f"| `{_md(host)}` | {qtd} | {SEVERIDADES[sev]} |")
    return "\n".join(linhas) + "\n"


def para_dict(resumo: Resumo) -> dict[str, Any]:
    return {
        "titulo": resumo.titulo,
        "inicio": resumo.inicio.isoformat() if resumo.inicio else None,
        "fim": resumo.fim.isoformat(),
        "total_eventos": resumo.total_eventos,
        "avisos": resumo.avisos,
        "grupos": [{
            "host": g.host,
            "problema": g.problema,
            "severidade": g.severidade,
            "ativo": g.ativo,
            "cliente": g.eh_cliente,
            "quedas": g.problemas,
            "resolucoes": g.resolucoes,
            "primeiro": g.primeiro.horario.isoformat(),
            "ultimo": g.ultimo.horario.isoformat(),
            "tags": g.ultimo.tags,
        } for g in resumo.grupos],
    }
