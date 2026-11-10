"""
Enriquecimento opcional das ocorrências com dados ao vivo do Zabbix e do IXC Provedor.

Para cada equipamento citado nos alertas, consulta o Zabbix e traz:
* As TAGS do problema (backbone/edge = 1/2/3), que não vêm na mensagem do WhatsApp.
* Se o problema ainda está ATIVO no Zabbix neste momento.

Para logins/circuitos de clientes, ``cruzar_com_ixc`` consulta o IXC Provedor em modo
somente leitura (Radius, ONU/sinal, contrato/bloqueio e O.S. abertas).

É totalmente tolerante a falhas: se o Zabbix ou o IXC estiverem fora, a análise
segue sem travar nem derrubar o fluxo principal.
"""
from __future__ import annotations

import re
import threading
import time
from collections.abc import Iterable
from typing import TYPE_CHECKING

from noc.correlator import Correlacao, Ocorrencia, decompor_hostname
from noc.parser import PROBLEMA, normalizar

if TYPE_CHECKING:
    from clients.ixc import DiagnosticoIXC, IXCClient

_MACRO_RE = re.compile(r"\{[A-Z#$][A-Z0-9_.#:]*\}")
_CACHE_IXC: dict[str, tuple[float, DiagnosticoIXC]] = {}
_CACHE_LOCK = threading.Lock()
_MAX_ITENS_CACHE_IXC = 500


def _padrao_nome(problema: str) -> re.Pattern:
    """Converte o nome (que pode ter macros não resolvidas) em regex de comparação."""
    partes = _MACRO_RE.split(problema)
    regex = ".*".join(re.escape(normalizar(p)) for p in partes)
    return re.compile(f"^{regex}$")


def enriquecer_com_zabbix(correlacao: Correlacao, zabbix_client=None) -> list[str]:
    """
    Preenche `tags` e `ativo_no_zabbix` das ocorrências. Retorna lista de mensagens de log.
    """
    logs: list[str] = []
    try:
        if zabbix_client is None:
            from clients.zabbix import ZabbixClient
            zabbix_client = ZabbixClient()
    except Exception as exc:  # noqa: BLE001
        return [f"Enriquecimento Zabbix desativado: {exc}"]

    ocorrencias = correlacao.ocorrencias
    nomes_hosts = sorted({o.equipamento for o in ocorrencias})
    if not nomes_hosts:
        return logs

    try:
        hosts = zabbix_client._call("host.get", {
            "output": ["hostid", "host", "name"],
            "filter": {"host": nomes_hosts},
        })
    except Exception as exc:  # noqa: BLE001
        return [f"Falha ao consultar hosts no Zabbix: {exc}"]

    id_por_nome = {h["host"].lower(): h["hostid"] for h in hosts}
    id_por_nome.update({h["name"].lower(): h["hostid"] for h in hosts})
    nao_encontrados = [n for n in nomes_hosts if n.lower() not in id_por_nome]
    if nao_encontrados:
        logs.append(f"Hosts não encontrados no Zabbix: {', '.join(nao_encontrados)}")
    if not hosts:
        return logs

    try:
        problemas = zabbix_client._call("problem.get", {
            "output": ["eventid", "name", "severity", "clock", "objectid"],
            "hostids": list({h["hostid"] for h in hosts}),
            "selectTags": "extend",
            "recent": True,
        })
        gatilhos = zabbix_client._call("trigger.get", {
            "output": ["triggerid"],
            "triggerids": list({p["objectid"] for p in problemas}) or ["0"],
            "selectHosts": ["hostid"],
        }) if problemas else []
    except Exception as exc:  # noqa: BLE001
        return logs + [f"Falha ao consultar problemas no Zabbix: {exc}"]

    host_por_trigger = {t["triggerid"]: t["hosts"][0]["hostid"] for t in gatilhos if t.get("hosts")}
    problemas_por_host: dict[str, list[dict]] = {}
    for p in problemas:
        hid = host_por_trigger.get(p["objectid"])
        if hid:
            problemas_por_host.setdefault(hid, []).append(p)

    casados = 0
    for o in ocorrencias:
        hid = id_por_nome.get(o.equipamento.lower())
        if not hid:
            continue
        padrao = _padrao_nome(o.problema)
        candidatos = [p for p in problemas_por_host.get(hid, []) if padrao.match(normalizar(p["name"]))]
        o.ativo_no_zabbix = bool(candidatos)
        if candidatos:
            casados += 1
            for p in candidatos:
                for t in p.get("tags", []):
                    o.tags.setdefault(t["tag"].lower(), t["value"])
        else:
            _tags_da_trigger(zabbix_client, hid, padrao, o, logs)

    logs.append(f"Zabbix: {casados}/{len(ocorrencias)} ocorrências ainda ativas e enriquecidas com tags.")
    return logs


def _tags_da_trigger(zabbix_client, hostid: str, padrao: re.Pattern,
                     o: Ocorrencia, logs: list[str]) -> None:
    """Se o problema já resolveu, ainda tenta buscar as tags na definição da trigger."""
    try:
        triggers = zabbix_client._call("trigger.get", {
            "output": ["description"],
            "hostids": [hostid],
            "selectTags": "extend",
            "expandDescription": True,
            "limit": 500,
        })
    except Exception:  # noqa: BLE001
        return
    for t in triggers:
        if padrao.match(normalizar(t.get("description", ""))):
            for tag in t.get("tags", []):
                o.tags.setdefault(tag["tag"].lower(), tag["value"])
            return


def limpar_cache_ixc() -> None:
    """Limpa o cache em memória de diagnósticos do IXC."""
    with _CACHE_LOCK:
        _CACHE_IXC.clear()


def _diagnosticar_com_cache(
    ixc_client: IXCClient,
    termo: str,
    usar_cache: bool = False,
    ttl_s: float = 600.0,
) -> DiagnosticoIXC:
    chave = termo.strip().lower()
    agora = time.monotonic()
    if usar_cache and ttl_s > 0:
        with _CACHE_LOCK:
            item = _CACHE_IXC.get(chave)
            if item is not None and (agora - item[0]) < ttl_s:
                return item[1]

    diag = ixc_client.diagnosticar(termo)
    if usar_cache and ttl_s > 0:
        with _CACHE_LOCK:
            if len(_CACHE_IXC) >= _MAX_ITENS_CACHE_IXC:
                expirados = [k for k, (ts, _) in _CACHE_IXC.items() if (agora - ts) >= ttl_s]
                for k in expirados:
                    _CACHE_IXC.pop(k, None)
                if len(_CACHE_IXC) >= _MAX_ITENS_CACHE_IXC:
                    mais_antigo = min(_CACHE_IXC, key=lambda k: _CACHE_IXC[k][0])
                    _CACHE_IXC.pop(mais_antigo, None)
            _CACHE_IXC[chave] = (agora, diag)
    return diag


def cruzar_com_ixc(
    termos: Iterable[str],
    ixc_client: IXCClient | None = None,
    limite: int = 5,
    *,
    usar_cache: bool = False,
    ttl_cache_s: float = 600.0,
    prazo_max_s: float | None = None,
) -> tuple[list[DiagnosticoIXC], list[str]]:
    """Cruza uma lista de logins/MACs/seriais/alertas no IXC com tolerância total a falhas.

    Retorna ``(diagnosticos, avisos)``. Nunca propaga exceção caso o IXC esteja
    indisponível ou não configurado.
    """
    avisos: list[str] = []
    diagnosticos: list[DiagnosticoIXC] = []
    try:
        from clients.ixc import extrair_termo_busca
    except Exception as exc:  # noqa: BLE001
        return [], [f"Enriquecimento IXC indisponível: {exc}"]

    unicos: list[str] = []
    vistos: set[str] = set()
    for t in termos:
        chave = extrair_termo_busca(t)
        if chave and chave.lower() not in vistos:
            vistos.add(chave.lower())
            unicos.append(chave)

    if not unicos:
        return diagnosticos, avisos

    criado_aqui = ixc_client is None
    try:
        if ixc_client is None:
            from clients.ixc import IXCClient as _IXCClient
            ixc_client = _IXCClient()
    except Exception as exc:  # noqa: BLE001
        return [], [f"Enriquecimento IXC indisponível: {exc}"]

    limite_efetivo = max(1, min(limite, 20))
    inicio_lote = time.monotonic()
    try:
        for idx, termo in enumerate(unicos[:limite_efetivo]):
            if prazo_max_s is not None and idx > 0 and (time.monotonic() - inicio_lote) >= prazo_max_s:
                avisos.append(
                    f"Orçamento de tempo do IXC ({prazo_max_s:g}s) atingido após {idx} consulta(s)."
                )
                break
            try:
                diagnosticos.append(
                    _diagnosticar_com_cache(
                        ixc_client, termo, usar_cache=usar_cache, ttl_s=ttl_cache_s
                    )
                )
            except Exception as exc:  # noqa: BLE001
                avisos.append(f"Falha ao consultar '{termo}' no IXC: {exc}")
    finally:
        if criado_aqui:
            ixc_client.close()

    if len(unicos) > limite_efetivo:
        avisos.append(
            f"Cruzamento IXC limitado aos primeiros {limite_efetivo} de {len(unicos)} itens "
            "para preservar performance (máx. 20)."
        )
    return diagnosticos, avisos


def formatar_resumo_ixc_lote(
    diagnosticos: list[DiagnosticoIXC],
    total_relacionados: int | None = None,
) -> str:
    """Gera uma frase única, gramaticalmente completa e sem abreviações para o Telegram."""
    if not diagnosticos:
        return ""

    consultados = len(diagnosticos)
    total = max(total_relacionados or consultados, consultados)
    if consultados == 1 and total == 1:
        prefixo = "🔎 Diagnóstico IXC (1 cliente verificado)"
    elif consultados == total:
        prefixo = f"🔎 Diagnóstico IXC ({consultados} clientes verificados)"
    else:
        prefixo = f"🔎 Diagnóstico IXC (amostra de {consultados} de {total} clientes)"

    contagem: dict[str, int] = {}
    causas_queda: list[str] = []
    for d in diagnosticos:
        st = d.status_operacional
        contagem[st] = contagem.get(st, 0) + 1
        if st == "FALHA_TECNICA_OFFLINE":
            for f in d.fibra_onus:
                causa = (f.get("causa_ultima_queda") or "").strip()
                if causa and causa not in {"-", "?"} and causa not in causas_queda:
                    causas_queda.append(causa)
            if not causas_queda:
                for lg in d.logins:
                    motivo = (lg.get("motivo_desconexao") or "").strip()
                    if motivo and motivo not in {"-", "?"} and motivo not in causas_queda:
                        causas_queda.append(motivo)

    partes: list[str] = []
    if n := contagem.get("FALHA_TECNICA_OFFLINE", 0):
        texto_falha = "1 cliente com falha técnica" if n == 1 else f"{n} clientes com falha técnica"
        if len(causas_queda) == 1:
            texto_falha += f" (última queda: {causas_queda[0]})"
        elif len(causas_queda) > 1:
            texto_falha += f" (últimas quedas: {', '.join(causas_queda[:2])})"
        partes.append(texto_falha)

    if n := contagem.get("OS_EM_ANDAMENTO", 0):
        partes.append(
            "1 cliente com Ordem de Serviço em andamento"
            if n == 1
            else f"{n} clientes com Ordens de Serviço em andamento"
        )

    if n := contagem.get("BLOQUEIO_ADMINISTRATIVO", 0):
        partes.append(
            "1 cliente com bloqueio administrativo"
            if n == 1
            else f"{n} clientes com bloqueio administrativo"
        )

    if n := contagem.get("ONLINE_NORMAL", 0):
        partes.append(
            "1 cliente online no Radius"
            if n == 1
            else f"{n} clientes online no Radius"
        )

    if n := contagem.get("CADASTRO_LOCALIZADO", 0):
        partes.append(
            "1 cliente localizado no cadastro"
            if n == 1
            else f"{n} clientes localizados no cadastro"
        )

    if n := contagem.get("NAO_ENCONTRADO", 0):
        partes.append(
            "1 login não localizado no cadastro"
            if n == 1
            else f"{n} logins não localizados no cadastro"
        )

    if not partes:
        return ""
    return f"{prefixo}: {' · '.join(partes)}."


def enriquecer_lote_com_ixc(
    correlacao: Correlacao,
    ixc_client: IXCClient | None = None,
    limite: int = 5,
    ttl_cache_s: float = 600.0,
    prazo_max_s: float = 6.0,
) -> list[str]:
    """Cruza clientes do lote com o IXC somente quando vinculados ao mesmo equipamento/POP da falha de infra.

    Preenche ``correlacao.resumo_ixc`` com uma frase consolidada e retorna mensagens de log.
    Nunca correlaciona quedas de clientes de cidades/POPs diferentes da ocorrência de infraestrutura.
    """
    logs: list[str] = []
    if not correlacao.incidentes or not correlacao.alertas_clientes:
        return logs

    try:
        from clients.ixc import extrair_termo_busca
    except Exception as exc:  # noqa: BLE001
        return [f"Enriquecimento IXC indisponível: {exc}"]

    ocorrencias_infra = [o for o in correlacao.ocorrencias if o.estado != "RESOLVIDO"] or correlacao.ocorrencias
    equipamentos_infra = {
        o.equipamento.strip().lower()
        for o in ocorrencias_infra
        if o.equipamento and o.equipamento.strip()
    }
    sites_infra = {
        o.site.strip().upper()
        for o in ocorrencias_infra
        if o.site and o.site.strip().upper() not in {"", "?", "DESCONHECIDO"}
    }

    logins_relacionados: list[str] = []
    vistos: set[str] = set()
    ignorados_outro_site = 0
    for alerta in correlacao.alertas_clientes:
        if alerta.status != PROBLEMA:
            continue
        eq_cliente = (alerta.equipamento or "").strip().lower()
        site_cliente, _, _ = decompor_hostname(alerta.equipamento or "")
        site_cliente_norm = site_cliente.strip().upper()

        mesmo_equipamento = bool(eq_cliente and eq_cliente in equipamentos_infra)
        mesmo_site = bool(
            site_cliente_norm
            and site_cliente_norm not in {"", "?", "DESCONHECIDO"}
            and site_cliente_norm in sites_infra
        )
        if not (mesmo_equipamento or mesmo_site):
            ignorados_outro_site += 1
            continue

        login = extrair_termo_busca(alerta.problema)
        if login and login.lower() not in vistos:
            vistos.add(login.lower())
            logins_relacionados.append(login)

    if ignorados_outro_site:
        logs.append(
            f"IXC: {ignorados_outro_site} alerta(s) de clientes ignorados por pertencerem a outro site/equipamento."
        )
    if not logins_relacionados:
        return logs

    diagnosticos, avisos = cruzar_com_ixc(
        logins_relacionados,
        ixc_client=ixc_client,
        limite=limite,
        usar_cache=True,
        ttl_cache_s=ttl_cache_s,
        prazo_max_s=prazo_max_s,
    )
    logs.extend(avisos)
    if diagnosticos:
        correlacao.resumo_ixc = formatar_resumo_ixc_lote(
            diagnosticos, total_relacionados=len(logins_relacionados)
        )
        logs.append(
            f"IXC: {len(diagnosticos)}/{len(logins_relacionados)} cliente(s) do mesmo POP/equipamento verificados."
        )
    return logs
