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
from typing import TYPE_CHECKING
from collections.abc import Iterable

from noc.correlator import Correlacao, Ocorrencia
from noc.parser import normalizar

if TYPE_CHECKING:
    from clients.ixc import DiagnosticoIXC, IXCClient

_MACRO_RE = re.compile(r"\{[A-Z#$][A-Z0-9_.#:]*\}")


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


def cruzar_com_ixc(
    termos: Iterable[str],
    ixc_client: IXCClient | None = None,
    limite: int = 5,
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
    try:
        for termo in unicos[:limite_efetivo]:
            try:
                diagnosticos.append(ixc_client.diagnosticar(termo))
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
