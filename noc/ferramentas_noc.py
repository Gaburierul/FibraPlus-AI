"""
Catálogo de ferramentas somente leitura (Read-Only) do NOC FibraPlus.

Centraliza todas as consultas que o agente investigativo (Hydrogen/Neon) e os
atalhos rápidos do painel web podem executar sobre Zabbix, IXC Provedor,
Ravicor e logs locais do webhook.

Diretrizes de segurança:
- 100% somente leitura: nenhuma ferramenta altera hosts, triggers, contratos,
  cadastros, arquivos ou executa comandos de shell.
- Dados sensíveis de clientes (CPF/CNPJ, nome civil, telefone, e-mail, endereço,
  senhas e faturas) continuam removidos/mascarados na camada ``clients/ixc.py``.
- Todas as saídas são estruturadas, resumidas e limitadas em tamanho para não
  estourar a janela de contexto do modelo.
"""
from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from noc.consulta import (
    FUSO,
    SEVERIDADES,
    agrupar,
    buscar_ativos,
    buscar_historico,
    filtrar,
)

RAIZ = Path(__file__).resolve().parent.parent
MAX_CHARS_RETORNO_FERRAMENTA = 14_000


def _parse_data_hora_local(texto: str) -> int:
    """Converte 'YYYY-MM-DD HH:MM[:SS]', 'DD/MM/YYYY HH:MM[:SS]' ou 'YYYY-MM-DD' em Unix timestamp."""
    bruto = (texto or "").strip()
    if not bruto:
        raise ValueError("Data/hora vazia.")
    formatos = (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
        "%Y-%m-%d",
        "%d/%m/%Y",
    )
    for fmt in formatos:
        try:
            dt = datetime.strptime(bruto, fmt).replace(tzinfo=FUSO)
            return int(dt.timestamp())
        except ValueError:
            continue
    raise ValueError(
        f"Formato de data/hora inválido: {bruto!r}. Use 'YYYY-MM-DD HH:MM' ou 'DD/MM/YYYY HH:MM'."
    )


def _fmt_clock(clock: Any, formato: str = "%d/%m %H:%M:%S") -> str:
    try:
        ts = int(float(clock))
    except (TypeError, ValueError):
        return "-"
    if ts <= 0:
        return "-"
    return datetime.fromtimestamp(ts, FUSO).strftime(formato)


def _fmt_valor_metrica(nome: str, valor: Any, unidades: str = "") -> str:
    bruto = str(valor if valor is not None else "").strip()
    if not bruto:
        return "-"
    u = (unidades or "").strip()
    nome_low = (nome or "").lower()
    if "bits" in nome_low or u.lower() in {"bps", "b"}:
        try:
            fv = float(bruto)
            if abs(fv) >= 1e9:
                return f"{fv / 1e9:.2f} Gbps"
            if abs(fv) >= 1e6:
                return f"{fv / 1e6:.2f} Mbps"
            if abs(fv) >= 1e3:
                return f"{fv / 1e3:.1f} Kbps"
            return f"{fv:.0f} bps"
        except ValueError:
            pass
    if u:
        return f"{bruto} {u}"
    return bruto


def _truncar_saida(dados: dict[str, Any]) -> str:
    texto = json.dumps(dados, ensure_ascii=False)
    if len(texto) <= MAX_CHARS_RETORNO_FERRAMENTA:
        return texto
    # Reduz listas grandes preservando a estrutura JSON válida
    enxuto = dict(dados)
    for chave, val in list(enxuto.items()):
        if isinstance(val, list) and len(val) > 15:
            enxuto[chave] = val[:15]
            enxuto[f"{chave}_truncado"] = f"Exibindo 15 de {len(val)} itens."
    texto = json.dumps(enxuto, ensure_ascii=False)
    if len(texto) <= MAX_CHARS_RETORNO_FERRAMENTA:
        return texto
    return texto[: MAX_CHARS_RETORNO_FERRAMENTA - 80] + ' ... [saída truncada por limite de tamanho]"}'


# ---------------------------------------------------------------------------
# Rótulos amigáveis para feedback em tempo real na interface (SSE)
# ---------------------------------------------------------------------------

ROTULOS_FERRAMENTAS: dict[str, str] = {
    "zabbix_problemas_ativos": "Consultando problemas ativos no Zabbix",
    "zabbix_historico_eventos": "Consultando histórico de eventos no Zabbix",
    "zabbix_buscar_hosts": "Buscando equipamentos no Zabbix",
    "zabbix_metricas_host": "Lendo métricas e interfaces no Zabbix",
    "zabbix_historico_metrica": "Analisando série temporal de métricas no Zabbix",
    "zabbix_resumo_olt_pon": "Consolidando saúde PON a PON da OLT no Zabbix",
    "ixc_diagnosticar_cliente": "Consultando diagnóstico do cliente no IXC",
    "ixc_historico_radius": "Verificando histórico de sessões Radius (radacct) no IXC",
    "ixc_clientes_fibra": "Cruzando ONUs/fibra por PON ou localidade no IXC",
    "ixc_chamados_recentes": "Consultando Ordens de Serviço no IXC",
    "ravicor_consultar": "Consultando equipamentos e OLTs no Ravicor",
    "noc_saude_e_logs": "Verificando saúde do NOC e logs recentes do webhook",
}


# ---------------------------------------------------------------------------
# Declarações JSON Schema para a Gemini Interactions API (Function Calling)
# ---------------------------------------------------------------------------

TOOLS_DECLARATIONS: list[dict[str, Any]] = [
    {
        "type": "function",
        "name": "zabbix_problemas_ativos",
        "description": (
            "Lista problemas atualmente abertos no Zabbix, com filtros opcionais por "
            "equipamento, cidade, protocolo, escopo (infra, clientes ou todos) e severidade mínima."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "termos": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Termos que precisam casar no host, problema ou tags (ex.: ['POP', 'BGP']).",
                },
                "excluir": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Termos para excluir do resultado.",
                },
                "escopo": {
                    "type": "string",
                    "enum": ["infra", "clientes", "todos"],
                    "description": "Padrão 'infra' para focar em backbone/PE/switch/OLT; use 'clientes' ou 'todos' quando precisar de ONUs.",
                },
                "severidade_min": {
                    "type": "integer",
                    "description": "Severidade mínima Zabbix de 0 a 5 (padrão 2 = Warning).",
                },
                "limite": {
                    "type": "integer",
                    "description": "Máximo de grupos retornados (padrão 40, máx 100).",
                },
            },
        },
    },
    {
        "type": "function",
        "name": "zabbix_historico_eventos",
        "description": (
            "Busca histórico de transições (problemas e resoluções) no Zabbix em uma janela "
            "de tempo, identificando oscilações (flapping) e hosts com mais quedas."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "horas": {
                    "type": "number",
                    "description": "Últimas N horas até agora (padrão 2; máx 168). Ignorado se desde/ate forem informados.",
                },
                "desde": {
                    "type": "string",
                    "description": "Início da janela no fuso America/Campo_Grande, ex.: '2026-11-18 05:30'.",
                },
                "ate": {
                    "type": "string",
                    "description": "Fim da janela no fuso America/Campo_Grande (padrão: agora).",
                },
                "termos": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filtros de inclusão (host, cidade, protocolo, tag).",
                },
                "excluir": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filtros de exclusão.",
                },
                "escopo": {
                    "type": "string",
                    "enum": ["infra", "clientes", "todos"],
                    "description": "Padrão 'infra'.",
                },
                "severidade_min": {
                    "type": "integer",
                    "description": "Severidade mínima de 0 a 5 (padrão 2).",
                },
                "limite": {
                    "type": "integer",
                    "description": "Máximo de grupos detalhados (padrão 40, máx 100).",
                },
            },
        },
    },
    {
        "type": "function",
        "name": "zabbix_buscar_hosts",
        "description": "Procura hosts cadastrados no Zabbix por parte do nome, sigla de cidade/POP ou função (ex.: 'POP', 'OLT', 'BNG', 'PE01').",
        "parameters": {
            "type": "object",
            "properties": {
                "busca": {
                    "type": "string",
                    "description": "Trecho do nome do equipamento ou sigla da cidade/POP.",
                },
                "limite": {
                    "type": "integer",
                    "description": "Máximo de hosts (padrão 30, máx 100).",
                },
            },
            "required": ["busca"],
        },
    },
    {
        "type": "function",
        "name": "zabbix_metricas_host",
        "description": (
            "Consulta valores atuais de métricas (item.get) de um host no Zabbix: tráfego de interfaces "
            "(Bits), utilização, erros, descartes, status operacional, sinal óptico, temperatura, CPU, uptime ou VLANs."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "host": {
                    "type": "string",
                    "description": "Nome exato, parcial ou hostid do equipamento no Zabbix.",
                },
                "filtros": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Lista de trechos de nome de métrica para filtrar (qualquer um casa, ex.: ['Eth-Trunk', 'Temperatura', 'Uptime']).",
                },
                "filtro_chave": {
                    "type": "string",
                    "description": "Opcional: filtro parcial por key_ do Zabbix (ex.: 'onu.rx', 'onu.status').",
                },
                "limite": {
                    "type": "integer",
                    "description": "Máximo de métricas retornadas (padrão 60, máx 150).",
                },
            },
            "required": ["host"],
        },
    },
    {
        "type": "function",
        "name": "zabbix_historico_metrica",
        "description": (
            "Consulta série temporal (history.get ou trend.get) de métricas específicas de um host "
            "em uma janela de tempo, retornando mínimo, máximo, média e pontos amostrados na linha do tempo."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "host": {
                    "type": "string",
                    "description": "Nome exato, parcial ou hostid do equipamento no Zabbix.",
                },
                "filtros_metrica": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Trechos para selecionar os itens desejados (ex.: ['Vlanif617', 'Bits'] ou ['onu.rx']).",
                },
                "horas": {
                    "type": "number",
                    "description": "Últimas N horas até agora (padrão 3). Ignorado se 'desde' for informado.",
                },
                "desde": {
                    "type": "string",
                    "description": "Início no fuso America/Campo_Grande, ex.: '2026-11-18 05:30'.",
                },
                "ate": {
                    "type": "string",
                    "description": "Fim no fuso America/Campo_Grande (padrão: agora).",
                },
                "max_itens": {
                    "type": "integer",
                    "description": "Máximo de métricas consultadas (padrão 8, máx 15).",
                },
            },
            "required": ["host", "filtros_metrica"],
        },
    },
    {
        "type": "function",
        "name": "zabbix_resumo_olt_pon",
        "description": (
            "Faz diagnóstico consolidado de uma OLT (ZTE GPON ou VSOL EPON): mostra totais de ONUs "
            "provisionadas, online, LOSS, DyingGasp e offline por porta PON, além das triggers de infra e "
            "distribuição das quedas de clientes por motivo (-80 LOS vs -90 DyingGasp/Energia vs Sinal alto)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "host_olt": {
                    "type": "string",
                    "description": "Nome exato, parcial ou hostid da OLT no Zabbix (ex.: 'LAB-POP-ZTE-OLT01').",
                },
            },
            "required": ["host_olt"],
        },
    },
    {
        "type": "function",
        "name": "ixc_diagnosticar_cliente",
        "description": (
            "Consulta completa e sanitizada (LGPD) de um cliente no IXC Provedor por login PPPoE, "
            "MAC, serial da ONU, IP ou #id_cliente. Retorna status Radius, sinal óptico RX/TX e porta PON, "
            "situação contratual (diferenciando falha técnica de bloqueio financeiro/administrativo) e Ordens de Serviço abertas."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "termo": {
                    "type": "string",
                    "description": "Login PPPoE, MAC, serial de ONU (ex.: 'ZTEG...'), IP ou '#id_cliente'.",
                },
            },
            "required": ["termo"],
        },
    },
    {
        "type": "function",
        "name": "ixc_historico_radius",
        "description": (
            "Consulta o histórico de sessões Radius na tabela radacct do IXC por login, IP exato, "
            "prefixo de IP (ex.: '198.51.100.') ou MAC. Útil para ver horários de queda, motivo de desconexão "
            "(acctterminatecause), NAS e qual login usava determinado IP."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "username": {
                    "type": "string",
                    "description": "Login PPPoE exato para buscar sessões recentes.",
                },
                "ip": {
                    "type": "string",
                    "description": "IPv4 exato ou prefixo (se prefixo_ip=true, ex.: '198.51.100.').",
                },
                "prefixo_ip": {
                    "type": "boolean",
                    "description": "Quando true, usa busca por prefixo (operador LIKE 'L') no campo framedipaddress.",
                },
                "mac": {
                    "type": "string",
                    "description": "MAC do roteador/CPE (callingstationid).",
                },
                "limite": {
                    "type": "integer",
                    "description": "Quantidade de sessões (padrão 20, máx 50).",
                },
            },
        },
    },
    {
        "type": "function",
        "name": "ixc_clientes_fibra",
        "description": (
            "Consulta ONUs/fibra sincronizadas no IXC (radpop_radio_cliente_fibra) por porta PON "
            "(ponid), bairro, id_transmissor ou serial/MAC."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "ponid": {"type": "string", "description": "Identificador da porta PON no IXC (ex.: '1/8/13')."},
                "bairro": {"type": "string", "description": "Nome do bairro (busca parcial)."},
                "id_transmissor": {"type": "string", "description": "ID numérico do transmissor/OLT no IXC."},
                "serial_ou_mac": {"type": "string", "description": "Serial da ONU ou MAC."},
                "limite": {"type": "integer", "description": "Máximo de registros (padrão 30, máx 80)."},
            },
        },
    },
    {
        "type": "function",
        "name": "ixc_chamados_recentes",
        "description": (
            "Lista Ordens de Serviço recentes no IXC (su_oss_chamado), já sanitizadas (sem CPF/telefone/e-mail), "
            "filtrando por status (A=Aberto, EN=Encaminhado, AG=Agendado, EX=Em Execução, F=Finalizado) ou termo no título."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "description": "Código de status da O.S. (ex.: 'A', 'EN', 'AG', 'EX', 'F').",
                },
                "termo_titulo": {
                    "type": "string",
                    "description": "Trecho para buscar no título da O.S.",
                },
                "limite": {
                    "type": "integer",
                    "description": "Máximo de chamados (padrão 20, máx 40).",
                },
            },
        },
    },
    {
        "type": "function",
        "name": "ravicor_consultar",
        "description": "Busca dispositivos, concentradoras ou OLTs cadastrados no Ravicor por nome, IP ou grupo.",
        "parameters": {
            "type": "object",
            "properties": {
                "busca": {
                    "type": "string",
                    "description": "Nome, sigla da cidade ou IP (vazio para listar resumo de OLTs e grupos).",
                },
                "limite": {
                    "type": "integer",
                    "description": "Máximo de registros (padrão 25, máx 50).",
                },
            },
        },
    },
    {
        "type": "function",
        "name": "noc_saude_e_logs",
        "description": (
            "Consulta o histórico recente do servidor webhook do NOC (logs/envios.jsonl e logs/webhook.log) "
            "e opcionalmente testa a conectividade atual com Zabbix e IXC."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "ultimos_envios": {
                    "type": "integer",
                    "description": "Quantos lotes recentes do webhook retornar (padrão 10, máx 30).",
                },
                "testar_apis": {
                    "type": "boolean",
                    "description": "Quando true, executa ping de leitura nas APIs do Zabbix e do IXC.",
                },
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Implementações das ferramentas
# ---------------------------------------------------------------------------

def _tool_zabbix_problemas_ativos(args: dict[str, Any]) -> dict[str, Any]:
    from clients.zabbix import ZabbixClient

    termos = [str(t) for t in (args.get("termos") or []) if str(t).strip()]
    excluir = [str(t) for t in (args.get("excluir") or []) if str(t).strip()]
    escopo = str(args.get("escopo") or "infra").strip().lower()
    if escopo not in {"infra", "clientes", "todos"}:
        escopo = "infra"
    sev_min = max(0, min(int(args.get("severidade_min", 2)), 5))
    limite = max(1, min(int(args.get("limite", 40)), 100))

    with ZabbixClient() as zbx:
        eventos, avisos = buscar_ativos(zbx, severidade_min=sev_min)
    selecionados = filtrar(eventos, termos=termos, excluir=excluir, escopo=escopo)
    grupos = agrupar(selecionados)
    grupos.sort(key=lambda g: (-g.severidade, -g.ultimo.clock))

    infra_total = sum(1 for g in grupos if not g.eh_cliente)
    clientes_total = sum(1 for g in grupos if g.eh_cliente)
    itens = [
        {
            "host": g.host,
            "problema": g.problema,
            "severidade": SEVERIDADES.get(g.severidade, str(g.severidade)),
            "severidade_num": g.severidade,
            "tipo": "cliente" if g.eh_cliente else "infra",
            "desde": g.ultimo.horario.strftime("%d/%m/%Y %H:%M:%S"),
            "tags": g.ultimo.tags,
        }
        for g in grupos[:limite]
    ]
    return {
        "ok": True,
        "consulta_em": datetime.now(FUSO).strftime("%d/%m/%Y %H:%M:%S"),
        "escopo": escopo,
        "total_grupos": len(grupos),
        "total_infra": infra_total,
        "total_clientes": clientes_total,
        "exibindo": len(itens),
        "avisos": avisos,
        "problemas": itens,
    }


def _tool_zabbix_historico_eventos(args: dict[str, Any]) -> dict[str, Any]:
    from clients.zabbix import ZabbixClient

    agora_ts = int(time.time())
    desde_str = str(args.get("desde") or "").strip()
    ate_str = str(args.get("ate") or "").strip()
    if desde_str:
        inicio_ts = _parse_data_hora_local(desde_str)
        fim_ts = _parse_data_hora_local(ate_str) if ate_str else agora_ts
    else:
        horas = float(args.get("horas", 2))
        horas = max(0.1, min(horas, 168.0))
        fim_ts = agora_ts
        inicio_ts = int(fim_ts - horas * 3600)

    if fim_ts < inicio_ts:
        raise ValueError("A data final ('ate') deve ser posterior à data inicial ('desde').")
    if (fim_ts - inicio_ts) > 14 * 86400:
        raise ValueError("Janela máxima permitida para histórico de eventos é de 14 dias.")

    termos = [str(t) for t in (args.get("termos") or []) if str(t).strip()]
    excluir = [str(t) for t in (args.get("excluir") or []) if str(t).strip()]
    escopo = str(args.get("escopo") or "infra").strip().lower()
    if escopo not in {"infra", "clientes", "todos"}:
        escopo = "infra"
    sev_min = max(0, min(int(args.get("severidade_min", 2)), 5))
    limite = max(1, min(int(args.get("limite", 40)), 100))

    with ZabbixClient() as zbx:
        eventos, avisos = buscar_historico(zbx, inicio_ts, fim_ts, severidade_min=sev_min)
    selecionados = filtrar(eventos, termos=termos, excluir=excluir, escopo=escopo)
    grupos = agrupar(selecionados)
    grupos.sort(key=lambda g: (not g.ativo, -g.severidade, -g.problemas, -g.ultimo.clock))

    flapping = [
        {
            "host": g.host,
            "problema": g.problema,
            "quedas": g.problemas,
            "resolucoes": g.resolucoes,
            "ativo": g.ativo,
            "primeira": g.primeiro.horario.strftime("%d/%m %H:%M:%S"),
            "ultima": g.ultimo.horario.strftime("%d/%m %H:%M:%S"),
        }
        for g in sorted((x for x in grupos if x.flapping), key=lambda x: -x.problemas)[:20]
    ]

    cont_host: dict[str, int] = {}
    for g in grupos:
        cont_host[g.host] = cont_host.get(g.host, 0) + g.problemas
    top_hosts = [
        {"host": h, "quedas": q}
        for h, q in sorted(cont_host.items(), key=lambda item: -item[1])[:12]
    ]

    itens = [
        {
            "host": g.host,
            "problema": g.problema,
            "severidade": SEVERIDADES.get(g.severidade, str(g.severidade)),
            "status": "ATIVO" if g.ativo else "RESOLVIDO",
            "ativo": g.ativo,
            "quedas": g.problemas,
            "resolucoes": g.resolucoes,
            "primeiro": g.primeiro.horario.strftime("%d/%m %H:%M:%S"),
            "ultimo": g.ultimo.horario.strftime("%d/%m %H:%M:%S"),
            "duracao_aprox_s": max(0, g.ultimo.clock - g.primeiro.clock) if not g.ativo else None,
            "tags": g.ultimo.tags,
        }
        for g in grupos[:limite]
    ]
    ativos_cnt = sum(1 for g in grupos if g.ativo)
    return {
        "ok": True,
        "periodo": f"{_fmt_clock(inicio_ts, '%d/%m/%Y %H:%M')} até {_fmt_clock(fim_ts, '%d/%m/%Y %H:%M')}",
        "escopo": escopo,
        "eventos_lidos": len(eventos),
        "eventos_filtrados": len(selecionados),
        "total_grupos": len(grupos),
        "ativos_na_janela": ativos_cnt,
        "resolvidos_na_janela": len(grupos) - ativos_cnt,
        "flapping": flapping,
        "top_hosts": top_hosts,
        "grupos": itens,
        "avisos": avisos,
    }


def _tool_zabbix_buscar_hosts(args: dict[str, Any]) -> dict[str, Any]:
    from clients.zabbix import ZabbixClient

    busca = str(args.get("busca") or "").strip()
    limite = max(1, min(int(args.get("limite", 30)), 100))
    with ZabbixClient() as zbx:
        hosts = zbx.get_hosts(search=busca or None, limit=limite, with_interfaces=True)
    lista = []
    for h in hosts:
        ips = sorted({
            str(iface.get("ip", "")).strip()
            for iface in (h.get("interfaces") or [])
            if iface.get("ip") and iface.get("ip") != "127.0.0.1"
        })
        lista.append({
            "hostid": h.get("hostid"),
            "name": h.get("name"),
            "host": h.get("host"),
            "monitorado": str(h.get("status", "0")) == "0",
            "ips": ips,
        })
    return {"ok": True, "busca": busca, "total": len(lista), "hosts": lista}


def _tool_zabbix_metricas_host(args: dict[str, Any]) -> dict[str, Any]:
    from clients.zabbix import ZabbixClient

    host_alvo = str(args.get("host") or "").strip()
    filtros = [str(f).strip().lower() for f in (args.get("filtros") or []) if str(f).strip()]
    filtro_chave = str(args.get("filtro_chave") or "").strip() or None
    limite = max(1, min(int(args.get("limite", 60)), 150))

    with ZabbixClient() as zbx:
        host = zbx.resolve_host(host_alvo)
        if not host:
            return {"ok": False, "erro": f"Host não encontrado no Zabbix: {host_alvo!r}"}
        itens = zbx.get_items(host["hostid"], search_key=filtro_chave, limit=5000)

    filtrados = []
    for it in sorted(itens, key=lambda x: x.get("name", "")):
        nome = it.get("name", "")
        if filtros and not any(p in nome.lower() for p in filtros):
            continue
        filtrados.append({
            "itemid": it.get("itemid"),
            "nome": nome,
            "chave": it.get("key_"),
            "valor_formatado": _fmt_valor_metrica(nome, it.get("lastvalue"), it.get("units", "")),
            "valor_bruto": it.get("lastvalue"),
            "atualizado_em": _fmt_clock(it.get("lastclock")),
        })
    return {
        "ok": True,
        "host": host.get("name") or host.get("host"),
        "hostid": host.get("hostid"),
        "total_encontradas": len(filtrados),
        "exibindo": min(len(filtrados), limite),
        "metricas": filtrados[:limite],
    }


def _tool_zabbix_historico_metrica(args: dict[str, Any]) -> dict[str, Any]:
    from clients.zabbix import ZabbixClient

    host_alvo = str(args.get("host") or "").strip()
    filtros = [str(f).strip().lower() for f in (args.get("filtros_metrica") or []) if str(f).strip()]
    if not filtros:
        return {"ok": False, "erro": "Informe ao menos um trecho em 'filtros_metrica'."}

    agora_ts = int(time.time())
    desde_str = str(args.get("desde") or "").strip()
    ate_str = str(args.get("ate") or "").strip()
    if desde_str:
        inicio_ts = _parse_data_hora_local(desde_str)
        fim_ts = _parse_data_hora_local(ate_str) if ate_str else agora_ts
    else:
        horas = max(0.25, min(float(args.get("horas", 3)), 168.0))
        fim_ts = agora_ts
        inicio_ts = int(fim_ts - horas * 3600)

    max_itens = max(1, min(int(args.get("max_itens", 8)), 15))
    janela_s = fim_ts - inicio_ts
    usar_trends = janela_s > 48 * 3600

    with ZabbixClient() as zbx:
        host = zbx.resolve_host(host_alvo)
        if not host:
            return {"ok": False, "erro": f"Host não encontrado no Zabbix: {host_alvo!r}"}
        todos_itens = zbx.get_items(host["hostid"], limit=5000)

        casados = [
            it for it in sorted(todos_itens, key=lambda x: x.get("name", ""))
            if any(p in (it.get("name", "") + " " + it.get("key_", "")).lower() for p in filtros)
        ]
        series = []
        for it in casados[:max_itens]:
            nome = it.get("name", "")
            units = it.get("units", "")
            vtype = int(it.get("value_type", 0))
            pontos_resumo: list[dict[str, str]] = []
            estatisticas: dict[str, Any] = {}

            if usar_trends and vtype in (0, 3):
                tr = zbx.get_trends(it["itemid"], time_from=inicio_ts, time_till=fim_ts, limit=500)
                if tr:
                    mins = [float(x["value_min"]) for x in tr]
                    maxs = [float(x["value_max"]) for x in tr]
                    avgs = [float(x["value_avg"]) for x in tr]
                    estatisticas = {
                        "fonte": "trend.get",
                        "pontos": len(tr),
                        "min": _fmt_valor_metrica(nome, min(mins), units),
                        "max": _fmt_valor_metrica(nome, max(maxs), units),
                        "media": _fmt_valor_metrica(nome, sum(avgs) / len(avgs), units),
                    }
                    passo = max(1, len(tr) // 16)
                    for x in tr[::passo][:16]:
                        pontos_resumo.append({
                            "hora": _fmt_clock(x["clock"], "%d/%m %H:%M"),
                            "media": _fmt_valor_metrica(nome, x["value_avg"], units),
                            "max": _fmt_valor_metrica(nome, x["value_max"], units),
                        })
            else:
                hist = zbx.get_history(
                    it["itemid"], value_type=vtype, time_from=inicio_ts, time_till=fim_ts, limit=1500
                )
                if hist:
                    if vtype in (0, 3):
                        vals = [float(x["value"]) for x in hist]
                        estatisticas = {
                            "fonte": "history.get",
                            "pontos": len(hist),
                            "min": _fmt_valor_metrica(nome, min(vals), units),
                            "max": _fmt_valor_metrica(nome, max(vals), units),
                            "media": _fmt_valor_metrica(nome, sum(vals) / len(vals), units),
                        }
                    else:
                        estatisticas = {"fonte": "history.get", "pontos": len(hist)}
                    passo = max(1, len(hist) // 18)
                    for x in hist[::passo][:18]:
                        pontos_resumo.append({
                            "hora": _fmt_clock(x["clock"], "%d/%m %H:%M"),
                            "valor": _fmt_valor_metrica(nome, x["value"], units),
                        })

            series.append({
                "nome": nome,
                "chave": it.get("key_"),
                "agora": _fmt_valor_metrica(nome, it.get("lastvalue"), units),
                "estatisticas": estatisticas or {"pontos": 0},
                "amostra_linha_do_tempo": pontos_resumo,
            })

    return {
        "ok": True,
        "host": host.get("name") or host.get("host"),
        "periodo": f"{_fmt_clock(inicio_ts, '%d/%m/%Y %H:%M')} até {_fmt_clock(fim_ts, '%d/%m/%Y %H:%M')}",
        "total_itens_casados": len(casados),
        "series": series,
    }


def _tool_zabbix_resumo_olt_pon(args: dict[str, Any]) -> dict[str, Any]:
    from clients.zabbix import ZabbixClient

    host_olt = str(args.get("host_olt") or "").strip()
    with ZabbixClient() as zbx:
        resumo = zbx.get_pon_summary(host_olt)
    resumo["ok"] = True
    resumo["ultimo_dado_horario"] = _fmt_clock(resumo.get("ultimo_dado_clock"))
    for trig in resumo.get("triggers_infra_ativas", []):
        trig["desde"] = _fmt_clock(trig.get("lastchange"))
    for cli in resumo.get("clientes_ativos_amostra_recente", []):
        cli["desde"] = _fmt_clock(cli.get("lastchange"))
    return resumo


def _tool_ixc_diagnosticar_cliente(args: dict[str, Any]) -> dict[str, Any]:
    from clients.ixc import IXCClient

    termo = str(args.get("termo") or "").strip()
    with IXCClient() as ixc:
        diag = ixc.diagnosticar(termo)
    dados = diag.to_dict()
    dados["ok"] = True
    return dados


def _tool_ixc_historico_radius(args: dict[str, Any]) -> dict[str, Any]:
    from clients.ixc import IXCClient

    username = str(args.get("username") or "").strip() or None
    ip = str(args.get("ip") or "").strip() or None
    mac = str(args.get("mac") or "").strip() or None
    prefixo_ip = bool(args.get("prefixo_ip", False))
    limite = max(1, min(int(args.get("limite", 20)), 50))
    if not (username or ip or mac):
        return {"ok": False, "erro": "Informe ao menos 'username', 'ip' ou 'mac'."}

    with IXCClient() as ixc:
        sessoes = ixc.buscar_sessoes_radius(
            username=username, ip=ip, mac=mac, prefixo_ip=prefixo_ip, rp=limite
        )
    return {
        "ok": True,
        "total": len(sessoes),
        "sessoes": sessoes,
    }


def _tool_ixc_clientes_fibra(args: dict[str, Any]) -> dict[str, Any]:
    from clients.ixc import IXCClient

    ponid = str(args.get("ponid") or "").strip() or None
    bairro = str(args.get("bairro") or "").strip() or None
    id_transmissor = str(args.get("id_transmissor") or "").strip() or None
    serial_ou_mac = str(args.get("serial_ou_mac") or "").strip() or None
    limite = max(1, min(int(args.get("limite", 30)), 80))

    with IXCClient() as ixc:
        if serial_ou_mac:
            registros = ixc.buscar_fibra(serial_ou_mac=serial_ou_mac, rp=limite)
        else:
            registros = ixc.buscar_fibra_por_pon_ou_local(
                ponid=ponid, bairro=bairro, id_transmissor=id_transmissor, rp=limite
            )
    return {"ok": True, "total": len(registros), "registros": registros}


def _tool_ixc_chamados_recentes(args: dict[str, Any]) -> dict[str, Any]:
    from clients.ixc import IXCClient

    status = str(args.get("status") or "").strip() or None
    termo = str(args.get("termo_titulo") or "").strip() or None
    limite = max(1, min(int(args.get("limite", 20)), 40))

    with IXCClient() as ixc:
        chamados = ixc.buscar_chamados_recentes(status=status, termo_titulo=termo, rp=limite)
    return {"ok": True, "total": len(chamados), "chamados": chamados}


def _tool_ravicor_consultar(args: dict[str, Any]) -> dict[str, Any]:
    from clients.ravicor import RavicorClient

    busca = str(args.get("busca") or "").strip()
    limite = max(1, min(int(args.get("limite", 25)), 50))

    with RavicorClient() as ravi:
        if busca:
            encontrados = ravi.search_devices(busca, limite=limite)
            return {"ok": True, "busca": busca, "total": len(encontrados), "itens": encontrados}
        concentradoras = [
            {
                "id": c.get("id"),
                "nome": c.get("nome") or c.get("name"),
                "ip": c.get("ip"),
                "status": c.get("status_descricao") or c.get("status"),
                "usuarios_online": c.get("usuarios_online"),
                "total_usuarios": c.get("total_usuarios"),
                "ultima_sincronizacao": c.get("ultima_sincronizacao"),
            }
            for c in ravi.list_concentradoras()
            if isinstance(c, dict)
        ]
        olts = ravi.list_olts()
        grupos = ravi.list_device_groups()
        return {
            "ok": True,
            "total_concentradoras": len(concentradoras),
            "concentradoras": concentradoras[:20],
            "total_olts": len(olts),
            "olts": olts[:25],
            "total_grupos": len(grupos),
            "grupos": grupos[:25],
        }


def _tool_noc_saude_e_logs(args: dict[str, Any]) -> dict[str, Any]:
    ultimos = max(1, min(int(args.get("ultimos_envios", 10)), 30))
    testar_apis = bool(args.get("testar_apis", False))

    envios_path = RAIZ / "logs" / "envios.jsonl"
    envios: list[dict[str, Any]] = []
    if envios_path.exists():
        linhas = envios_path.read_text(encoding="utf-8", errors="replace").splitlines()
        for linha in linhas[-ultimos:]:
            try:
                envios.append(json.loads(linha))
            except ValueError:
                continue

    webhook_path = RAIZ / "logs" / "webhook.log"
    ultimos_eventos: list[str] = []
    if webhook_path.exists():
        linhas = webhook_path.read_text(encoding="utf-8", errors="replace").splitlines()
        for linha in reversed(linhas):
            if "Recebido" in linha and ("PROBLEMA" in linha or "RESOLVIDO" in linha):
                partes = linha.split("INFO noc.webhook:")
                ultimos_eventos.append(partes[1].strip() if len(partes) > 1 else linha.strip())
                if len(ultimos_eventos) >= 12:
                    break
        ultimos_eventos.reverse()

    resultado: dict[str, Any] = {
        "ok": True,
        "verificado_em": datetime.now(FUSO).strftime("%d/%m/%Y %H:%M:%S"),
        "envios_recentes": envios,
        "ultimos_alertas_webhook": ultimos_eventos,
    }

    if testar_apis:
        apis: dict[str, dict[str, Any]] = {}
        try:
            from clients.zabbix import ZabbixClient
            t0 = time.monotonic()
            with ZabbixClient() as zbx:
                zbx.get_hosts(limit=1)
            apis["zabbix"] = {"ok": True, "latencia_ms": round((time.monotonic() - t0) * 1000)}
        except Exception as exc:  # noqa: BLE001
            apis["zabbix"] = {"ok": False, "erro": str(exc)[:180]}

        try:
            from clients.ixc import IXCClient
            t0 = time.monotonic()
            with IXCClient() as ixc:
                ixc.listar("radusuarios", "id", "1", oper="=", rp=1)
            apis["ixc"] = {"ok": True, "latencia_ms": round((time.monotonic() - t0) * 1000)}
        except Exception as exc:  # noqa: BLE001
            apis["ixc"] = {"ok": False, "erro": str(exc)[:180]}

        resultado["conectividade_apis"] = apis

    return resultado


_HANDLERS = {
    "zabbix_problemas_ativos": _tool_zabbix_problemas_ativos,
    "zabbix_historico_eventos": _tool_zabbix_historico_eventos,
    "zabbix_buscar_hosts": _tool_zabbix_buscar_hosts,
    "zabbix_metricas_host": _tool_zabbix_metricas_host,
    "zabbix_historico_metrica": _tool_zabbix_historico_metrica,
    "zabbix_resumo_olt_pon": _tool_zabbix_resumo_olt_pon,
    "ixc_diagnosticar_cliente": _tool_ixc_diagnosticar_cliente,
    "ixc_historico_radius": _tool_ixc_historico_radius,
    "ixc_clientes_fibra": _tool_ixc_clientes_fibra,
    "ixc_chamados_recentes": _tool_ixc_chamados_recentes,
    "ravicor_consultar": _tool_ravicor_consultar,
    "noc_saude_e_logs": _tool_noc_saude_e_logs,
}


def executar_ferramenta(nome: str, argumentos: dict[str, Any] | None = None) -> tuple[bool, str, str]:
    """Executa uma ferramenta somente leitura do catálogo e retorna ``(ok, json_resultado, resumo_curto)``."""
    handler = _HANDLERS.get(nome)
    if handler is None:
        erro_json = json.dumps({"ok": False, "erro": f"Ferramenta desconhecida: {nome!r}"}, ensure_ascii=False)
        return False, erro_json, f"Ferramenta desconhecida: {nome}"

    args_seguros = argumentos if isinstance(argumentos, dict) else {}
    try:
        dados = handler(args_seguros)
        ok = bool(dados.get("ok", True))
        resumo = _resumir_execucao(nome, dados)
        return ok, _truncar_saida(dados), resumo
    except Exception as exc:  # noqa: BLE001
        msg = f"{type(exc).__name__}: {str(exc)[:220]}"
        erro_json = json.dumps({"ok": False, "erro": msg}, ensure_ascii=False)
        return False, erro_json, msg


def _resumir_execucao(nome: str, dados: dict[str, Any]) -> str:
    if not dados.get("ok", True):
        return str(dados.get("erro", "Falha na consulta"))[:140]
    if nome == "zabbix_problemas_ativos":
        return f"{dados.get('total_infra', 0)} infra / {dados.get('total_clientes', 0)} clientes ativos"
    if nome == "zabbix_historico_eventos":
        return f"{dados.get('total_grupos', 0)} grupos ({dados.get('ativos_na_janela', 0)} ativos)"
    if nome == "zabbix_buscar_hosts":
        return f"{dados.get('total', 0)} hosts encontrados"
    if nome == "zabbix_metricas_host":
        return f"{dados.get('total_encontradas', 0)} métricas em {dados.get('host', '?')}"
    if nome == "zabbix_historico_metrica":
        return f"{len(dados.get('series') or [])} séries analisadas em {dados.get('host', '?')}"
    if nome == "zabbix_resumo_olt_pon":
        tot = dados.get("totais") or {}
        return f"{dados.get('host', '?')}: {tot.get('online', 0)}/{tot.get('provisionadas', 0)} online, {tot.get('loss', 0)} LOSS"
    if nome == "ixc_diagnosticar_cliente":
        return f"{dados.get('status_operacional', '?')} — {dados.get('termo_buscado', '?')}"
    if nome == "ixc_historico_radius":
        return f"{dados.get('total', 0)} sessões radacct"
    if nome == "ixc_clientes_fibra":
        return f"{dados.get('total', 0)} registros de fibra"
    if nome == "ixc_chamados_recentes":
        return f"{dados.get('total', 0)} Ordens de Serviço"
    if nome == "ravicor_consultar":
        if "total" in dados:
            return f"{dados.get('total', 0)} registros encontrados no Ravicor"
        return (
            f"{dados.get('total_concentradoras', 0)} concentradoras, "
            f"{dados.get('total_olts', 0)} OLTs e {dados.get('total_grupos', 0)} grupos"
        )
    if nome == "noc_saude_e_logs":
        return f"{len(dados.get('envios_recentes') or [])} lotes recentes do webhook"
    return "Consulta concluída"
