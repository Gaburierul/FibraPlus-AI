"""
Monitoramento Contínuo de Infraestrutura e Incidentes - FibraPlus AI NOC
Fuso Horário Oficial: America/Campo_Grande (UTC-4)

Execução periódica para:
1. Consultar a API do Zabbix (problemas da janela recente e ativos).
2. Cruzar dados de equipamentos com o Ravicor.
3. Separar quedas de clientes (ONUs) de incidentes de infraestrutura (Backbone, PE, OLT, Switches).
4. Correlacionar eventos temporais.
5. Diagnosticar causa raiz com IA (Gemini) e fallback determinístico.
6. Gravar histórico em logs/monitor_historico.jsonl.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Configuração de caminhos e encoding
RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

for stream in (sys.stdout, sys.stderr):
    try:
        stream.reconfigure(encoding="utf-8")
    except Exception:
        pass

from dotenv import load_dotenv
load_dotenv(RAIZ / ".env")

try:
    import zoneinfo
    FUSO_CAMPO_GRANDE = zoneinfo.ZoneInfo("America/Campo_Grande")
except Exception:
    FUSO_CAMPO_GRANDE = timezone(timedelta(hours=-4))

from clients.zabbix import ZabbixClient
from clients.ravicor import RavicorClient
from noc.parser import parse_alertas
from noc.correlator import correlacionar
from noc.analyzer import MODELO_PADRAO, THINKING_NIVEIS, THINKING_PADRAO, analisar

PASTA_LOGS = RAIZ / "logs"
PASTA_LOGS.mkdir(exist_ok=True)
HISTORICO_PATH = PASTA_LOGS / "monitor_historico.jsonl"

SEVERITY_MAP = {
    "0": "Not classified",
    "1": "Information",
    "2": "Warning",
    "3": "Average",
    "4": "High",
    "5": "Disaster"
}

def carregar_base_ravicor(r_client: RavicorClient) -> dict[str, dict]:
    """Carrega mapa de hosts para cruzamento rápido."""
    ravi_db = {}
    try:
        # Concentradoras
        concentradoras = r_client._call("concentradora", "list").get("data", [])
        for c in concentradoras:
            nome = c.get("nome", "").strip().lower()
            if nome:
                ravi_db[nome] = {"tipo": "Concentradora", "ip": c.get("ip", "N/A"), "dados": c}
        
        # Dispositivos por grupo
        grupos = r_client.list_device_groups()
        for g in grupos:
            devs = r_client.list_devices(group_id=g.get("id"))
            for d in devs:
                nome = d.get("name", "").strip().lower()
                if nome:
                    ravi_db[nome] = {"tipo": "Dispositivo", "ip": d.get("ip", "N/A"), "grupo": g.get("name"), "dados": d}
    except Exception as exc:
        print(f"⚠️ Aviso ao carregar base Ravicor: {exc}")
    return ravi_db

def executar_monitoramento(janela_min: int = 30, usar_ia: bool = True,
                           modelo: str = MODELO_PADRAO, thinking: str = THINKING_PADRAO):
    agora_local = datetime.now(FUSO_CAMPO_GRANDE)
    agora_ts = int(time.time())
    inicio_janela_ts = agora_ts - (janela_min * 60)
    inicio_local = datetime.fromtimestamp(inicio_janela_ts, FUSO_CAMPO_GRANDE)

    print("=" * 75)
    print("📡 [FIBRAPLUS AI NOC] MONITORAMENTO DE INFRAESTRUTURA")
    print(f"🕒 Data/Hora Local: {agora_local.strftime('%Y-%m-%d %H:%M:%S (%Z %z)')}")
    print(f"⏱️  Janela de Análise: Últimos {janela_min} minutos (desde {inicio_local.strftime('%H:%M:%S')})")
    print("=" * 75)

    zabbix = ZabbixClient()
    
    # Conexão com Ravicor
    ravi_db = {}
    try:
        ravicor = RavicorClient()
        ravi_db = carregar_base_ravicor(ravicor)
    except Exception as exc:
        print(f"⚠️ Ravicor indisponível nesta checagem: {exc}")

    # Consulta problemas no Zabbix
    print("🔍 Consultando problemas ativos e recentes no Zabbix...")
    todos_problemas = zabbix.get_problems(limit=150, severity_min=2)

    # Filtrar problemas da janela
    problemas_janela = [p for p in todos_problemas if int(p.get("clock", 0)) >= inicio_janela_ts]
    
    # Separar Clientes vs Infraestrutura
    problemas_clientes = []
    problemas_infra = []

    for p in problemas_janela:
        nome_alerta = p.get("name", "")
        if nome_alerta.lower().startswith("cliente"):
            problemas_clientes.append(p)
        else:
            problemas_infra.append(p)

    print(f"📊 Total de eventos na janela: {len(problemas_janela)}")
    print(f"   ├─ Clientes (ONUs / FTTH): {len(problemas_clientes)}")
    print(f"   └─ Infraestrutura (Backbone / PEs / OLTs / Switches): {len(problemas_infra)}")

    # Se não houver problemas de infraestrutura
    if not problemas_infra and not problemas_clientes:
        print("\n✅ NENHUM INCIDENTE DETECTADO! Toda a infraestrutura está operando normalmente.")
        resultado_log = {
            "timestamp": agora_local.isoformat(),
            "fuso": "America/Campo_Grande",
            "janela_min": janela_min,
            "status": "NORMAL",
            "infra_count": 0,
            "clientes_count": 0,
            "mensagem": "Nenhum incidente detectado na janela."
        }
        with open(HISTORICO_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(resultado_log, ensure_ascii=False) + "\n")
        return resultado_log

    # Mapear triggers para obter os hosts
    trigger_ids = list({p["objectid"] for p in problemas_infra})
    trigger_map = {}
    if trigger_ids:
        triggers = zabbix._call("trigger.get", {
            "triggerids": trigger_ids,
            "selectHosts": ["hostid", "host", "name"],
            "output": ["triggerid", "description"]
        })
        trigger_map = {t["triggerid"]: t for t in triggers}

    # Montar texto dos alertas no formato padrão
    alertas_formatados = []
    detalhes_infra = []

    for p in sorted(problemas_infra, key=lambda x: int(x.get("clock", 0))):
        t_id = p["objectid"]
        hosts_info = trigger_map.get(t_id, {}).get("hosts", [{"name": "Desconhecido", "host": "Desconhecido"}])
        host_obj = hosts_info[0]
        host_name = host_obj.get("name", "Desconhecido")
        host_key = host_obj.get("host", "").lower()
        
        name = p.get("name", "Unknown")
        sev = SEVERITY_MAP.get(str(p.get("severity", "0")), "Average")
        dt_str = datetime.fromtimestamp(int(p.get("clock", 0)), FUSO_CAMPO_GRANDE).strftime("%H:%M:%S em %Y.%m.%d")
        tags_str = ", ".join([f"{t['tag']}: {t['value']}" for t in p.get("tags", [])])

        # Cruzar com Ravicor
        ravi_info = ravi_db.get(host_key) or ravi_db.get(host_name.lower())
        info_extra = ""
        if ravi_info:
            info_extra = f" [Ravicor: {ravi_info['tipo']} | IP: {ravi_info['ip']}]"

        bloco = [
            "🛑🛑 Problema: 🛑🛑",
            f"Equipamento: {host_name}{info_extra}",
            f"Nome do problema: {name}",
            f"Nível: {sev}",
            f"Iniciado às: {dt_str}"
        ]
        if tags_str:
            bloco.append(f"Tags: {tags_str}")
        bloco.append("")
        alertas_formatados.append("\n".join(bloco))

        detalhes_infra.append({
            "equipamento": host_name,
            "problema": name,
            "nivel": sev,
            "horario": dt_str,
            "ravicor": ravi_info
        })

    # Adicionar sumário de ONUs se houver
    if problemas_clientes:
        print(f"\n👥 Detecção de Clientes Isolados: {len(problemas_clientes)} quedas registradas no período.")

    if alertas_formatados:
        texto_alertas = "\n".join(alertas_formatados)
        parse = parse_alertas(texto_alertas)
        correlacao = correlacionar(parse.alertas, janela_min=10)
        
        print("\n🧠 Analisando causa raiz e correlação de incidentes com a IA...")
        analise = analisar(correlacao, usar_ia=usar_ia, modelo=modelo, thinking=thinking)

        print("\n" + "-" * 75)
        print("📋 DIAGNÓSTICO DO INCIDENTE (FIBRAPLUS AI NOC)")
        print("-" * 75)
        print(analise.mensagem)
        print("-" * 75)

        resultado_log = {
            "timestamp": agora_local.isoformat(),
            "fuso": "America/Campo_Grande",
            "janela_min": janela_min,
            "status": "INCIDENTES_DETECTADOS",
            "infra_count": len(problemas_infra),
            "clientes_count": len(problemas_clientes),
            "detalhes": detalhes_infra,
            "origem_analise": analise.origem,
            "mensagem": analise.mensagem
        }
    else:
        print("\nℹ️ Apenas incidentes pontuais de clientes identificados (sem impacto em infraestrutura central).")
        resultado_log = {
            "timestamp": agora_local.isoformat(),
            "fuso": "America/Campo_Grande",
            "janela_min": janela_min,
            "status": "APENAS_CLIENTES",
            "infra_count": 0,
            "clientes_count": len(problemas_clientes),
            "mensagem": f"{len(problemas_clientes)} cliente(s) com queda pontual."
        }

    # Salva no histórico
    with open(HISTORICO_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(resultado_log, ensure_ascii=False) + "\n")

    print(f"\n💾 Registro salvo com sucesso em: {HISTORICO_PATH}")
    return resultado_log

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Monitoramento Contínuo de Infraestrutura e Incidentes")
    parser.add_argument("--janela", type=int, default=30, help="Janela de análise em minutos (padrão: 30)")
    parser.add_argument("--offline", action="store_true", help="Desativar IA e rodar em modo determinístico")
    parser.add_argument("--modelo", type=str, default=MODELO_PADRAO, help="Modelo do Gemini")
    parser.add_argument("--thinking", choices=THINKING_NIVEIS, default=THINKING_PADRAO,
                        help="Nível de raciocínio do Gemini")
    args = parser.parse_args()

    executar_monitoramento(janela_min=args.janela, usar_ia=not args.offline,
                           modelo=args.modelo, thinking=args.thinking)
