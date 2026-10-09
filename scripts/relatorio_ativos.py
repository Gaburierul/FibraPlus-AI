import sys
import os
import time
import argparse
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from clients.zabbix import ZabbixClient
from datetime import datetime, timezone, timedelta
from noc.analyzer import MODELO_PADRAO, THINKING_NIVEIS, THINKING_PADRAO, analisar

try:
    from zoneinfo import ZoneInfo
    FUSO_LOCAL = ZoneInfo("America/Campo_Grande")
except Exception:
    FUSO_LOCAL = timezone(timedelta(hours=-4))

SEVERITY_MAP = {
    "0": "Not classified",
    "1": "Information",
    "2": "Warning",
    "3": "Average",
    "4": "High",
    "5": "Disaster"
}

def main():
    parser = argparse.ArgumentParser(description="Gera relatório de incidentes.")
    parser.add_argument("--horas", type=float, default=0, help="Filtra problemas das últimas X horas.")
    parser.add_argument("--enviar", action="store_true",
                        help="Envia explicitamente o relatório ao mensageiro configurado.")
    modo_ia = parser.add_mutually_exclusive_group()
    modo_ia.add_argument("--usar-ia", action="store_true",
                         help="Autoriza uma chamada ao Gemini para acrescentar hipótese breve.")
    modo_ia.add_argument("--offline", action="store_true",
                         help="Compatibilidade: não chama o Gemini; gera resumo determinístico.")
    parser.add_argument("--modelo", default=MODELO_PADRAO, help="Modelo Gemini.")
    parser.add_argument("--thinking", default=THINKING_PADRAO, choices=THINKING_NIVEIS,
                        help="Nível de raciocínio do Gemini.")
    args = parser.parse_args()
    if args.horas < 0:
        parser.error("--horas deve ser zero ou positivo.")

    try:
        client = ZabbixClient()
    except Exception as e:
        print(f"Erro ao inicializar ZabbixClient: {e}")
        return

    time_from = None
    if args.horas > 0:
        time_from = int(time.time() - (args.horas * 3600))
        print(f"Buscando problemas ativos no Zabbix das últimas {args.horas} horas (Severity >= 2)...")
    else:
        print("Buscando todos os problemas ativos no Zabbix (Severity >= 2)...")
        
    # Fetch active problems with severity >= 2 (Warning or higher)
    limite_problemas = 100
    problems = client.get_problems(limit=limite_problemas, severity_min=2, time_from=time_from)
    
    if not problems:
        print("✅ Nenhum problema ativo encontrado no Zabbix no momento.")
        return

    print(f"Encontrados {len(problems)} problemas ativos.")
    if len(problems) >= limite_problemas:
        print(f"AVISO: a consulta atingiu o limite de {limite_problemas}; o relatório pode estar incompleto.")

    # Get host names for the problems. Problem object has 'objectid' which is triggerid.
    # We need to map triggerid -> host name.
    triggerids = list(set([p["objectid"] for p in problems]))
    
    try:
        triggers = client._call("trigger.get", {
            "triggerids": triggerids,
            "selectHosts": ["hostid", "name"],
            "output": ["triggerid", "description"]
        })
        trigger_map = {t["triggerid"]: t for t in triggers}
    except Exception as e:
        print(f"Erro ao buscar triggers: {e}")
        trigger_map = {}

    out_lines = []
    
    # Sort problems by clock
    problems = sorted(problems, key=lambda x: int(x["clock"]))

    for p in problems:
        t_id = p["objectid"]
        trigger = trigger_map.get(t_id, {})
        hosts = trigger.get("hosts", [])
        host_name = hosts[0]["name"] if hosts else "Desconhecido"
        
        name = p.get("name", "Unknown Problem")
        severity_code = str(p.get("severity", "0"))
        severity = SEVERITY_MAP.get(severity_code, "Average")
        clock = int(p.get("clock", 0))
        dt_str = datetime.fromtimestamp(clock, FUSO_LOCAL).strftime('%H:%M:%S em %Y.%m.%d')
        
        tags = p.get("tags", [])
        tags_str = ", ".join([f"{tag['tag']}: {tag['value']}" for tag in tags])

        # Formatar como mensagem do WhatsApp para o nosso parser
        out_lines.append("🛑🛑 Problema: 🛑🛑")
        out_lines.append(f"Equipamento: {host_name}")
        out_lines.append(f"Nome do problema: {name}")
        out_lines.append(f"Nível: {severity}")
        out_lines.append(f"Iniciado às: {dt_str}")
        if tags_str:
            out_lines.append(f"Tags: {tags_str}")
        out_lines.append("")

    out_text = "\n".join(out_lines)
    
    pasta_logs = Path(__file__).resolve().parent.parent / "logs"
    pasta_logs.mkdir(exist_ok=True)
    filename = pasta_logs / f"alertas_ativos_{datetime.now(FUSO_LOCAL):%Y%m%d_%H%M%S}.txt"
    with filename.open('w', encoding='utf-8') as f:
        f.write(out_text)
        
    print(f"Arquivo gerado: {filename}\n")
    print("Iniciando análise...\n" + "="*50)
    
    # Chamar o analisador
    from noc.parser import parse_alertas
    from noc.correlator import correlacionar
    resultado_parse = parse_alertas(out_text)
    correlacao = correlacionar(resultado_parse.alertas, janela_min=10)
    
    # Mostrar na tela o resumo de fallback
    print(f"Correlacionado em {len(correlacao.incidentes)} incidentes lógicos.\n")
    
    resultado = analisar(correlacao, usar_ia=args.usar_ia, modelo=args.modelo, thinking=args.thinking)
    
    print(resultado.mensagem)
    if not args.usar_ia:
        print("Gemini não foi chamado. Use --usar-ia para pedir uma hipótese breve.")
    print("\n" + "=" * 50)
    
    if not args.enviar:
        print("Relatório não enviado. Use --enviar para autorizar o envio desta execução.")
        return
    # Envia somente quando o usuário opta explicitamente por esta execução.
    mensageiro = os.getenv("NOC_MENSAGEIRO", "telegram").strip().lower()

    try:
        if mensageiro == "evolution":
            from clients.whatsapp import EvolutionClient
            destino = os.getenv("EVOLUTION_GROUP_JID", "")
            if destino:
                EvolutionClient().enviar_texto(destino, resultado.mensagem)
                print("Relatório enviado via Evolution API com sucesso!")
            else:
                print("AVISO: EVOLUTION_GROUP_JID não configurado. Relatório não enviado.")
        elif mensageiro == "telegram":
            from clients.telegram import TelegramClient
            destino = os.getenv("TELEGRAM_CHAT_ID", "")
            if destino:
                TelegramClient().enviar_texto(destino, resultado.mensagem)
                print("Relatório enviado via Telegram com sucesso!")
            else:
                print("AVISO: TELEGRAM_CHAT_ID não configurado. Relatório não enviado.")
        else:
            print(f"NOC_MENSAGEIRO inválido: {mensageiro!r}. Use telegram ou evolution.")
    except Exception as e:
        print(f"Erro ao enviar relatório pelo {mensageiro}: {e}")

if __name__ == "__main__":
    main()
