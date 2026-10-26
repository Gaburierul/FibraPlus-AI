"""
Script consolidado para verificação rápida do NOC - FibraPlus AI.

Substitui a criação de scripts temporários/avulsos. Centraliza a inspeção de:
1. Status e conectividade da IA (Gemini).
2. Últimos envios e ações registradas no webhook (logs/envios.jsonl).
3. Últimos eventos processados no log (logs/webhook.log).
4. Problemas ativos em tempo real no Zabbix (opcional via --zabbix).

Uso:
  python scripts/verificar_noc.py              # Painel geral consolidado
  python scripts/verificar_noc.py --envios 15  # Lista os últimos 15 envios do webhook
  python scripts/verificar_noc.py --zabbix     # Consulta problemas ativos no Zabbix
  python scripts/verificar_noc.py --ia-teste   # Executa teste ao vivo da API Gemini
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

# Se executado com o Python global fora da .venv, reexecuta automaticamente no ambiente virtual do projeto
VENV_PYTHON = RAIZ / ".venv" / "Scripts" / "python.exe"
if VENV_PYTHON.exists() and Path(sys.executable).resolve() != VENV_PYTHON.resolve():
    import subprocess
    sys.exit(subprocess.run([str(VENV_PYTHON), *sys.argv]).returncode)

for stream in (sys.stdout, sys.stderr):
    try:
        stream.reconfigure(encoding="utf-8")
    except Exception:
        pass

try:
    from dotenv import load_dotenv
    load_dotenv(RAIZ / ".env")
except ImportError:
    env_file = RAIZ / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def _verificar_ia() -> tuple[bool, str]:
    """Testa rapidamente a conectividade com o modelo Gemini configurado."""
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        return False, "GEMINI_API_KEY não configurada no .env"

    modelo = os.getenv("NOC_AI_MODEL", "gemini-3.5-flash-lite")
    try:
        from google import genai
        from google.genai import types

        client = genai.Client(
            api_key=api_key,
            http_options=types.HttpOptions(
                timeout=12000,
                retry_options=types.HttpRetryOptions(attempts=1),
            ),
        )
        t0 = time.time()
        res = client.models.generate_content(
            model=modelo,
            contents="Responda apenas: OK",
        )
        latencia = round((time.time() - t0) * 1000)
        return True, f"Modelo {modelo} operacional ({latencia}ms) -> {res.text.strip()[:30]}"
    except Exception as exc:
        msg = f"{type(exc).__name__}: {str(exc)}"
        if "503" in msg or "high demand" in msg.lower():
            return False, f"Modelo {modelo} com sobrecarga no Google (503 High Demand)"
        return False, f"Modelo {modelo} erro: {msg[:100]}"


def _resumo_envios(limite: int = 10) -> list[dict]:
    """Lê as últimas linhas de logs/envios.jsonl."""
    caminho = RAIZ / "logs" / "envios.jsonl"
    if not caminho.exists():
        return []

    linhas = caminho.read_text(encoding="utf-8").strip().splitlines()
    resultado = []
    for linha in linhas[-limite:]:
        try:
            resultado.append(json.loads(linha))
        except Exception:
            continue
    return resultado


def _ultimos_eventos_webhook(limite: int = 8) -> list[str]:
    """Extrai os últimos alertas recebidos do arquivo logs/webhook.log."""
    caminho = RAIZ / "logs" / "webhook.log"
    if not caminho.exists():
        return []

    linhas = caminho.read_text(encoding="utf-8", errors="replace").splitlines()
    eventos = []
    for linha in reversed(linhas):
        if "Recebido" in linha and ("PROBLEMA" in linha or "RESOLVIDO" in linha):
            # Limpa formatação básica
            partes = linha.split("INFO noc.webhook:")
            if len(partes) > 1:
                eventos.append(partes[1].strip())
            else:
                eventos.append(linha.strip())
            if len(eventos) >= limite:
                break
    return list(reversed(eventos))


def _problemas_zabbix(limite: int = 60) -> list[dict]:
    """Busca problemas ativos com severidade >= 2 no Zabbix."""
    try:
        from clients.zabbix import ZabbixClient
        z = ZabbixClient()
        # Busca janela ampla (mínimo 500) para que rajadas de ONUs de clientes (sev=3)
        # mais recentes não escondam alertas de infraestrutura (sev=4/5) mais antigos.
        problemas = z.get_problems(limit=max(limite, 500), severity_min=2)
        if not problemas:
            return []
        triggerids = list({p["objectid"] for p in problemas if "objectid" in p})
        triggers = z._call("trigger.get", {
            "triggerids": triggerids,
            "selectHosts": ["name"],
            "output": ["triggerid", "description"],
        })
        mapa_hosts = {}
        for t in triggers:
            hosts = t.get("hosts", [])
            mapa_hosts[t["triggerid"]] = hosts[0]["name"] if hosts else "Desconhecido"

        resultado = []
        for p in problemas:
            host = mapa_hosts.get(p.get("objectid"), "Host")
            prob = p.get("name", "Sem descrição")
            resultado.append({
                "host": host,
                "problema": prob,
                "severidade": int(p.get("severity", "0")),
                "clock": int(p.get("clock", 0)),
                "eh_cliente": bool(re.search(r"^cliente\b|esta down : -\d+", prob, re.I)),
            })
        ordenados = sorted(resultado, key=lambda x: (-x["severidade"], -x["clock"]))
        infra = [x for x in ordenados if not x["eh_cliente"]]
        clientes = [x for x in ordenados if x["eh_cliente"]]
        return infra + clientes[:limite]
    except Exception as exc:
        return [{"erro": f"Falha ao consultar Zabbix: {exc}"}]


def main():
    parser = argparse.ArgumentParser(description="Verificação operacional consolidada do NOC FibraPlus.")
    parser.add_argument("--envios", type=int, default=8, help="Número de envios recentes a inspecionar.")
    parser.add_argument("--zabbix", action="store_true", help="Consulta problemas ativos na API do Zabbix.")
    parser.add_argument("--ia-teste", action="store_true", help="Força teste ao vivo na API do Gemini.")
    args = parser.parse_args()

    print("=" * 70)
    print(" 📡  VERIFICAÇÃO OPERACIONAL DO NOC - FIBRAPLUS AI")
    print(f" Data/Hora: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    print("=" * 70)

    # 1. Status da IA
    print("\n[1] STATUS DA IA (Google Gemini)")
    if args.ia_teste:
        print("  -> Testando conexão ao vivo...")
        ok, msg = _verificar_ia()
        icone = "🟢" if ok else "🔴"
        print(f"  {icone} {msg}")
    else:
        # Verifica a partir dos últimos envios
        envios = _resumo_envios(limite=10)
        recentes_ia = [e for e in envios if e.get("origem") == "ia"]
        recentes_fb = [e for e in envios if e.get("origem") == "fallback"]
        total_analises = len(recentes_ia) + len(recentes_fb)
        if total_analises > 0:
            taxa_ia = round((len(recentes_ia) / total_analises) * 100)
            icone = "🟢" if taxa_ia >= 70 else ("🟡" if taxa_ia > 0 else "🔴")
            print(f"  {icone} Taxa recente de análises com IA: {taxa_ia}% ({len(recentes_ia)} IA / {len(recentes_fb)} Fallback em {total_analises} lotes)")
            ultimo_envio = next((e for e in reversed(envios) if e.get("origem") in ("ia", "fallback")), None)
            if ultimo_envio:
                print(f"  Última análise às {ultimo_envio.get('quando', '')}: origem={ultimo_envio.get('origem')}")
        else:
            print("  Nenhuma análise recente no histórico.")
        print("  (Dica: use --ia-teste para disparar um ping em tempo real à API)")

    # 2. Últimos Envios do Webhook
    print(f"\n[2] ÚLTIMOS {args.envios} ENVIOS / AÇÕES DO WEBHOOK")
    envios_lista = _resumo_envios(limite=args.envios)
    if not envios_lista:
        print("  Nenhum registro encontrado em logs/envios.jsonl")
    else:
        for e in envios_lista:
            quando = e.get("quando", "")
            origens = "/".join(e.get("origens", [])) or "ORIGEM"
            alertas = e.get("alertas", 0)
            acao = e.get("acao", "")
            origem_analise = e.get("origem", "")
            erros = e.get("erros", [])

            if acao == "ignorado_sem_infra":
                status = "⚪ IGNORADO (Só clientes)"
            elif origem_analise == "ia":
                tokens = e.get("tokens", {}).get("total_tokens", 0) if e.get("tokens") else 0
                status = f"🤖 IA ({tokens} tokens)"
            elif origem_analise == "fallback":
                motivo = erros[-1] if erros else "falha"
                status = f"⚠️ FALLBACK ({motivo[:35]})"
            else:
                status = f"ℹ️ {acao}"

            print(f"  [{quando}] {origens:6} | {alertas:2} alertas | {status}")

    # 3. Alertas Brutos Recentes Recebidos
    print("\n[3] ÚLTIMOS ALERTAS PROCESSADOS NO LOG")
    eventos = _ultimos_eventos_webhook(limite=6)
    if not eventos:
        print("  Nenhum alerta recente encontrado.")
    else:
        for ev in eventos:
            print(f"  • {ev}")

    # 4. Zabbix (se solicitado ou se houver problemas)
    if args.zabbix:
        print("\n[4] PROBLEMAS ATIVOS NO ZABBIX (Severidade >= 2)")
        problemas = _problemas_zabbix()
        if not problemas:
            print("  ✅ Nenhum problema ativo encontrado no Zabbix.")
        elif "erro" in problemas[0]:
            print(f"  ❌ {problemas[0]['erro']}")
        else:
            sev_nome = {5: "Disaster", 4: "High", 3: "Average", 2: "Warning"}
            infra = [p for p in problemas if not p.get("eh_cliente")]
            clientes = [p for p in problemas if p.get("eh_cliente")]

            print(f"  --- INFRAESTRUTURA ({len(infra)} ativos) ---")
            if not infra:
                print("  ✅ Nenhuma falha de infraestrutura ativa no momento.")
            for p in infra:
                s = sev_nome.get(p["severidade"], str(p["severidade"]))
                print(f"  • [{s}] {p['host']} — {p['problema']}")

            if clientes:
                print(f"\n  --- CLIENTES / ONUs ISOLADAS ({len(clientes)} ativos) ---")
                for p in clientes[:10]:
                    print(f"  • [{sev_nome.get(p['severidade'], 'Average')}] {p['host']} — {p['problema']}")
                if len(clientes) > 10:
                    print(f"  ... e mais {len(clientes) - 10} clientes com ONU down.")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
