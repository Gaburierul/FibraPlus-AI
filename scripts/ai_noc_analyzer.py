"""
Analisador de alertas do NOC com IA (Prova de Conceito).

Lê alertas no formato enviado pelo Zabbix ao WhatsApp, correlaciona, aplica as
regras de tags da FibraPlus e gera UMA mensagem consolidada para o grupo.

Exemplos:
    python scripts/ai_noc_analyzer.py                                  # cenário real (padrão)
    python scripts/ai_noc_analyzer.py --todos                           # roda todos os cenários
    python scripts/ai_noc_analyzer.py --arquivo alertas.txt --zabbix    # arquivo + tags ao vivo
    Get-Content alertas.txt | python scripts/ai_noc_analyzer.py --stdin
    python scripts/ai_noc_analyzer.py --offline                         # sem IA (só correlação)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))  # permite rodar de qualquer pasta, sem PYTHONPATH

from dotenv import load_dotenv  # noqa: E402

load_dotenv(RAIZ / ".env")

from noc.analyzer import MODELO_PADRAO, THINKING_NIVEIS, THINKING_PADRAO, analisar  # noqa: E402
from noc.correlator import correlacionar  # noqa: E402
from noc.enrich import enriquecer_com_zabbix  # noqa: E402
from noc.parser import parse_alertas  # noqa: E402

CENARIOS = RAIZ / "samples" / "alertas"

# Evita o erro 'charmap' com emojis no console do Windows
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass


def _ler_entrada(args) -> list[tuple[str, str]]:
    if args.stdin:
        return [("stdin", sys.stdin.read())]
    if args.arquivo:
        caminho = Path(args.arquivo)
        if not caminho.exists():
            sys.exit(f"Arquivo não encontrado: {caminho}")
        return [(caminho.name, caminho.read_text(encoding="utf-8", errors="replace"))]
    arquivos = sorted(CENARIOS.glob("*.txt"))
    if args.todos:
        return [(a.name, a.read_text(encoding="utf-8")) for a in arquivos]
    escolhido = next((a for a in arquivos if a.name.startswith(args.cenario)), None)
    if not escolhido:
        sys.exit(f"Cenário '{args.cenario}' não encontrado. Disponíveis: {[a.name for a in arquivos]}")
    return [(escolhido.name, escolhido.read_text(encoding="utf-8"))]


def processar(nome: str, texto: str, args) -> None:
    print("\n" + "#" * 70)
    print(f"# ENTRADA: {nome}")
    print("#" * 70)

    parse = parse_alertas(texto)
    print(f"\n[1] Parser: {len(parse.alertas)} bloco(s) válido(s), {len(parse.ignorados)} ignorado(s)")
    for motivo, trecho in parse.ignorados:
        print(f"    - ignorado ({motivo}): {trecho[:90]}")

    correlacao = correlacionar(parse.alertas, janela_min=args.janela, incluir_clientes=args.incluir_clientes)

    if args.zabbix:
        print("\n[2] Enriquecimento Zabbix:")
        for log in enriquecer_com_zabbix(correlacao):
            print(f"    - {log}")

    print(f"\n[3] Correlação: {len(correlacao.incidentes)} incidente(s) | "
          f"clientes filtrados: {correlacao.clientes_filtrados}")
    for inc in correlacao.incidentes:
        janela = f"{inc.inicio:%H:%M:%S}–{inc.fim:%H:%M:%S}" if inc.inicio else "sem horário"
        print(f"    #{inc.id} {inc.classificacao:<11} {janela} | sites={inc.sites} | {inc.categorias}")
        for o in inc.ocorrencias:
            peso = o.peso[1] if o.peso else "sem tag"
            avisos = f" ⚠ {'; '.join(o.avisos)}" if o.avisos else ""
            print(f"       - [{o.estado:<9}] {o.equipamento} | {o.categoria} | {peso} | x{o.vezes}{avisos}")
    for obs in correlacao.observacoes:
        print(f"    obs: {obs}")

    print(f"\n[4] Análise ({'offline' if args.offline else MODELO_PADRAO}, thinking={args.thinking})...")
    resultado = analisar(correlacao, usar_ia=not args.offline, thinking=args.thinking)

    print("\n" + "=" * 70)
    print(f"MENSAGEM PARA O WHATSAPP  (origem: {resultado.origem.upper()})")
    print("=" * 70)
    print(resultado.mensagem)
    print("=" * 70)

    if resultado.analise:
        a = resultado.analise
        print(f"\nConfiança declarada pela IA: {a.confianca}")
        if a.dados_faltantes:
            print("Dados sugeridos para confirmar (validar): " + " | ".join(a.dados_faltantes))
        if args.json:
            print(json.dumps(a.model_dump(), ensure_ascii=False, indent=2))
    if resultado.tokens:
        print(f"Tokens: {resultado.tokens}")
    for erro in resultado.erros:
        print(f"[aviso] {erro}")


def main() -> None:
    p = argparse.ArgumentParser(description="Analisador de alertas do NOC com IA")
    fonte = p.add_mutually_exclusive_group()
    fonte.add_argument("--arquivo", help="Arquivo .txt com os alertas")
    fonte.add_argument("--stdin", action="store_true", help="Lê os alertas da entrada padrão")
    fonte.add_argument("--cenario", default="01", help="Prefixo do cenário em samples/alertas (padrão: 01)")
    fonte.add_argument("--todos", action="store_true", help="Roda todos os cenários de teste")
    p.add_argument("--offline", action="store_true", help="Não chama a IA (apenas correlação/fallback)")
    p.add_argument("--zabbix", action="store_true", help="Enriquece com tags/status ao vivo do Zabbix")
    p.add_argument("--incluir-clientes", action="store_true", help="Não filtra alertas de clientes")
    p.add_argument("--janela", type=int, default=10, help="Minutos para agrupar alertas no mesmo incidente")
    p.add_argument("--thinking", default=THINKING_PADRAO, choices=THINKING_NIVEIS)
    p.add_argument("--json", action="store_true", help="Mostra a análise estruturada completa")
    args = p.parse_args()

    for nome, texto in _ler_entrada(args):
        try:
            processar(nome, texto, args)
        except Exception as exc:  # noqa: BLE001 - um cenário com erro não derruba os demais
            print(f"\n[ERRO] Falha ao processar {nome}: {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    main()
