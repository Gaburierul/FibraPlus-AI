"""
Consulta geral do Zabbix — um único comando para qualquer recorte.

Substitui scripts avulsos por equipamento, cliente, cidade ou data. Os termos
são buscados (sem acento, sem diferenciar maiúsculas) no nome do host, no nome
técnico, no nome do problema e nas tags. Vários termos = todos precisam casar.

Exemplos:
    python scripts/consultar.py                                  # problemas ativos agora
    python scripts/consultar.py RRP-ESCRITORIO                   # ativos de um equipamento
    python scripts/consultar.py ospf --horas 12                  # histórico por assunto
    python scripts/consultar.py prefeitura --desde "2026-10-20 18:00" --ate "2026-10-21 08:00"
    python scripts/consultar.py --plantao noturno --data 2026-10-23 --md
    python scripts/consultar.py --escopo clientes --horas 2      # só quedas de clientes/ONU
    python scripts/consultar.py BGP --excluir IPv6 --sev-min 4
    python scripts/consultar.py --horas 1 --analisar --enviar    # resumo correlacionado ao grupo
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(RAIZ / ".env")

from noc.consulta import (ESCOPOS, FUSO, Resumo, agrupar, buscar_ativos,  # noqa: E402
                          buscar_historico, filtrar, formatar_markdown, formatar_texto,
                          para_alertas, para_dict)

PLANTOES = {
    # nome: (hora início, dia de início relativo à data, hora fim, dia de fim relativo)
    "noturno": (18, -1, 8, 0),
    "diurno": (8, 0, 18, 0),
}


def _data_hora(valor: str) -> datetime:
    for formato in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d",
                    "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%Y"):
        try:
            return datetime.strptime(valor.strip(), formato).replace(tzinfo=FUSO)
        except ValueError:
            continue
    raise argparse.ArgumentTypeError(f"data/hora inválida: {valor!r} (use AAAA-MM-DD HH:MM)")


def _janela(args) -> tuple[datetime, datetime] | None:
    """Devolve (início, fim) no fuso local ou None para o modo de problemas ativos."""
    agora = datetime.now(FUSO)
    if args.plantao:
        base = args.data or agora
        h_ini, d_ini, h_fim, d_fim = PLANTOES[args.plantao]
        dia = base.replace(hour=0, minute=0, second=0, microsecond=0)
        inicio = dia + timedelta(days=d_ini, hours=h_ini)
        fim = dia + timedelta(days=d_fim, hours=h_fim) - timedelta(seconds=1)
        return inicio, min(fim, agora)
    if args.desde:
        return args.desde, args.ate or agora
    if args.horas or args.minutos:
        return agora - timedelta(hours=args.horas or 0, minutes=args.minutos or 0), agora
    return None


def _titulo(args, janela) -> str:
    if args.plantao:
        base = f"Plantão {args.plantao}"
    else:
        base = "Problemas ativos" if janela is None else "Histórico Zabbix"
    extras = []
    if args.termos:
        extras.append("“" + " ".join(args.termos) + "”")
    if args.escopo != "todos":
        extras.append(f"({args.escopo})")
    return f"{base} — {' '.join(extras)}" if extras else base


def _slug(texto: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", texto.lower()).strip("_")[:60] or "consulta"


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, OSError):
            pass

    p = argparse.ArgumentParser(description="Consulta geral de problemas e eventos do Zabbix.",
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__.split("Exemplos:", 1)[1])
    p.add_argument("termos", nargs="*", help="equipamento, cliente, cidade, interface, tag... (todos devem casar)")
    p.add_argument("--excluir", action="append", default=[], metavar="TERMO",
                   help="descarta eventos que contenham o termo (pode repetir)")
    p.add_argument("--escopo", choices=ESCOPOS, default="todos", help="infraestrutura, clientes/ONU ou ambos")
    p.add_argument("--sev-min", type=int, default=0, choices=range(0, 6), metavar="0-5",
                   help="severidade mínima do Zabbix (padrão 0)")

    janela = p.add_argument_group("janela (sem nenhuma opção: problemas ativos agora)")
    janela.add_argument("--horas", type=float, help="histórico das últimas N horas")
    janela.add_argument("--minutos", type=float, help="histórico dos últimos N minutos")
    janela.add_argument("--desde", type=_data_hora, help="início do histórico (AAAA-MM-DD HH:MM)")
    janela.add_argument("--ate", type=_data_hora, help="fim do histórico (padrão: agora)")
    janela.add_argument("--plantao", choices=sorted(PLANTOES), help="noturno 18:00→07:59 ou diurno 08:00→17:59")
    janela.add_argument("--data", type=_data_hora, help="data do plantão (dia em que termina; padrão hoje)")

    saida = p.add_argument_group("saída")
    saida.add_argument("--max-linhas", type=int, default=30, help="linhas por seção no terminal")
    saida.add_argument("--md", nargs="?", const="", metavar="ARQUIVO",
                       help="exporta Markdown (padrão: docs/relatorios/<consulta>.md)")
    saida.add_argument("--json", nargs="?", const="", metavar="ARQUIVO", help="exporta JSON")

    ia = p.add_argument_group("análise e envio")
    ia.add_argument("--analisar", action="store_true",
                    help="correlaciona os resultados e gera o resumo do NOC (sem IA por padrão)")
    ia.add_argument("--usar-ia", action="store_true", help="com --analisar: acrescenta hipótese do Gemini")
    ia.add_argument("--enviar", action="store_true", help="envia o resultado ao mensageiro configurado")
    args = p.parse_args()

    if args.usar_ia and not args.analisar:
        p.error("--usar-ia exige --analisar")
    if (args.horas or 0) < 0 or (args.minutos or 0) < 0:
        p.error("--horas/--minutos devem ser positivos")
    if args.data and not args.plantao:
        p.error("--data só é usada com --plantao")
    if args.ate and not args.desde:
        p.error("--ate exige --desde")
    if sum(bool(x) for x in (args.plantao, args.desde, args.horas or args.minutos)) > 1:
        p.error("use apenas uma forma de janela: --horas/--minutos, --desde/--ate ou --plantao")

    from clients.zabbix import ZabbixClient
    try:
        client = ZabbixClient()
    except ValueError as exc:
        print(f"Erro de configuração do Zabbix: {exc}", file=sys.stderr)
        return 2

    intervalo = _janela(args)
    t0 = time.time()
    if intervalo is None:
        eventos, avisos = buscar_ativos(client, args.sev_min)
    else:
        eventos, avisos = buscar_historico(client, int(intervalo[0].timestamp()),
                                           int(intervalo[1].timestamp()), args.sev_min)
    selecionados = filtrar(eventos, args.termos, args.excluir, args.escopo)
    resumo = Resumo(
        titulo=_titulo(args, intervalo),
        inicio=intervalo[0] if intervalo else None,
        fim=intervalo[1] if intervalo else datetime.now(FUSO),
        grupos=agrupar(selecionados),
        total_eventos=len(selecionados),
        avisos=avisos,
    )
    print(formatar_texto(resumo, args.max_linhas))
    print(f"\n({len(eventos)} evento(s) lidos do Zabbix, {len(selecionados)} selecionado(s), "
          f"{time.time() - t0:.1f}s)")

    nome_base = _slug(f"{resumo.titulo}_{resumo.fim:%Y%m%d_%H%M}")
    if args.md is not None:
        destino = Path(args.md) if args.md else RAIZ / "docs" / "relatorios" / f"{nome_base}.md"
        destino.parent.mkdir(parents=True, exist_ok=True)
        destino.write_text(formatar_markdown(resumo), encoding="utf-8")
        print(f"Markdown salvo em {destino}")
    if args.json is not None:
        destino = Path(args.json) if args.json else RAIZ / "logs" / f"{nome_base}.json"
        destino.parent.mkdir(parents=True, exist_ok=True)
        destino.write_text(json.dumps(para_dict(resumo), ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"JSON salvo em {destino}")

    mensagem = formatar_texto(resumo, max_linhas=15)
    if args.analisar:
        from noc.analyzer import analisar
        from noc.correlator import correlacionar
        correlacao = correlacionar(para_alertas(resumo.grupos), janela_min=10)
        if not correlacao.incidentes:
            mensagem = (f"✅ {resumo.titulo}: nenhum incidente de infraestrutura "
                        f"({correlacao.clientes_filtrados} alerta(s) de clientes filtrados).")
        else:
            mensagem = analisar(correlacao, usar_ia=args.usar_ia).mensagem
        print("\n" + "=" * 60 + "\n" + mensagem + "\n" + "=" * 60)

    if args.enviar:
        from clients.mensageiro import enviar_mensagem
        try:
            usado = enviar_mensagem(mensagem)
        except Exception as exc:  # noqa: BLE001
            print(f"Falha no envio ({type(exc).__name__}): {exc}", file=sys.stderr)
            return 1
        print(f"Mensagem enviada via {usado}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
