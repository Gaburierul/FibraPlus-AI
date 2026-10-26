from datetime import datetime

from noc.consulta import (
    Evento,
    Resumo,
    agrupar,
    filtrar,
    formatar_markdown,
    formatar_texto,
    para_alertas,
    para_dict,
)
from noc.parser import PROBLEMA, RESOLVIDO


def _criar_evento(
    eventid: str,
    clock: int,
    problema_ativo: bool,
    severidade: int = 4,
    host: str = "EXEMPLO-IDC-HUAWEI-PE01",
    problema: str = "OSPF: Interface 192.0.2.22 em estado Down",
    objectid: str = "100",
    tags: dict[str, str] | None = None,
) -> Evento:
    return Evento(
        eventid=eventid,
        objectid=objectid,
        clock=clock,
        problema_ativo=problema_ativo,
        severidade=severidade,
        host=host,
        host_tecnico=host.lower(),
        problema=problema,
        tags=tags or {},
    )


def test_filtrar_por_termo_e_escopo():
    ev_infra = _criar_evento("1", 1000, True, host="CPE-EXEMPLO-HUAWEI-PE01", problema="OSPF Down")
    ev_cli = _criar_evento("2", 1010, True, host="EXEMPLO-IDC-ZTE-OLT01", problema="Cliente: exemplo -> Esta down : -80", objectid="101")
    ev_bgp = _criar_evento("3", 1020, True, host="CPE-EXEMPLO-EDGE01", problema="BGP IPv6 Down", objectid="102")

    todos = [ev_infra, ev_cli, ev_bgp]

    # Filtra apenas infraestrutura
    infra = filtrar(todos, escopo="infra")
    assert len(infra) == 2
    assert ev_cli not in infra

    # Filtra apenas clientes
    clientes = filtrar(todos, escopo="clientes")
    assert clientes == [ev_cli]

    # Filtra por termo (case-insensitive e sem acento) e exclusão
    ospf = filtrar(todos, termos=["exemplo", "ospf"])
    assert ospf == [ev_infra]

    sem_ipv6 = filtrar(todos, excluir=["ipv6"], escopo="infra")
    assert sem_ipv6 == [ev_infra]


def test_agrupar_flapping_e_conversao_para_alertas():
    # 3 quedas e 2 recuperações no mesmo objectid/host -> ativo no final e em flapping
    eventos = [
        _criar_evento("1", 1000, True, severidade=3),
        _criar_evento("2", 1060, False, severidade=3),
        _criar_evento("3", 1120, True, severidade=4),
        _criar_evento("4", 1180, False, severidade=4),
        _criar_evento("5", 1240, True, severidade=4),
    ]
    grupos = agrupar(eventos)
    assert len(grupos) == 1
    g = grupos[0]
    assert g.problemas == 3
    assert g.resolucoes == 2
    assert g.ativo is True
    assert g.flapping is True
    assert g.severidade == 4

    alertas = para_alertas(grupos)
    assert len(alertas) == 1
    assert alertas[0].status == PROBLEMA
    assert alertas[0].severidade == 4

    # Adiciona resolução final -> grupo passa a resolvido
    eventos.append(_criar_evento("6", 1300, False, severidade=4))
    grupos_res = agrupar(eventos)
    alertas_res = para_alertas(grupos_res)
    assert grupos_res[0].ativo is False
    assert alertas_res[0].status == RESOLVIDO
    assert alertas_res[0].fim is not None


def test_resumo_formatacao_e_serializacao():
    ev = _criar_evento("10", 1700000000, True, severidade=5, tags={"backbone": "1"})
    grupos = agrupar([ev])
    resumo = Resumo(
        titulo="Teste Consulta",
        inicio=datetime.fromtimestamp(1699990000, ev.horario.tzinfo),
        fim=ev.horario,
        grupos=grupos,
        total_eventos=1,
    )

    txt = formatar_texto(resumo)
    md = formatar_markdown(resumo)
    dados = para_dict(resumo)

    assert "Teste Consulta" in txt
    assert "EXEMPLO-IDC-HUAWEI-PE01" in txt
    assert "| Disaster |" in md
    assert dados["total_eventos"] == 1
    assert dados["grupos"][0]["ativo"] is True
