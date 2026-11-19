from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from clients.ixc import IXCClient
from clients.zabbix import ZabbixClient
from noc.agente_investigacao import investigar_streaming, resolver_modelo
from noc.chat_store import ChatStore


def test_chat_store_crud_e_busca(tmp_path):
    store = ChatStore(tmp_path / "chat.sqlite3")
    c1 = store.criar_conversa("Queda POP Exemplo", modelo="gemini-4-hydrogen")
    store.salvar_mensagem(c1["id"], "user", "Verifica a OLT LAB-POP-ZTE-OLT01")
    store.salvar_mensagem(
        c1["id"],
        "assistant",
        "Resumo: 2 PONs em LOSS.",
        modelo="gemini-4-neon",
        ferramentas=[{"nome": "zabbix_resumo_olt_pon", "ok": True, "duracao_ms": 210}],
        tokens={"total_tokens": 540},
    )

    conv = store.obter_conversa(c1["id"])
    assert conv is not None
    assert conv["modelo"] == "gemini-4-neon"
    assert len(conv["mensagens"]) == 2
    assert conv["mensagens"][1]["ferramentas"][0]["nome"] == "zabbix_resumo_olt_pon"
    assert conv["mensagens"][1]["tokens"]["total_tokens"] == 540

    achadas = store.listar_conversas(busca="LAB-POP-ZTE")
    assert len(achadas) == 1
    assert achadas[0]["id"] == c1["id"]

    assert store.atualizar_conversa(c1["id"], titulo="Incidente POP GPON")
    assert store.obter_conversa(c1["id"])["titulo"] == "Incidente POP GPON"

    assert store.excluir_conversa(c1["id"])
    assert store.obter_conversa(c1["id"]) is None


def test_ixc_radacct_somente_leitura_e_prefixo_ip():
    cliente = IXCClient(base_url="https://ixc.example.com.br", user_id="10", api_hash="hash_ok")

    def falso_post(url, headers, data, timeout):
        assert url.endswith("/radacct")
        assert headers["ixcsoft"] == "listar"
        payload = json.loads(data)
        assert payload["qtype"] == "radacct.framedipaddress"
        assert payload["oper"] == "L"
        assert payload["sortname"] == "radacct.radacctid"
        resp = MagicMock()
        resp.ok = True
        resp.status_code = 200
        resp.json.return_value = {
            "registros": [{
                "radacctid": "999",
                "username": "cliente_dedicado",
                "framedipaddress": "198.51.100.25",
                "acctstarttime": "2026-11-18 06:00:00",
                "acctstoptime": "2026-11-18 06:15:00",
                "acctterminatecause": "Lost-Carrier",
                "nasipaddress": "192.0.2.1",
                "cnpj_cpf": "123.456.789-00",
                "senha": "segredo",
            }]
        }
        return resp

    with patch("clients.ixc.requests.Session.post", side_effect=falso_post):
        sessoes = cliente.buscar_sessoes_radius(ip="198.51.100.", prefixo_ip=True, rp=10)

    assert len(sessoes) == 1
    assert sessoes[0]["username"] == "cliente_dedicado"
    assert sessoes[0]["acctterminatecause"] == "Lost-Carrier"
    assert "cnpj_cpf" not in sessoes[0]
    assert "senha" not in sessoes[0]


def test_zabbix_pon_summary_classifica_loss_e_dyinggasp():
    zbx = ZabbixClient.__new__(ZabbixClient)

    def falso_call(method, params):
        if method == "host.get":
            return [{"hostid": "101", "host": "LAB-ZTE-OLT01", "name": "LAB-ZTE-OLT01", "status": "0"}]
        if method == "item.get":
            return [
                {"itemid": "1", "name": "PON gpon_1/1/1: ONUs PROVISIONADAS", "lastvalue": "40", "lastclock": "1700000000"},
                {"itemid": "2", "name": "PON gpon_1/1/1: ONUs ONLINE", "lastvalue": "30", "lastclock": "1700000000"},
                {"itemid": "3", "name": "PON gpon_1/1/1: ONUs LOSS", "lastvalue": "8", "lastclock": "1700000000"},
                {"itemid": "4", "name": "PON gpon_1/1/1: ONUs DYINGGASP", "lastvalue": "2", "lastclock": "1700000000"},
                {"itemid": "5", "name": "PON gpon_1/1/1: ONUs OFFLINE", "lastvalue": "0", "lastclock": "1700000000"},
            ]
        if method == "trigger.get":
            return [
                {
                    "triggerid": "t1",
                    "description": "Cliente: cli_los -> Esta down : -80",
                    "priority": "3",
                    "lastchange": "1700000000",
                    "items": [{"lastvalue": "-80"}],
                },
                {
                    "triggerid": "t2",
                    "description": "Cliente: cli_energia -> Esta down : -90",
                    "priority": "3",
                    "lastchange": "1700000000",
                    "items": [{"lastvalue": "-90"}],
                },
            ]
        return []

    zbx._call = falso_call
    res = zbx.get_pon_summary("LAB-ZTE-OLT01")
    assert res["totais"]["provisionadas"] == 40
    assert res["totais"]["loss"] == 8
    assert res["totais"]["dyinggasp"] == 2
    assert res["pons_afetadas"][0]["percentual_queda"] == 25.0
    assert res["clientes_ativos_por_motivo"]["LOS / Rompimento (-80)"] == 1
    assert res["clientes_ativos_por_motivo"]["DyingGasp / Energia (-90)"] == 1


def test_agente_streaming_function_calling_stateless_preserva_steps():
    assert resolver_modelo("hydrogen")[0] == "gemini-4-hydrogen"
    assert resolver_modelo("neon")[0] == "gemini-4-neon"
    assert resolver_modelo("invalido")[0] == "gemini-4-hydrogen"

    chamadas_input = []

    def falso_create(**kwargs):
        # Copia profunda do input para validar histórico stateless entre rodadas
        chamadas_input.append(json.loads(json.dumps(kwargs["input"])))
        assert kwargs["store"] is False
        assert kwargs["stream"] is True

        if len(chamadas_input) == 1:
            return iter([
                SimpleNamespace(event_type="step.start", index=0, step=SimpleNamespace(type="thought")),
                SimpleNamespace(
                    event_type="step.delta",
                    index=0,
                    delta=SimpleNamespace(type="thought_summary", content=SimpleNamespace(text="Vou checar o IXC.")),
                ),
                SimpleNamespace(
                    event_type="step.delta",
                    index=0,
                    delta=SimpleNamespace(type="thought_signature", signature="sig_abc"),
                ),
                SimpleNamespace(
                    event_type="step.start",
                    index=1,
                    step=SimpleNamespace(type="function_call", id="fc_1", name="ixc_diagnosticar_cliente", arguments={}),
                ),
                SimpleNamespace(
                    event_type="step.delta",
                    index=1,
                    delta=SimpleNamespace(type="arguments_delta", arguments='{"termo": "cliente_teste"}'),
                ),
                SimpleNamespace(
                    event_type="interaction.completed",
                    interaction=SimpleNamespace(
                        status="requires_action",
                        steps=None,
                        usage={"total_input_tokens": 120, "total_output_tokens": 30, "total_tokens": 150},
                    ),
                ),
            ])
        return iter([
            SimpleNamespace(event_type="step.start", index=0, step=SimpleNamespace(type="model_output")),
            SimpleNamespace(
                event_type="step.delta",
                index=0,
                delta=SimpleNamespace(type="text", text="Cliente **online** no Radius."),
            ),
            SimpleNamespace(
                event_type="interaction.completed",
                interaction=SimpleNamespace(
                    status="completed",
                    steps=None,
                    usage={"total_input_tokens": 200, "total_output_tokens": 20, "total_tokens": 220},
                ),
            ),
        ])

    fake_client = SimpleNamespace(interactions=SimpleNamespace(create=falso_create))
    fake_tool_result = (True, json.dumps({"ok": True, "status_operacional": "ONLINE_NORMAL"}), "ONLINE_NORMAL")

    with patch("noc.agente_investigacao.executar_ferramenta", return_value=fake_tool_result) as mock_exec:
        eventos = list(
            investigar_streaming("Verifica cliente_teste", modelo="gemini-4-neon", client=fake_client)
        )

    mock_exec.assert_called_once_with("ixc_diagnosticar_cliente", {"termo": "cliente_teste"})
    tipos = [e["tipo"] for e in eventos]
    assert "pensamento" in tipos
    assert "ferramenta_inicio" in tipos
    assert "ferramenta_fim" in tipos
    assert "texto" in tipos
    concluido = next(e for e in eventos if e["tipo"] == "concluido")
    assert concluido["modelo"] == "gemini-4-neon"
    assert concluido["texto_completo"] == "Cliente **online** no Radius."
    assert concluido["tokens"]["total_tokens"] == 370

    # Verifica que na 2ª rodada o histórico stateless manteve thought+signature, function_call e function_result
    tipos_hist_r2 = [s["type"] for s in chamadas_input[1]]
    assert tipos_hist_r2 == ["user_input", "thought", "function_call", "function_result"]
    assert chamadas_input[1][1]["signature"] == "sig_abc"


def test_agente_trata_erro_402_com_mensagem_clara():
    class Fake402Error(Exception):
        status_code = 402

    def falha(**_kwargs):
        raise Fake402Error("Your prepayment credits are depleted.")

    fake_client = SimpleNamespace(interactions=SimpleNamespace(create=falha))
    eventos = list(investigar_streaming("Status agora", modelo="gemini-4-hydrogen", client=fake_client))
    erro = next(e for e in eventos if e["tipo"] == "erro")
    assert "HTTP 402" in erro["mensagem"]
    assert "Consultas Rápidas" in erro["mensagem"]


def test_painel_fastapi_rotas_e_sse(tmp_path, monkeypatch):
    import server.painel as painel

    monkeypatch.setattr(painel, "store", ChatStore(tmp_path / "painel_test.sqlite3"))

    def falso_agente(pergunta, *, historico_mensagens=None, modelo=None, client=None):
        yield {"tipo": "status", "texto": "Consultando..."}
        yield {"tipo": "texto", "delta": "Diagnóstico concluído."}
        yield {
            "tipo": "concluido",
            "modelo": modelo or "gemini-4-hydrogen",
            "texto_completo": "Diagnóstico concluído.",
            "ferramentas_usadas": [],
            "tokens": {"total_tokens": 90},
        }

    monkeypatch.setattr(painel, "investigar_streaming", falso_agente)

    client = TestClient(painel.app)
    assert client.get("/").status_code == 200
    assert client.get("/api/health").json()["status"] == "ok"

    cfg = client.get("/api/config").json()
    assert cfg["modelo_padrao"] == "gemini-4-hydrogen"
    assert {m["id"] for m in cfg["modelos"]} == {"gemini-4-hydrogen", "gemini-4-neon"}

    criada = client.post("/api/conversas", json={"modelo": "gemini-4-hydrogen"}).json()
    cid = criada["id"]

    with client.stream(
        "POST",
        f"/api/conversas/{cid}/mensagens",
        json={"conteudo": "Como está o POP Norte agora?", "modelo": "gemini-4-neon"},
    ) as resp:
        assert resp.status_code == 200
        linhas = [ln for ln in resp.iter_lines() if ln.startswith("data:")]

    assert any("Diagnóstico concluído." in ln for ln in linhas)
    conv_final = client.get(f"/api/conversas/{cid}").json()
    assert conv_final["titulo"] == "Como está o POP Norte agora"
    assert len(conv_final["mensagens"]) == 2
    assert conv_final["mensagens"][1]["conteudo"] == "Diagnóstico concluído."


def test_custos_calculo_tokens_e_agregacao_webhook_e_chat(tmp_path):
    from datetime import datetime
    from noc.consulta import FUSO
    from noc.custos import calcular_custo_tokens, resumo_consumo

    # Hydrogen: 100k in (40k em cache) + 2k out + 1k thought
    c = calcular_custo_tokens(
        "gemini-4-hydrogen",
        {
            "total_input_tokens": 100_000,
            "total_cached_tokens": 40_000,
            "total_output_tokens": 2_000,
            "total_thought_tokens": 1_000,
        },
        usd_brl=5.0,
    )
    # 60k * 1.50/1M = 0.09 | 40k * 0.075/1M = 0.003 | 3k * 7.50/1M = 0.0225 -> total 0.1155 USD -> R$ 0.5775
    assert abs(c["usd"] - 0.1155) < 1e-6
    assert abs(c["brl"] - 0.5775) < 1e-4

    # Agrega envios.jsonl + SQLite do chat
    envios = tmp_path / "envios.jsonl"
    envios.write_text(
        json.dumps({
            "quando": "2026-11-19T09:00:00",
            "origem": "ia",
            "tokens": {"total_input_tokens": 2000, "total_output_tokens": 200, "total_tokens": 2200},
        }) + "\n",
        encoding="utf-8",
    )
    store = ChatStore(tmp_path / "chat.sqlite3")
    conv = store.criar_conversa("Teste", modelo="gemini-4-neon")
    store.salvar_mensagem(
        conv["id"],
        "assistant",
        "OK",
        modelo="gemini-4-neon",
        tokens={"total_input_tokens": 10_000, "total_output_tokens": 500, "total_tokens": 10_500},
    )

    ref = datetime(2026, 11, 19, 10, 0, 0, tzinfo=FUSO)
    res_paid = resumo_consumo(
        envios_path=envios, chat_db_path=store.caminho, usd_brl=5.85, agora=ref, webhook_gratis=False
    )
    assert res_paid["ok"] is True
    assert res_paid["hoje"]["chamadas_webhook"] == 1
    assert res_paid["ultimos_30d"]["brl_webhook"] > 0
    assert res_paid["ultimos_30d"]["brl_painel"] > 0

    res_free = resumo_consumo(
        envios_path=envios, chat_db_path=store.caminho, usd_brl=5.85, agora=ref, webhook_gratis=True
    )
    assert res_free["webhook_free_tier"] is True
    assert res_free["ultimos_30d"]["brl_webhook"] == 0.0
    assert res_free["ultimos_30d"]["brl_webhook_economia"] > 0
    assert res_free["ultimos_30d"]["brl"] == res_free["ultimos_30d"]["brl_painel"]
