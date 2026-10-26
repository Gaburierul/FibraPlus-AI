import unittest
import os
from types import SimpleNamespace
from unittest.mock import patch

from noc.analyzer import (
    MAX_TOKENS_RESPOSTA_IA,
    AnaliseNOC,
    _chamar_gemini,
    _montar_entrada,
    _sanitizar,
)


class AnalyzerGuardrailTests(unittest.TestCase):
    def setUp(self):
        self.correlacao = SimpleNamespace(ocorrencias=[SimpleNamespace(
            equipamento="LAB-PE-01",
            problema="Peer de laboratório indisponível",
            ip="192.0.2.10",
            site="LAB-A",
        )])

    def test_hipotese_sem_evidencia_literal_e_omitida(self):
        analise = AnaliseNOC(
            causa_raiz_provavel="O roteador foi desligado por falha elétrica.",
            confianca="alta",
            evidencias=["LOCAL-NAO-PRESENTE-NO-ALERTA"],
            dados_faltantes=[],
        )

        avisos = _sanitizar(analise, self.correlacao)

        self.assertEqual(analise.causa_raiz_provavel, "")
        self.assertEqual(analise.confianca, "baixa")
        self.assertEqual(analise.evidencias, [])
        self.assertTrue(any("omitida" in aviso for aviso in avisos))

    def test_evidencia_literal_permitida(self):
        analise = AnaliseNOC(
            causa_raiz_provavel="Pode haver indisponibilidade no peer.",
            confianca="baixa",
            evidencias=["Peer de laboratório indisponível"],
            dados_faltantes=[],
        )

        _sanitizar(analise, self.correlacao)

        self.assertEqual(analise.evidencias, ["Peer de laboratório indisponível"])
        self.assertTrue(analise.causa_raiz_provavel)

    def test_contexto_da_ia_pseudonimiza_identificadores_e_preserva_horario(self):
        incidente = SimpleNamespace(to_dict=lambda: {
            "incidente": 1,
            "sites": ["SITE-REAL-01"],
            "ocorrencias": [{
                "equipamento": "CPE-REAL-HUAWEI-PE01",
                "ip": "2001:db8:1234::10",
                "site": "SITE-REAL-01",
                "problema": "Peer 2001:db8:1234::10 caiu em 10:00:00",
                "categoria": "BGP",
                "nivel_zabbix": "High",
                "estado_no_lote": "ATIVO",
                "ocorrencias_no_lote": 1,
                "inicio": "2025-01-15 10:00:00",
                "ultima_resolucao": None,
                "duracoes": [],
                "tags": {"backbone": "1", "interface": "XGigabitEthernet0/0/1"},
                "peso_topologico": "backbone=1",
                "classificacao_regra": "CRITICO",
                "classificacao_origem": "tag",
                "ativo_no_zabbix_agora": True,
                "origens": ["ZABBIX"],
                "avisos": [],
            }],
            "total_ocorrencias": 1,
            "ativos": 1,
            "classificacao_regra": "CRITICO",
        })
        correlacao = SimpleNamespace(
            incidentes=[incidente], clientes_filtrados=0, observacoes=[]
        )

        entrada, _, aliases = _montar_entrada(correlacao)

        self.assertNotIn("CPE-REAL-HUAWEI-PE01", entrada)
        self.assertNotIn("2001:db8:1234::10", entrada)
        self.assertNotIn("XGigabitEthernet0/0/1", entrada)
        self.assertIn("2025-01-15 10:00:00", entrada)
        self.assertNotIn("TELEFONE_REDACTED", entrada)
        self.assertIn("EQUIPAMENTO_1", entrada)
        self.assertIn("IP_1", entrada)
        self.assertTrue(aliases)

    def test_chamada_gemini_limita_saida_e_desativa_repeticoes_do_sdk(self):
        with patch.dict(os.environ, {"GEMINI_API_KEY": "fake-test-key"}):
            with patch("google.genai.Client") as criar_cliente:
                _chamar_gemini("{}", "gemini-test", "minimal")

        configuracao_http = criar_cliente.call_args.kwargs["http_options"]
        self.assertEqual(configuracao_http.retry_options.attempts, 1)
        chamada = criar_cliente.return_value.interactions.create.call_args.kwargs
        self.assertEqual(chamada["generation_config"]["max_output_tokens"], MAX_TOKENS_RESPOSTA_IA)
        self.assertFalse(chamada["store"])

    def test_desmascarar_e_sanitizacao_reverte_aliases_e_remove_urls_e_mencoes(self):
        aliases = {
            "EQUIPAMENTO_1": "LAB-PE-01",
            "EQUIPAMENTO_12": "LAB-PE-12",
            "IP_1": "192.0.2.10",
        }
        analise = AnaliseNOC(
            causa_raiz_provavel="Falha no EQUIPAMENTO_12 e no IP_1. Veja https://evil.com e contate @admin ou TELEFONE_REDACTED",
            confianca="alta",
            evidencias=["Peer de laboratório indisponível"],
            dados_faltantes=["Logs do EQUIPAMENTO_1"],
        )

        _sanitizar(analise, self.correlacao, aliases=aliases)

        self.assertIn("LAB-PE-12", analise.causa_raiz_provavel)
        self.assertIn("192.0.2.10", analise.causa_raiz_provavel)
        self.assertNotIn("https://", analise.causa_raiz_provavel)
        self.assertNotIn("@admin", analise.causa_raiz_provavel)
        self.assertNotIn("TELEFONE_REDACTED", analise.causa_raiz_provavel)
        self.assertIn("dado omitido", analise.causa_raiz_provavel)
        self.assertEqual(analise.dados_faltantes, ["Logs do LAB-PE-01"])

    def test_evidencia_com_alias_valida_e_reverte_corretamente(self):
        aliases = {"IP_1": "192.0.2.10"}
        correlacao = SimpleNamespace(ocorrencias=[SimpleNamespace(
            equipamento="LAB-PE-01",
            problema="Peer 192.0.2.10 não está ESTABLISHED",
            ip="192.0.2.10",
            site="LAB-A",
        )])
        analise = AnaliseNOC(
            causa_raiz_provavel="Peer caiu",
            confianca="baixa",
            evidencias=["Peer IP_1 não está ESTABLISHED"],
            dados_faltantes=[],
        )

        _sanitizar(analise, correlacao, aliases=aliases)

        self.assertEqual(analise.evidencias, ["Peer 192.0.2.10 não está ESTABLISHED"])
        self.assertTrue(analise.causa_raiz_provavel)

    def test_concordancia_singular_plural_cabecalho(self):
        from datetime import datetime
        from noc.analyzer import _mensagem_deterministica
        from noc.correlator import correlacionar
        from noc.parser import Alerta, PROBLEMA, RESOLVIDO

        t = datetime(2026, 10, 13, 11, 0, 0)

        # Caso 1: 0 ativos de 1 alerta
        c1 = correlacionar([
            Alerta(status=RESOLVIDO, equipamento="LAB-PE01", problema="Link ok", fim=t, origem="ZABBIX")
        ])
        msg_1 = _mensagem_deterministica(c1)
        self.assertIn("0 ativos de 1 alerta", msg_1)
        self.assertNotIn("1 alertas", msg_1)

        # Caso 2: 1 alerta ativo
        c2 = correlacionar([
            Alerta(status=PROBLEMA, equipamento="LAB-PE01", problema="Link down", inicio=t, origem="ZABBIX")
        ])
        msg_2 = _mensagem_deterministica(c2)
        self.assertIn("1 alerta ativo", msg_2)

        # Caso 3: 1 ativo de 2 alertas
        c3 = correlacionar([
            Alerta(status=PROBLEMA, equipamento="LAB-PE01", problema="Link down", inicio=t, origem="ZABBIX"),
            Alerta(status=RESOLVIDO, equipamento="LAB-SW01", problema="BGP down", fim=t, origem="ZABBIX"),
        ])
        msg_3 = _mensagem_deterministica(c3)
        self.assertIn("1 ativo de 2 alertas", msg_3)

    def test_formato_ocorrencia_unica_limpo_e_completo(self):
        from datetime import datetime
        from noc.analyzer import _mensagem_deterministica
        from noc.correlator import correlacionar
        from noc.parser import Alerta, RESOLVIDO

        alerta = Alerta(
            status=RESOLVIDO,
            equipamento="LAB-ESCRITORIO-HUAWEI-PE01",
            ip="192.0.2.1",
            problema="Interface XGigabitEthernet0/0/43: High bandwidth usage (>= 90%)",
            nivel="High",
            severidade=4,
            inicio=datetime(2026, 10, 19, 8, 42, 32),
            fim=datetime(2026, 10, 19, 9, 35, 44),
            duracao="53m 12s",
            tags={"backbone": "1"},
            origem="ZABBIX",
        )
        correlacao = correlacionar([alerta])
        analise = AnaliseNOC(
            causa_raiz_provavel="Saturação temporária de tráfego na interface de backbone.",
            confianca="media",
            evidencias=["LAB-ESCRITORIO-HUAWEI-PE01"],
            dados_faltantes=[],
        )
        msg = _mensagem_deterministica(correlacao, analise=analise)

        self.assertIn("Equipamento: LAB-ESCRITORIO-HUAWEI-PE01", msg)
        self.assertIn("IP: 192.0.2.1", msg)
        self.assertIn("Problema: Interface XGigabitEthernet0/0/43: High bandwidth usage (>= 90%)", msg)
        self.assertIn("Nível: High (backbone=1)", msg)
        self.assertIn("Iniciado às: 08:42:32 em 19/10/2026", msg)
        self.assertIn("Resolvido às: 09:35:44 em 19/10/2026", msg)
        self.assertIn("Duração: 53m 12s", msg)
        self.assertNotIn("Base:", msg)
        self.assertLess(msg.index("Equipamento:"), msg.index("Hipótese da IA"))

    def test_lote_grande_preserva_hipotese_ia_e_nao_corta_item_ao_meio(self):
        from datetime import datetime, timedelta
        from noc.analyzer import LIMITE_MENSAGEM, _mensagem_deterministica
        from noc.correlator import correlacionar
        from noc.parser import Alerta, PROBLEMA

        t0 = datetime(2026, 10, 19, 8, 0, 0)
        alertas = [
            Alerta(
                status=PROBLEMA,
                equipamento=f"SITE-{i // 5:02d}-HUAWEI-PE{i:02d}",
                ip=f"192.0.2.{i + 1}",
                problema=f"Interface XGigabitEthernet0/0/{i}(BACKBONE-TRECHO-{i}): Link down e perda de sinal RX",
                nivel="High",
                severidade=4,
                inicio=t0 + timedelta(seconds=i * 10),
                tags={"backbone": "1"},
                origem="ZABBIX",
            )
            for i in range(25)
        ]
        correlacao = correlacionar(alertas)
        analise = AnaliseNOC(
            causa_raiz_provavel="Rompimento óptico afetando múltiplas interfaces de backbone simultaneamente.",
            confianca="alta",
            evidencias=["SITE-00-HUAWEI-PE00"],
            dados_faltantes=[],
        )
        msg = _mensagem_deterministica(correlacao, analise=analise)

        self.assertLessEqual(len(msg), LIMITE_MENSAGEM)
        self.assertIn("💡 Hipótese da IA (não confirmada, confiança: alta):", msg)
        self.assertIn("ocorrências omitidas do resumo.", msg)
        # Em lotes múltiplos, a hipótese entra antes da listagem para não ser truncada
        self.assertLess(msg.index("Hipótese da IA"), msg.index("• 🔴 ATIVO"))

    def test_hipoteses_por_grupo_isoladas_e_preservadas_sob_limite(self):
        from datetime import datetime, timedelta
        from noc.analyzer import HipoteseGrupo, LIMITE_MENSAGEM, _mensagem_deterministica
        from noc.correlator import correlacionar
        from noc.parser import Alerta, PROBLEMA

        t1 = datetime(2026, 10, 19, 8, 0, 0)
        t2 = datetime(2026, 10, 19, 9, 0, 0)  # 1h depois -> Grupo 2

        # Grupo 1: 22 alertas no POP-NORTE
        alertas_g1 = [
            Alerta(
                status=PROBLEMA,
                equipamento=f"POP-NORTE-HUAWEI-PE{i:02d}",
                ip=f"192.0.2.{i + 1}",
                problema=f"Interface XGigabitEthernet0/0/{i}(ENLACE-NORTE-{i}): Link down",
                nivel="High",
                severidade=4,
                inicio=t1 + timedelta(seconds=i * 5),
                tags={"backbone": "1"},
                origem="ZABBIX",
            )
            for i in range(22)
        ]
        # Grupo 2: 1 alerta no POP-SUL
        alerta_g2 = Alerta(
            status=PROBLEMA,
            equipamento="POP-SUL-OLT01",
            ip="198.51.100.10",
            problema="gpon_olt-1/2/7: Interface inoperante",
            nivel="High",
            severidade=4,
            inicio=t2,
            origem="RAVI",
        )

        correlacao = correlacionar(alertas_g1 + [alerta_g2])
        self.assertEqual(len(correlacao.incidentes), 2)

        analise = AnaliseNOC(
            causa_raiz_provavel="Eventos independentes em POP-NORTE e POP-SUL.",
            confianca="media",
            evidencias=["POP-NORTE-HUAWEI-PE00", "POP-SUL-OLT01"],
            dados_faltantes=[],
            hipoteses_por_grupo=[
                HipoteseGrupo(
                    incidente=1,
                    causa_raiz_provavel="Queda múltipla de enlaces de backbone no POP-NORTE.",
                    confianca="alta",
                    evidencias=["POP-NORTE-HUAWEI-PE00"],
                ),
                HipoteseGrupo(
                    incidente=2,
                    causa_raiz_provavel="Indisponibilidade isolada na porta GPON da OLT do POP-SUL.",
                    confianca="media",
                    evidencias=["POP-SUL-OLT01"],
                ),
            ],
        )
        _sanitizar(analise, correlacao)
        msg = _mensagem_deterministica(correlacao, analise=analise)

        self.assertLessEqual(len(msg), LIMITE_MENSAGEM)
        # Ambos os grupos e ambas as hipóteses devem aparecer na mensagem final
        self.assertIn("Queda múltipla de enlaces de backbone no POP-NORTE.", msg)
        self.assertIn("Indisponibilidade isolada na porta GPON da OLT do POP-SUL.", msg)
        self.assertIn("POP-SUL-OLT01", msg)
        self.assertIn("ocorrências omitidas do resumo.", msg)


if __name__ == "__main__":
    unittest.main()
