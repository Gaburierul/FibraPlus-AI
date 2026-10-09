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
        self.assertIn("10:00:00", entrada)
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


if __name__ == "__main__":
    unittest.main()
