import unittest

from noc.parser import PROBLEMA, RESOLVIDO
from noc.ravi_event import (
    PayloadRaviIgnorado,
    chave_evento_ravi,
    payload_para_alerta_ravi,
)


class RaviEventTests(unittest.TestCase):
    def test_resolvido_nao_vira_problema_por_conter_campo_problema(self):
        alerta = payload_para_alerta_ravi({
            "evento": "incidente",
            "mensagem": (
                "✅ NORMALIZADO | ambiente sintético\n"
                "Dispositivo: LAB-OLT-01\n"
                "Problema: interface ficou offline\n"
                "Severidade: High\n"
                "Data: 2025-01-15 12:05:00"
            )
        })

        self.assertEqual(alerta.status, RESOLVIDO)
        self.assertEqual(alerta.fim.isoformat(), "2025-01-15T12:05:00")

    def test_evento_ativo_com_cabecalho_explicito(self):
        alerta = payload_para_alerta_ravi({
            "mensagem": (
                "❌ PROBLEMA ENCONTRADO\n"
                "Dispositivo: LAB-PE-01\n"
                "Problema: peer de laboratório offline\n"
                "Severidade: High\n"
                "Data: 2025-01-15 12:00:00"
            )
        })

        self.assertEqual(alerta.status, PROBLEMA)
        self.assertEqual(alerta.inicio.isoformat(), "2025-01-15T12:00:00")

    def test_payload_misto_nao_e_classificado_como_evento_unico(self):
        with self.assertRaises(PayloadRaviIgnorado):
            payload_para_alerta_ravi({
                "mensagem": (
                    "✅ NORMALIZADO | resumo sintético\n"
                    "🔴 ATIVO | segundo alerta sintético\n"
                    "Dispositivo: LAB-PE-01\n"
                    "Problema: status misto\n"
                    "Severidade: High"
                )
            })

    def test_chave_idempotente_somente_com_id_de_evento(self):
        self.assertEqual(chave_evento_ravi({"event_id": "evt-42"}), ("RAVI", "evt-42"))
        self.assertIsNone(chave_evento_ravi({"mensagem": "alerta sem ID"}))
        self.assertIsNone(chave_evento_ravi({"event_id": "x" * 201}))


if __name__ == "__main__":
    unittest.main()
