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

    def test_limpeza_formatacao_whatsapp_markdown(self):
        alerta = payload_para_alerta_ravi({
            "mensagem": (
                "❌ PROBLEMA ENCONTRADO\n"
                "*Dispositivo:* * SWITCH 6730 _(ITAPORA - ITP)_\n"
                "*Sensor:* * Potência RX 100GE0/0/3\n"
                "*Problema:* * Sinal RX caiu mais de 30% em relação à média esperada para o horário\n"
                "Severidade: High\n"
                "Data: 13/10/2026 12:05:26"
            )
        })
        self.assertEqual(alerta.equipamento, "SWITCH 6730 (ITAPORA - ITP)")
        self.assertEqual(
            alerta.problema,
            "Sensor Potência RX 100GE0/0/3: Sinal RX caiu mais de 30% em relação à média esperada para o horário"
        )

    def test_campos_com_prefixo_nao_colidem(self):
        alerta = payload_para_alerta_ravi({
            "mensagem": (
                "❌ PROBLEMA ENCONTRADO\n"
                "Cliente VIP: ACME\n"
                "IP: 192.0.2.55\n"
                "Dispositivo: LAB-SW-01\n"
                "Tipo de Problema: Óptico\n"
                "Problema: Sinal RX degradado\n"
                "Severidade: High"
            )
        })
        self.assertEqual(alerta.ip, "192.0.2.55")
        self.assertEqual(alerta.problema, "Sinal RX degradado")

    def test_ravi_resolvido_com_nome_status_data_atual_e_tempo_decorrido(self):
        alerta = payload_para_alerta_ravi({
            "data": "19/10/2026 10:37:33",
            "mensagem": (
                "✅ PROBLEMA RESOLVIDO\n\n"
                "Dispositivo: OLT (SITE EXEMPLO - EXM)\n"
                "IP: 192.0.2.2\n"
                "Nome: gpon_olt-1/2/7\n"
                "Status: Interface voltou a ficar operante. Funcionamento normalizado.\n"
                "Data atual: 19/10/2026 10:37:09\n"
                "Tempo decorrido: 00:02:32"
            ),
        })
        self.assertEqual(alerta.status, RESOLVIDO)
        self.assertEqual(alerta.equipamento, "OLT (SITE EXEMPLO - EXM)")
        self.assertEqual(alerta.ip, "192.0.2.2")
        self.assertEqual(
            alerta.problema,
            "gpon_olt-1/2/7: Interface voltou a ficar operante. Funcionamento normalizado.",
        )
        self.assertEqual(alerta.fim.isoformat(), "2026-10-19T10:37:09")
        self.assertEqual(alerta.duracao, "00:02:32")
        self.assertEqual(alerta.tags.get("item_chave"), "gpon_olt-1/2/7")

    def test_ravi_alerta_problema_massivo_olt_extrai_campos_em_topicos(self):
        from noc.correlator import correlacionar

        p1 = payload_para_alerta_ravi({
            "origem": "ravi-monitor",
            "evento": "alerta",
            "origem_modulo": "olt",
            "data": "2026-10-19 16:30:45",
            "mensagem": (
                "🚨 *ALERTA DE PROBLEMA MASSIVO*\n\n"
                "*Localização do Problema*\n"
                "- OLT: OLT NOVA ALVORADA\n"
                "- Endereço IP: 192.0.2.82\n"
                "- PON Afetada: Slot 1 / PON 7\n\n"
                "⚠️ *Detalhes do Incidente*\n"
                "- ONTs Offline: 28 unidades\n"
                "- IDs Afetadas: 1, 2, 3\n"
                "- Limite Crítico: 10+ ONTs offline"
            ),
        })
        p2 = payload_para_alerta_ravi({
            "origem": "ravi-monitor",
            "evento": "alerta",
            "origem_modulo": "olt",
            "data": "2026-10-19 16:30:46",
            "mensagem": (
                "🚨 *ALERTA DE PROBLEMA MASSIVO*\n\n"
                "*Localização do Problema*\n"
                "- OLT: OLT NOVA ALVORADA\n"
                "- Endereço IP: 192.0.2.82\n"
                "- PON Afetada: Slot 2 / PON 7\n\n"
                "⚠️ *Detalhes do Incidente*\n"
                "- ONTs Offline: 53 unidades"
            ),
        })

        self.assertEqual(p1.status, PROBLEMA)
        self.assertEqual(p1.equipamento, "OLT NOVA ALVORADA")
        self.assertEqual(p1.ip, "192.0.2.82")
        self.assertEqual(p1.problema, "Slot 1 / PON 7: Queda massiva (28 unidades offline)")
        self.assertEqual(p1.tags.get("item_chave"), "Slot 1 / PON 7")

        correlacao = correlacionar([p1, p2])
        self.assertEqual(len(correlacao.ocorrencias), 2)
        self.assertTrue(all(o.estado == "ATIVO" for o in correlacao.ocorrencias))
        self.assertEqual(correlacao.incidentes[0].sites, ["NOVA-ALVORADA"])

    def test_ravi_problema_massivo_resolvido_casa_pela_pon(self):
        from noc.correlator import correlacionar

        prob = payload_para_alerta_ravi({
            "origem": "ravi-monitor",
            "evento": "alerta",
            "origem_modulo": "olt",
            "data": "2026-10-19 10:30:47",
            "mensagem": (
                "🚨 *ALERTA DE PROBLEMA MASSIVO*\n\n"
                "*Localização do Problema*\n"
                "- OLT: OLT NOVA ALVORADA\n"
                "- Endereço IP: 192.0.2.82\n"
                "- PON Afetada: Slot 1 / PON 7\n\n"
                "⚠️ *Detalhes do Incidente*\n"
                "- ONTs Offline: 21 unidades"
            ),
        })
        res = payload_para_alerta_ravi({
            "origem": "ravi-monitor",
            "evento": "resolvido",
            "origem_modulo": "olt",
            "data": "2026-10-19 10:45:47",
            "mensagem": (
                "✅ *PROBLEMA MASSIVO RESOLVIDO*\n\n"
                "*Localização*\n"
                "- OLT: OLT NOVA ALVORADA\n"
                "- Endereço IP: 192.0.2.82\n"
                "- PON Restaurada: Slot 1 / PON 7\n\n"
                "*Status da Resolução*\n"
                "- ONTs Reconectadas: 21 unidades\n\n"
                "*Tempo de Resolução*\n"
                "Problema resolvido em: 15 minutos"
            ),
        })

        self.assertEqual(res.status, RESOLVIDO)
        self.assertEqual(res.equipamento, "OLT NOVA ALVORADA")
        self.assertEqual(res.ip, "192.0.2.82")
        self.assertEqual(res.problema, "Slot 1 / PON 7: Normalizado (21 unidades reconectadas)")
        self.assertEqual(res.duracao, "15 minutos")
        self.assertEqual(res.tags.get("item_chave"), "Slot 1 / PON 7")

        correlacao = correlacionar([prob, res])
        self.assertEqual(len(correlacao.ocorrencias), 1)
        self.assertEqual(correlacao.ocorrencias[0].estado, "RESOLVIDO")


if __name__ == "__main__":
    unittest.main()
