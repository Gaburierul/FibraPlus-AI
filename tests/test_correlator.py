import unittest
from datetime import datetime

from noc.parser import Alerta, PROBLEMA, RESOLVIDO
from noc.correlator import _consolidar, correlacionar


class CorrelatorResolutionTests(unittest.TestCase):
    def test_resolucao_sem_inicio_casa_com_problema_anterior(self):
        t_prob = datetime(2026, 10, 12, 10, 0, 0)
        t_res = datetime(2026, 10, 12, 10, 5, 0)
        
        prob = Alerta(
            status=PROBLEMA,
            equipamento="LAB-ROUTER-01",
            problema="Link down",
            inicio=t_prob,
            origem="RAVI",
        )
        # Resolução do Ravi que só traz o fim/horário do evento, sem início
        res = Alerta(
            status=RESOLVIDO,
            equipamento="LAB-ROUTER-01",
            problema="Link down",
            inicio=None,
            fim=t_res,
            origem="RAVI",
        )
        
        ocorrencias = _consolidar([prob, res])
        self.assertEqual(len(ocorrencias), 1)
        self.assertEqual(ocorrencias[0].estado, "RESOLVIDO")

    def test_problema_sem_resolucao_permanece_ativo(self):
        t_prob = datetime(2026, 10, 12, 10, 0, 0)
        prob = Alerta(
            status=PROBLEMA,
            equipamento="LAB-ROUTER-01",
            problema="Link down",
            inicio=t_prob,
            origem="ZABBIX",
        )
        ocorrencias = _consolidar([prob])
        self.assertEqual(len(ocorrencias), 1)
        self.assertEqual(ocorrencias[0].estado, "ATIVO")

    def test_decompor_hostname_limpa_simbolos_e_extrai_site_e_funcao(self):
        from noc.correlator import decompor_hostname
        # Ravi com site em parênteses e asteriscos/underlines
        site, funcao, fab = decompor_hostname("* SWITCH 6730 _(ITAPORA - ITP)_")
        self.assertEqual(site, "ITAPORA-ITP")
        self.assertEqual(funcao, "SWITCH-6730")
        self.assertIsNone(fab)

        # Servidor com role em parênteses
        site, funcao, fab = decompor_hostname("SERVIDOR-EXEMPLO (ROTAS)")
        self.assertEqual(site, "SERVIDOR-EXEMPLO")
        self.assertEqual(funcao, "ROTAS")
        self.assertIsNone(fab)

        # Padrão Zabbix FibraPlus
        site, funcao, fab = decompor_hostname("CPE-EXEMPLO-HUAWEI-VS02-RR01")
        self.assertEqual(site, "CPE-EXEMPLO")
        self.assertEqual(funcao, "VS02-RR01")
        self.assertEqual(fab, "HUAWEI")

        # Nome com parênteses e fabricante explícito no prefixo
        site, funcao, fab = decompor_hostname("SWITCH HUAWEI 6730 (ITAPORA - ITP)")
        self.assertEqual(site, "ITAPORA-ITP")
        self.assertEqual(funcao, "SWITCH-HUAWEI-6730")
        self.assertEqual(fab, "HUAWEI")

    def test_uma_resolucao_nao_fecha_dois_problemas_distintos(self):
        p1 = Alerta(
            status=PROBLEMA,
            equipamento="LAB-ROUTER-01",
            problema="Link down",
            inicio=datetime(2026, 10, 12, 10, 0, 0),
            origem="RAVI",
        )
        p2 = Alerta(
            status=PROBLEMA,
            equipamento="LAB-ROUTER-01",
            problema="Link down",
            inicio=datetime(2026, 10, 12, 10, 2, 0),
            origem="RAVI",
        )
        r1 = Alerta(
            status=RESOLVIDO,
            equipamento="LAB-ROUTER-01",
            problema="Link down",
            inicio=None,
            fim=datetime(2026, 10, 12, 10, 5, 0),
            origem="RAVI",
        )

        ocorrencias = _consolidar([p1, p2, r1])
        self.assertEqual(len(ocorrencias), 1)
        self.assertEqual(ocorrencias[0].estado, "OSCILANDO")
        self.assertEqual(ocorrencias[0].vezes, 2)

    def test_novo_problema_apos_resolucao_permanece_oscilando_ativo(self):
        p1 = Alerta(
            status=PROBLEMA,
            equipamento="LAB-ROUTER-01",
            problema="Link down",
            inicio=datetime(2026, 10, 12, 10, 0, 0),
            origem="RAVI",
        )
        r1 = Alerta(
            status=RESOLVIDO,
            equipamento="LAB-ROUTER-01",
            problema="Link down",
            inicio=None,
            fim=datetime(2026, 10, 12, 10, 2, 0),
            origem="RAVI",
        )
        p2 = Alerta(
            status=PROBLEMA,
            equipamento="LAB-ROUTER-01",
            problema="Link down",
            inicio=datetime(2026, 10, 12, 10, 4, 0),
            origem="RAVI",
        )

        correlacao = correlacionar([p1, r1, p2])
        self.assertEqual(len(correlacao.ocorrencias), 1)
        self.assertEqual(correlacao.ocorrencias[0].estado, "OSCILANDO")
        self.assertEqual(len(correlacao.incidentes[0].ativos), 1)


if __name__ == "__main__":
    unittest.main()
