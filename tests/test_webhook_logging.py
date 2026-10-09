import logging
import os
import unittest

# Evita carregar credenciais locais quando o módulo configura o filtro de log.
os.environ["MODO_TESTE"] = "true"
os.environ["WEBHOOK_TOKEN"] = ""
os.environ["RAVI_WEBHOOK_TOKEN"] = "unit-ravi-secret"
os.environ["ZABBIX_WEBHOOK_TOKEN"] = "unit-zabbix-secret"

from server.webhook import _RedigirTokenQuery, _token_valido_para_origem


class WebhookLoggingTests(unittest.TestCase):
    def test_token_por_origem_e_fallback_legado(self):
        self.assertTrue(_token_valido_para_origem("unit-ravi-secret", ("unit-ravi-secret", "legacy")))
        self.assertTrue(_token_valido_para_origem("legacy", ("unit-ravi-secret", "legacy")))
        self.assertFalse(_token_valido_para_origem("unit-zabbix-secret", ("unit-ravi-secret", "legacy")))

    def test_filtro_redige_token_da_url_no_log_de_acesso(self):
        registro = logging.LogRecord(
            "uvicorn.access", logging.INFO, "", 0, "%s - \"%s %s HTTP/%s\" %s",
            ("127.0.0.1", "POST", "/ravi/webhook?token=secret-value&x=1", "1.1", 202),
            None,
        )

        self.assertTrue(_RedigirTokenQuery().filter(registro))
        self.assertNotIn("secret-value", str(registro.args))
        self.assertIn("[REDACTED]", str(registro.args))


if __name__ == "__main__":
    unittest.main()
