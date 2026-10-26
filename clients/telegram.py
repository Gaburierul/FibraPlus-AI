"""
Cliente mínimo do Telegram (usado para homologação do NOC IA).

Variáveis de ambiente (.env):
    TELEGRAM_BOT_TOKEN   Token do bot (criado no @BotFather)
    TELEGRAM_CHAT_ID     ID do seu chat ou do grupo (pode ser negativo para grupos)
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Optional

import requests
from dotenv import load_dotenv

RAIZ = Path(__file__).resolve().parent.parent
load_dotenv(RAIZ / ".env")


class TelegramErro(RuntimeError):
    pass


class TelegramClient:
    def __init__(self, token: Optional[str] = None, timeout: Optional[float] = None):
        self.token = token or os.getenv("TELEGRAM_BOT_TOKEN", "")
        try:
            self.timeout = float(timeout if timeout is not None else os.getenv("MESSAGING_TIMEOUT_S", "20"))
        except (TypeError, ValueError) as exc:
            raise TelegramErro("MESSAGING_TIMEOUT_S deve ser numérico.") from exc
        if not self.token:
            raise TelegramErro("TELEGRAM_BOT_TOKEN ausente no .env")
        if not 0 < self.timeout <= 120:
            raise TelegramErro("MESSAGING_TIMEOUT_S deve estar entre 0 e 120 segundos.")

    def enviar_texto(self, destino: str, texto: str, tentativas: int = 3) -> dict[str, Any]:
        """Envia texto; repete 429 e falhas de conexão, nunca timeouts de leitura.

        Falha de conexão (DNS, recusa, timeout ao conectar) quase sempre ocorre antes
        de a requisição chegar ao Telegram; em casos raros de queda de socket após o
        envio do request (ConnectionResetError), pode gerar duplicata — trade-off
        intencional em alerta operacional onde perder o alerta é pior que duplicá-lo.
        Timeout de leitura é ambíguo (a mensagem pode ter sido entregue) e não é repetido.
        """
        if not isinstance(destino, str) or not destino.strip():
            raise TelegramErro("Destino vazio ou inválido.")
        if not isinstance(texto, str) or not texto.strip():
            raise TelegramErro("Mensagem vazia ou inválida.")
        if len(texto) > 4096:
            raise TelegramErro("Mensagem excede o limite de 4096 caracteres do Telegram.")
        if not 1 <= tentativas <= 5:
            raise TelegramErro("tentativas deve estar entre 1 e 5.")
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        payload = {
            "chat_id": destino,
            "text": texto,
        }
        
        for tentativa in range(1, tentativas + 1):
            try:
                resp = requests.post(url, json=payload, timeout=self.timeout)
            except requests.ConnectionError as exc:
                # Exceções HTTP podem incluir a URL completa, que contém o token do bot:
                # só o nome da classe é propagado.
                if tentativa >= tentativas:
                    raise TelegramErro(
                        f"{type(exc).__name__}; falha de conexão após {tentativas} tentativas."
                    ) from None
                time.sleep(2 * tentativa)
                continue
            except requests.RequestException as exc:
                raise TelegramErro(
                    f"{type(exc).__name__}; resultado do envio incerto, não foi repetido para evitar duplicata."
                ) from None
            else:
                if resp.ok:
                    try:
                        dados = resp.json()
                    except ValueError:
                        raise TelegramErro("Telegram retornou resposta inválida após o envio.") from None
                    if isinstance(dados, dict) and dados.get("ok") is True:
                        return dados
                    raise TelegramErro("Telegram não confirmou o envio.")
                if resp.status_code != 429:
                    raise TelegramErro(f"Telegram recusou o envio (HTTP {resp.status_code}).")
                if tentativa >= tentativas:
                    raise TelegramErro("Telegram limitou o envio (HTTP 429); tentativas esgotadas.")
                _aguardar_429(resp.headers.get("Retry-After"), tentativa)
        raise TelegramErro("Telegram não confirmou o envio.")


def _aguardar_429(retry_after: Optional[str], tentativa: int) -> None:
    try:
        espera = float(retry_after) if retry_after else 2 * tentativa
    except ValueError:
        espera = 2 * tentativa
    time.sleep(max(0, min(espera, 30)))
