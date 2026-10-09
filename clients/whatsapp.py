"""
Cliente mínimo da Evolution API (envio de texto para o grupo do NOC).

Variáveis de ambiente (.env):
    EVOLUTION_URL        ex.: https://evolution.example.com   (sem barra no final)
    EVOLUTION_INSTANCE   nome da instância (sensível a maiúsculas/minúsculas)
    EVOLUTION_APIKEY     apikey da instância (ou a global, conforme o servidor)
    EVOLUTION_GROUP_JID  JID do grupo, ex.: ID_DO_GRUPO@g.us
    EVOLUTION_API_VERSION  "2" (padrão) ou "1" — muda o formato do corpo

Para descobrir o JID do grupo: `python scripts/listar_grupos_evolution.py`.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote, urlsplit

import requests
from dotenv import load_dotenv

RAIZ = Path(__file__).resolve().parent.parent
load_dotenv(RAIZ / ".env")


class EvolutionErro(RuntimeError):
    pass


class EvolutionClient:
    def __init__(self, url: Optional[str] = None, instancia: Optional[str] = None,
                 apikey: Optional[str] = None, versao: Optional[str] = None,
                 timeout: Optional[float] = None):
        self.url = (url or os.getenv("EVOLUTION_URL", "")).rstrip("/")
        self.instancia = instancia or os.getenv("EVOLUTION_INSTANCE", "")
        self.apikey = apikey or os.getenv("EVOLUTION_APIKEY", "")
        self.versao = (versao or os.getenv("EVOLUTION_API_VERSION", "2")).strip()
        try:
            self.timeout = float(timeout if timeout is not None else os.getenv("MESSAGING_TIMEOUT_S", "20"))
        except (TypeError, ValueError) as exc:
            raise EvolutionErro("MESSAGING_TIMEOUT_S deve ser numérico.") from exc
        partes_url = urlsplit(self.url)
        if (partes_url.scheme not in {"http", "https"} or not partes_url.hostname
                or partes_url.username or partes_url.password or partes_url.query or partes_url.fragment):
            raise EvolutionErro("EVOLUTION_URL deve ser uma URL HTTP(S) válida, sem credenciais embutidas.")
        if not 0 < self.timeout <= 120:
            raise EvolutionErro("MESSAGING_TIMEOUT_S deve estar entre 0 e 120 segundos.")
        if self.versao not in {"1", "2"}:
            raise EvolutionErro("EVOLUTION_API_VERSION deve ser 1 ou 2.")
        faltando = [n for n, v in [("EVOLUTION_URL", self.url), ("EVOLUTION_INSTANCE", self.instancia),
                                   ("EVOLUTION_APIKEY", self.apikey)] if not v]
        if faltando:
            raise EvolutionErro(f"Variáveis ausentes no .env: {', '.join(faltando)}")

    @property
    def _headers(self) -> dict[str, str]:
        return {"apikey": self.apikey, "Content-Type": "application/json"}

    def _corpo_texto(self, destino: str, texto: str) -> dict[str, Any]:
        if self.versao == "1":
            return {"number": destino, "options": {"delay": 0}, "textMessage": {"text": texto}}
        return {"number": destino, "text": texto}

    def enviar_texto(self, destino: str, texto: str, tentativas: int = 3) -> dict[str, Any]:
        """Envia texto; só repete 429, que confirma que a API recusou a tentativa."""
        if not isinstance(destino, str) or not destino.strip():
            raise EvolutionErro("Destino vazio ou inválido.")
        if not isinstance(texto, str) or not texto.strip():
            raise EvolutionErro("Mensagem vazia ou inválida.")
        if not 1 <= tentativas <= 5:
            raise EvolutionErro("tentativas deve estar entre 1 e 5.")
        instancia = quote(self.instancia, safe="")
        endpoint = f"{self.url}/message/sendText/{instancia}"
        for tentativa in range(1, tentativas + 1):
            try:
                resp = requests.post(endpoint, json=self._corpo_texto(destino, texto),
                                     headers=self._headers, timeout=self.timeout)
            except requests.RequestException as exc:
                raise EvolutionErro(
                    f"{type(exc).__name__}; resultado do envio incerto, não foi repetido para evitar duplicata."
                ) from None
            else:
                if resp.ok:
                    try:
                        dados = resp.json()
                        return dados if isinstance(dados, dict) else {"status": resp.status_code}
                    except ValueError:
                        return {"status": resp.status_code}
                if resp.status_code != 429:
                    raise EvolutionErro(f"API Evolution recusou o envio (HTTP {resp.status_code}).")
                if tentativa >= tentativas:
                    raise EvolutionErro("API Evolution limitou o envio (HTTP 429); tentativas esgotadas.")
                _aguardar_429(resp.headers.get("Retry-After"), tentativa)
        raise EvolutionErro("API Evolution não confirmou o envio.")

    def listar_grupos(self) -> list[dict[str, Any]]:
        instancia = quote(self.instancia, safe="")
        endpoint = f"{self.url}/group/fetchAllGroups/{instancia}"
        try:
            resp = requests.get(endpoint, params={"getParticipants": "false"},
                                headers=self._headers, timeout=self.timeout)
        except requests.RequestException as exc:
            raise EvolutionErro(f"{type(exc).__name__} ao consultar grupos.") from None
        if not resp.ok:
            raise EvolutionErro(f"API Evolution recusou a consulta de grupos (HTTP {resp.status_code}).")
        try:
            dados = resp.json()
        except ValueError:
            raise EvolutionErro("API Evolution retornou JSON inválido ao listar grupos.") from None
        if isinstance(dados, list):
            return dados
        if isinstance(dados, dict) and isinstance(dados.get("groups", []), list):
            return dados.get("groups", [])
        raise EvolutionErro("API Evolution retornou formato inesperado ao listar grupos.")


def _aguardar_429(retry_after: Optional[str], tentativa: int) -> None:
    try:
        espera = float(retry_after) if retry_after else 2 * tentativa
    except ValueError:
        espera = 2 * tentativa
    time.sleep(max(0, min(espera, 30)))
