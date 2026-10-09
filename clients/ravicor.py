"""
Cliente API para o Ravicor.
"""
import os
from pathlib import Path
from urllib.parse import urlsplit
import requests
from dotenv import load_dotenv

RAIZ = Path(__file__).resolve().parent.parent
load_dotenv(dotenv_path=RAIZ / ".env")

class RavicorClient:
    def __init__(self):
        self.url = os.getenv("RAVICOR_URL")
        self.token = os.getenv("RAVICOR_TOKEN")
        try:
            self.timeout = float(os.getenv("RAVICOR_TIMEOUT_S", "15"))
        except ValueError as exc:
            raise ValueError("RAVICOR_TIMEOUT_S deve ser um número positivo.") from exc
        
        if not self.url or not self.token:
            raise ValueError("RAVICOR_URL e RAVICOR_TOKEN devem estar no .env")
        partes_url = urlsplit(self.url)
        if (partes_url.scheme not in {"http", "https"} or not partes_url.hostname
                or partes_url.username or partes_url.password):
            raise ValueError("RAVICOR_URL deve ser uma URL HTTP(S) válida, sem credenciais embutidas.")
        if not 0 < self.timeout <= 120:
            raise ValueError("RAVICOR_TIMEOUT_S deve estar entre 0 e 120 segundos.")

    def _call(self, action: str, operation: str, **extra_params) -> dict:
        """Faz a chamada POST com form-data padrão do Ravicor."""
        data = {
            "token": self.token,
            "action": action,
            "operation": operation
        }
        data.update(extra_params)
        
        response = requests.post(self.url, data=data, timeout=self.timeout)
        response.raise_for_status()
        resultado = response.json()
        if not isinstance(resultado, dict):
            raise ValueError("Resposta inválida da API Ravicor: esperado um objeto JSON.")
        return resultado

    def list_device_groups(self) -> list:
        """Lista os grupos de dispositivos cadastrados."""
        res = self._call("dispositivo", "list_groups")
        return res.get("groups", [])

    def list_devices(self, group_id: int = None) -> list:
        """Lista os dispositivos. Pode filtrar por group_id."""
        params = {}
        if group_id is not None:
            params["group_id"] = group_id
            
        res = self._call("dispositivo", "list_devices", **params)
        return res.get("devices", [])

    def list_olts(self) -> list:
        """Lista as OLTs cadastradas."""
        res = self._call("olt", "list_olts")
        return res.get("olts", res.get("data", []))

    def get_device(self, device_id: int) -> dict:
        """Obtém os detalhes de um dispositivo específico."""
        return self._call("dispositivo", "get_device", id=device_id)
