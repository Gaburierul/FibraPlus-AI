"""
Cliente API para o Ravicor.
"""
import os
import requests
from dotenv import load_dotenv

# Força a leitura do arquivo .env no caminho exato
load_dotenv(dotenv_path=r"C:\FibraPlus-AI\.env")

class RavicorClient:
    def __init__(self):
        self.url = os.getenv("RAVICOR_URL")
        self.token = os.getenv("RAVICOR_TOKEN")
        
        if not self.url or not self.token:
            raise ValueError("RAVICOR_URL e RAVICOR_TOKEN devem estar no .env")

    def _call(self, action: str, operation: str, **extra_params) -> dict:
        """Faz a chamada POST com form-data padrão do Ravicor."""
        data = {
            "token": self.token,
            "action": action,
            "operation": operation
        }
        data.update(extra_params)
        
        response = requests.post(self.url, data=data, timeout=15)
        response.raise_for_status()
        return response.json()

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