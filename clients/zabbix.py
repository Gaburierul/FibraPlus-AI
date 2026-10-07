import os
import requests
from typing import Optional, List, Dict, Any
from dotenv import load_dotenv

# Carrega as variáveis de ambiente
load_dotenv()

class ZabbixClient:
    """
    Cliente para a API JSON-RPC 2.0 do Zabbix.
    """
    def __init__(self):
        """
        Inicializa o cliente Zabbix carregando e validando as credenciais do .env.
        """
        self.url = os.getenv("ZABBIX_URL")
        self.token = os.getenv("ZABBIX_TOKEN")

        if not self.url or not self.token:
            raise ValueError("As variáveis de ambiente ZABBIX_URL e ZABBIX_TOKEN devem estar definidas.")

        self.headers = {
            "Content-Type": "application/json-rpc",
            "Authorization": f"Bearer {self.token}"
        }

    def _call(self, method: str, params: Dict[str, Any]) -> Any:
        """
        Realiza a chamada interna para a API JSON-RPC do Zabbix.
        
        :param method: Método da API do Zabbix (ex: host.get).
        :param params: Parâmetros para a chamada.
        :return: Resultado retornado pela API.
        """
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        }
        
        response = requests.post(self.url, json=payload, headers=self.headers)
        response.raise_for_status()
        
        data = response.json()
        
        if "error" in data:
            error_data = data["error"]
            raise Exception(f"Erro na API Zabbix: {error_data.get('message')} - {error_data.get('data')}")
            
        return data.get("result")

    def get_hosts(self, search: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Obtém uma lista de hosts.
        
        :param search: Filtra os hosts pelo nome (opcional).
        :param limit: Limite máximo de hosts retornados (padrão 50).
        :return: Lista de hosts.
        """
        params: Dict[str, Any] = {
            "output": ["hostid", "host", "name", "status"],
            "limit": limit
        }
        if search:
            params["search"] = {"name": search}
            
        return self._call("host.get", params)

    def get_problems(self, limit: int = 20, severity_min: int = 0) -> List[Dict[str, Any]]:
        """
        Obtém problemas ativos.
        
        :param limit: Limite máximo de problemas (padrão 20).
        :param severity_min: Severidade mínima (0-5).
        :return: Lista de problemas.
        """
        params = {
            "output": "extend",
            "selectTags": "extend",
            "sortfield": ["eventid"],
            "sortorder": "DESC",
            "limit": limit,
            "severities": [i for i in range(severity_min, 6)]
        }
        return self._call("problem.get", params)

    def get_host_details(self, hostname: str) -> Optional[Dict[str, Any]]:
        """
        Obtém os detalhes de um host específico.
        
        :param hostname: Nome do host.
        :return: Dicionário com os detalhes do host ou None.
        """
        params = {
            "filter": {"host": [hostname]},
            "selectInterfaces": "extend",
            "selectItems": ["itemid", "name", "lastvalue", "lastclock"],
            "selectTriggers": ["triggerid", "description", "priority", "value"]
        }
        
        results = self._call("host.get", params)
        return results[0] if results else None

    def get_triggers(self, hostids: Optional[List[str]] = None, only_problems: bool = True) -> List[Dict[str, Any]]:
        """
        Obtém os triggers configurados.
        
        :param hostids: Lista de IDs de hosts para filtrar (opcional).
        :param only_problems: Se verdadeiro, filtra apenas os triggers em estado de problema (value=1).
        :return: Lista de triggers.
        """
        params: Dict[str, Any] = {
            "output": ["triggerid", "description", "priority", "value", "lastchange"],
            "sortfield": ["lastchange"],
            "sortorder": "DESC",
            "limit": 50
        }
        
        if only_problems:
            params["filter"] = {"value": 1}
            
        if hostids:
            params["hostids"] = hostids
            
        return self._call("trigger.get", params)

    def get_events(self, limit: int = 30) -> List[Dict[str, Any]]:
        """
        Obtém os eventos recentes.
        
        :param limit: Número máximo de eventos (padrão 30).
        :return: Lista de eventos.
        """
        params = {
            "output": "extend",
            "source": 0,
            "value": 1,
            "sortfield": ["clock"],
            "sortorder": "DESC",
            "limit": limit
        }
        
        return self._call("event.get", params)
