import os
from pathlib import Path
from urllib.parse import urlsplit
import requests
from typing import Optional, List, Dict, Any
from dotenv import load_dotenv

RAIZ = Path(__file__).resolve().parent.parent
load_dotenv(RAIZ / ".env")

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
        try:
            self.timeout = float(os.getenv("ZABBIX_TIMEOUT_S", "15"))
        except ValueError as exc:
            raise ValueError("ZABBIX_TIMEOUT_S deve ser um número positivo.") from exc

        if not self.url or not self.token:
            raise ValueError("As variáveis de ambiente ZABBIX_URL e ZABBIX_TOKEN devem estar definidas.")
        partes_url = urlsplit(self.url)
        if (partes_url.scheme not in {"http", "https"} or not partes_url.hostname
                or partes_url.username or partes_url.password):
            raise ValueError("ZABBIX_URL deve ser uma URL HTTP(S) válida, sem credenciais embutidas.")
        if not 0 < self.timeout <= 120:
            raise ValueError("ZABBIX_TIMEOUT_S deve estar entre 0 e 120 segundos.")

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
        
        response = requests.post(self.url, json=payload, headers=self.headers, timeout=self.timeout)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise ValueError("Resposta inválida da API Zabbix: esperado um objeto JSON-RPC.")
        
        if "error" in data:
            error_data = data["error"]
            if isinstance(error_data, dict):
                detalhe = " - ".join(
                    str(parte) for parte in (error_data.get("message"), error_data.get("data")) if parte
                )
            else:
                detalhe = str(error_data)
            raise RuntimeError(f"Erro na API Zabbix: {detalhe or 'erro JSON-RPC sem detalhe'}")

        if "result" not in data:
            raise ValueError("Resposta inválida da API Zabbix: campo result ausente.")
            
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

    def get_problems(self, limit: int = 20, severity_min: int = 0, time_from: int = None) -> List[Dict[str, Any]]:
        """
        Obtém problemas ativos.
        
        :param limit: Limite máximo de problemas (padrão 20).
        :param severity_min: Severidade mínima (0-5).
        :param time_from: Filtrar problemas gerados após este timestamp (Unix epoch).
        :return: Lista de problemas.
        """
        if not 1 <= limit <= 10000:
            raise ValueError("limit deve estar entre 1 e 10000.")
        if not 0 <= severity_min <= 5:
            raise ValueError("severity_min deve estar entre 0 e 5.")
        if time_from is not None and time_from < 0:
            raise ValueError("time_from deve ser um timestamp Unix não negativo.")

        params = {
            "output": "extend",
            "selectTags": "extend",
            "sortfield": ["eventid"],
            "sortorder": "DESC",
            "limit": limit,
            "severities": [i for i in range(severity_min, 6)]
        }
        if time_from is not None:
            params["time_from"] = time_from
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

    def get_trigger_events(self, limit: int = 500, eventid_from: int = None,
                           time_from: int = None) -> List[Dict[str, Any]]:
        """Busca transições de trigger em ordem crescente, incluindo problemas e resoluções.

        Use exatamente um cursor: ``eventid_from`` para polling incremental ou
        ``time_from`` para a primeira leitura. A API documenta ``eventid_from``
        como inclusivo; o chamador deve passar o último ID processado + 1.
        """
        if not 1 <= limit <= 10000:
            raise ValueError("limit deve estar entre 1 e 10000.")
        if eventid_from is not None and eventid_from < 1:
            raise ValueError("eventid_from deve ser um ID positivo.")
        if time_from is not None and time_from < 0:
            raise ValueError("time_from deve ser um timestamp Unix não negativo.")
        if eventid_from is not None and time_from is not None:
            raise ValueError("Informe eventid_from ou time_from, não ambos.")

        params: Dict[str, Any] = {
            "output": ["eventid", "source", "object", "objectid", "clock", "value",
                       "name", "severity", "r_eventid"],
            "source": 0,
            "object": 0,
            "selectHosts": ["hostid", "host", "name"],
            "selectTags": "extend",
            "sortfield": ["eventid"],
            "sortorder": "ASC",
            "limit": limit,
        }
        if eventid_from is not None:
            params["eventid_from"] = str(eventid_from)
        elif time_from is not None:
            params["time_from"] = time_from

        resultado = self._call("event.get", params)
        if not isinstance(resultado, list) or any(not isinstance(item, dict) for item in resultado):
            raise ValueError("Resposta inválida de event.get: esperado uma lista de eventos.")
        return resultado
