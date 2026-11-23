from __future__ import annotations

import os
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

import requests
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
        self._session = requests.Session()

    def close(self) -> None:
        """Libera as conexões HTTP mantidas pela sessão."""
        self._session.close()

    def __enter__(self) -> ZabbixClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"ZabbixClient(timeout={self.timeout:g})"

    def _call(self, method: str, params: dict[str, Any]) -> Any:
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
        
        response = self._session.post(self.url, json=payload, headers=self.headers, timeout=self.timeout)
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

    def get_hosts(self, search: Optional[str] = None, limit: int = 50,
                  with_interfaces: bool = False,
                  with_groups: bool = False) -> list[dict[str, Any]]:
        """
        Obtém uma lista de hosts.
        
        :param search: Filtra os hosts pelo nome (opcional).
        :param limit: Limite máximo de hosts retornados (padrão 50).
        :param with_interfaces: Inclui IPs das interfaces do host quando True.
        :param with_groups: Inclui grupos de hosts (ex.: nome completo da cidade/POP) quando True.
        :return: Lista de hosts.
        """
        params: dict[str, Any] = {
            "output": ["hostid", "host", "name", "status"],
            "limit": max(1, min(limit, 2000)),
        }
        if with_interfaces:
            params["selectInterfaces"] = ["ip", "dns", "port", "main", "type"]
        if with_groups:
            params["selectHostGroups"] = ["name"]
        if search:
            params["search"] = {"name": search}
            
        return self._call("host.get", params)

    def get_problems(self, limit: int = 20, severity_min: int = 0,
                     time_from: Optional[int] = None) -> list[dict[str, Any]]:
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

    def get_host_details(self, hostname: str) -> Optional[dict[str, Any]]:
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

    def get_triggers(self, hostids: Optional[list[str]] = None, only_problems: bool = True) -> list[dict[str, Any]]:
        """
        Obtém os triggers configurados.
        
        :param hostids: Lista de IDs de hosts para filtrar (opcional).
        :param only_problems: Se verdadeiro, filtra apenas os triggers em estado de problema (value=1).
        :return: Lista de triggers.
        """
        params: dict[str, Any] = {
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

    def get_events(self, limit: int = 30) -> list[dict[str, Any]]:
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

    def get_trigger_events(self, limit: int = 500, eventid_from: Optional[int] = None,
                           time_from: Optional[int] = None) -> list[dict[str, Any]]:
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

        params: dict[str, Any] = {
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

    # ------------------------------------------------------------------
    # Métodos de investigação aprofundada (somente leitura)
    # ------------------------------------------------------------------

    def resolve_host(self, nome_ou_id: str) -> Optional[dict[str, Any]]:
        """Resolve um host por hostid numérico, nome exato ou busca parcial."""
        termo = (nome_ou_id or "").strip()
        if not termo:
            return None
        if termo.isdigit():
            res = self._call("host.get", {
                "hostids": [termo],
                "output": ["hostid", "host", "name", "status"],
                "selectInterfaces": ["ip", "dns", "port", "main", "type"],
            })
            if res:
                return res[0]
        for campo in ("name", "host"):
            res = self._call("host.get", {
                "filter": {campo: [termo]},
                "output": ["hostid", "host", "name", "status"],
                "selectInterfaces": ["ip", "dns", "port", "main", "type"],
            })
            if res:
                return res[0]
        res = self._call("host.get", {
            "search": {"name": termo},
            "output": ["hostid", "host", "name", "status"],
            "selectInterfaces": ["ip", "dns", "port", "main", "type"],
            "limit": 10,
        })
        return res[0] if res else None

    def get_items(
        self,
        hostids: list[str] | str,
        search_name: Optional[str] = None,
        search_key: Optional[str] = None,
        limit: int = 300,
    ) -> list[dict[str, Any]]:
        """Consulta itens (métricas) atuais de um ou mais hosts via ``item.get``."""
        hids = [hostids] if isinstance(hostids, str) else list(hostids)
        params: dict[str, Any] = {
            "hostids": hids,
            "output": ["itemid", "hostid", "name", "key_", "lastvalue", "lastclock", "units", "value_type"],
            "limit": max(1, min(limit, 5000)),
        }
        search: dict[str, str] = {}
        if search_name:
            search["name"] = search_name
        if search_key:
            search["key_"] = search_key
        if search:
            params["search"] = search
        return self._call("item.get", params)

    def get_history(
        self,
        itemids: list[str] | str,
        value_type: int,
        time_from: int,
        time_till: Optional[int] = None,
        limit: int = 1000,
        sortorder: str = "ASC",
    ) -> list[dict[str, Any]]:
        """Consulta série temporal de métricas via ``history.get``."""
        iids = [itemids] if isinstance(itemids, str) else list(itemids)
        params: dict[str, Any] = {
            "itemids": iids,
            "history": int(value_type),
            "time_from": int(time_from),
            "sortfield": "clock",
            "sortorder": "DESC" if sortorder.upper() == "DESC" else "ASC",
            "limit": max(1, min(limit, 5000)),
        }
        if time_till is not None:
            params["time_till"] = int(time_till)
        return self._call("history.get", params)

    def get_trends(
        self,
        itemids: list[str] | str,
        time_from: int,
        time_till: Optional[int] = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """Consulta tendências horárias agregadas via ``trend.get`` (janelas longas)."""
        iids = [itemids] if isinstance(itemids, str) else list(itemids)
        params: dict[str, Any] = {
            "itemids": iids,
            "time_from": int(time_from),
            "output": ["itemid", "clock", "num", "value_min", "value_avg", "value_max"],
            "limit": max(1, min(limit, 5000)),
        }
        if time_till is not None:
            params["time_till"] = int(time_till)
        return self._call("trend.get", params)

    def get_active_triggers(
        self,
        hostids: Optional[list[str] | str] = None,
        search: Optional[str] = None,
        limit: int = 500,
        with_items: bool = True,
    ) -> list[dict[str, Any]]:
        """Retorna triggers ativas (value=1, status=0) com últimos valores dos itens."""
        params: dict[str, Any] = {
            "output": ["triggerid", "description", "priority", "value", "lastchange"],
            "filter": {"value": 1, "status": 0},
            "selectHosts": ["hostid", "host", "name"],
            "sortfield": ["lastchange"],
            "sortorder": "DESC",
            "limit": max(1, min(limit, 5000)),
        }
        if with_items:
            params["selectItems"] = ["itemid", "name", "key_", "lastvalue", "units"]
        if hostids:
            params["hostids"] = [hostids] if isinstance(hostids, str) else list(hostids)
        if search:
            params["search"] = {"description": search}
        return self._call("trigger.get", params)

    def get_pon_summary(self, host_nome_ou_id: str) -> dict[str, Any]:
        """Consolida saúde PON a PON de uma OLT (ZTE/GPON e VSOL/EPON) e classifica quedas de ONUs."""
        host = self.resolve_host(host_nome_ou_id)
        if not host:
            raise ValueError(f"Host OLT não encontrado no Zabbix: {host_nome_ou_id!r}")

        hostid = host["hostid"]
        host_name = host.get("name") or host.get("host") or hostid
        items = self.get_items(hostid, limit=5000)

        pons: dict[str, dict[str, int]] = defaultdict(dict)
        max_clock = 0
        for it in items:
            nome = it.get("name", "")
            m_zte = re.match(r"^PON\s+((?:gpon|epon)[^:]+):\s+ONUs\s+(\w+)", nome, re.I)
            m_vsol = re.match(r"^((?:EPON|GPON)[^:]+):\s+ONUs\s+(\w+)", nome, re.I)
            m = m_zte or m_vsol
            if m:
                pon_id = m.group(1).strip()
                metrica = m.group(2).strip().upper()
                try:
                    pons[pon_id][metrica] = int(float(it.get("lastvalue") or 0))
                except (TypeError, ValueError):
                    pons[pon_id][metrica] = 0
                try:
                    max_clock = max(max_clock, int(it.get("lastclock") or 0))
                except (TypeError, ValueError):
                    pass

        prov_explicito = sum(d.get("PROVISIONADAS", 0) for d in pons.values())
        total_on = sum(d.get("ONLINE", 0) for d in pons.values())
        total_loss = sum(d.get("LOSS", 0) for d in pons.values())
        total_dg = sum(d.get("DYINGGASP", 0) for d in pons.values())
        total_off = sum(d.get("OFFLINE", 0) for d in pons.values())
        prov_inferido = prov_explicito == 0 and (total_on + total_loss + total_dg + total_off) > 0

        totais = {
            "pons_monitoradas": len(pons),
            "provisionadas": (total_on + total_loss + total_dg + total_off) if prov_inferido else prov_explicito,
            "online": total_on,
            "loss": total_loss,
            "dyinggasp": total_dg,
            "offline": total_off,
        }

        pons_afetadas = []
        for pon_id, d in pons.items():
            loss = d.get("LOSS", 0)
            dg = d.get("DYINGGASP", 0)
            off = d.get("OFFLINE", 0)
            on = d.get("ONLINE", 0)
            prov = d.get("PROVISIONADAS", 0)
            base_total = prov if prov > 0 else (on + loss + dg + off)
            if loss > 0 or dg > 0 or off > 0 or (base_total > 0 and on < base_total):
                caidas = max(0, base_total - on) if prov > 0 else (loss + dg + off)
                pct = round(100.0 * caidas / base_total, 1) if base_total else 0.0
                pons_afetadas.append({
                    "pon": pon_id,
                    "provisionadas": base_total,
                    "online": on,
                    "loss": loss,
                    "dyinggasp": dg,
                    "offline": off,
                    "percentual_queda": pct,
                })
        pons_afetadas.sort(key=lambda x: (-x["loss"], -x["dyinggasp"], -x["offline"], x["pon"]))

        triggers = self.get_active_triggers(hostids=[hostid], limit=2000, with_items=True)
        motivos_clientes: Counter[str] = Counter()
        triggers_infra: list[dict[str, Any]] = []
        clientes_recentes: list[dict[str, Any]] = []
        for t in triggers:
            desc = t.get("description", "")
            eh_cli = bool(re.match(r"^cliente\s*:", desc, re.I) or "sinal acima" in desc.lower())
            if not eh_cli:
                triggers_infra.append({
                    "descricao": desc,
                    "prioridade": int(t.get("priority") or 0),
                    "lastchange": int(t.get("lastchange") or 0),
                })
                continue
            itens_t = t.get("items") or []
            val = str(itens_t[0].get("lastvalue", "")) if itens_t else ""
            if "sinal acima" in desc.lower():
                motivo = "Sinal óptico alto"
            elif val == "-80":
                motivo = "LOS / Rompimento (-80)"
            elif val == "-90":
                motivo = "DyingGasp / Energia (-90)"
            else:
                motivo = f"Outro ({val or 'sem valor'})"
            motivos_clientes[motivo] += 1
            if len(clientes_recentes) < 25:
                clientes_recentes.append({
                    "descricao": desc,
                    "motivo": motivo,
                    "lastchange": int(t.get("lastchange") or 0),
                })

        return {
            "host": host_name,
            "hostid": hostid,
            "ultimo_dado_clock": max_clock,
            "totais": totais,
            "pons_afetadas": pons_afetadas[:40],
            "total_pons_afetadas": len(pons_afetadas),
            "triggers_infra_ativas": triggers_infra[:30],
            "clientes_ativos_por_motivo": dict(motivos_clientes),
            "clientes_ativos_amostra_recente": clientes_recentes,
        }
