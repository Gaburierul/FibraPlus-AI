"""
Cliente API para o Ravicor (somente leitura).
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional
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
        self._session = requests.Session()

    def close(self) -> None:
        """Libera as conexões HTTP mantidas pela sessão."""
        self._session.close()

    def __enter__(self) -> RavicorClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"RavicorClient(timeout={self.timeout:g})"

    def _call(self, action: str, operation: str, **extra_params: Any) -> dict[str, Any]:
        """Faz a chamada POST com form-data padrão do Ravicor."""
        data = {
            "token": self.token,
            "action": action,
            "operation": operation,
        }
        data.update(extra_params)

        response = self._session.post(self.url, data=data, timeout=self.timeout)
        response.raise_for_status()
        resultado = response.json()
        if not isinstance(resultado, dict):
            raise ValueError("Resposta inválida da API Ravicor: esperado um objeto JSON.")
        return resultado

    def list_device_groups(self) -> list[dict[str, Any]]:
        """Lista os grupos de dispositivos cadastrados."""
        res = self._call("dispositivo", "list_groups")
        return res.get("groups", [])

    def list_devices(self, group_id: Optional[int] = None) -> list[dict[str, Any]]:
        """Lista os dispositivos. Pode filtrar por group_id."""
        params: dict[str, Any] = {}
        if group_id is not None:
            params["group_id"] = group_id

        res = self._call("dispositivo", "list_devices", **params)
        return res.get("devices", [])

    def list_olts(self) -> list[dict[str, Any]]:
        """Lista as OLTs cadastradas."""
        res = self._call("olt", "list_olts")
        return res.get("olts", res.get("data", []))

    def list_concentradoras(self) -> list[dict[str, Any]]:
        """Lista as concentradoras cadastradas no Ravicor."""
        res = self._call("concentradora", "list")
        return res.get("data", res.get("concentradoras", []))

    def get_device(self, device_id: int) -> dict[str, Any]:
        """Obtém os detalhes de um dispositivo específico."""
        return self._call("dispositivo", "get_device", id=device_id)

    def search_devices(self, termo: str, limite: int = 30) -> list[dict[str, Any]]:
        """Busca unificada por nome ou IP entre concentradoras, OLTs e dispositivos."""
        alvo = (termo or "").strip().lower()
        encontrados: list[dict[str, Any]] = []

        def _casa(item: dict[str, Any]) -> bool:
            if not alvo:
                return True
            texto = " ".join(
                str(item.get(k, "")) for k in ("name", "nome", "ip", "host", "modelo", "fabricante")
            ).lower()
            return alvo in texto

        for c in self.list_concentradoras():
            if isinstance(c, dict) and _casa(c):
                encontrados.append({
                    "tipo": "concentradora",
                    "id": c.get("id"),
                    "nome": c.get("nome") or c.get("name"),
                    "ip": c.get("ip"),
                    "status": c.get("status_descricao") or c.get("status"),
                    "usuarios_online": c.get("usuarios_online"),
                    "total_usuarios": c.get("total_usuarios"),
                    "ultima_sincronizacao": c.get("ultima_sincronizacao"),
                })

        for olt in self.list_olts():
            if isinstance(olt, dict) and _casa(olt):
                encontrados.append({
                    "tipo": "olt",
                    "id": olt.get("id"),
                    "nome": olt.get("nome") or olt.get("name"),
                    "ip": olt.get("ip"),
                    "fabricante": olt.get("fabricante") or olt.get("vendor"),
                    "status": olt.get("status"),
                })

        for g in self.list_device_groups():
            if not isinstance(g, dict):
                continue
            gid = g.get("id")
            gname = g.get("name") or ""
            for d in self.list_devices(group_id=gid):
                if isinstance(d, dict) and (_casa(d) or (alvo and alvo in gname.lower())):
                    encontrados.append({
                        "tipo": "dispositivo",
                        "id": d.get("id"),
                        "nome": d.get("name") or d.get("nome"),
                        "ip": d.get("ip"),
                        "grupo": gname,
                        "status": d.get("status"),
                    })
                if len(encontrados) >= limite:
                    return encontrados[:limite]
        return encontrados[:limite]
