"""
Cliente Somente Leitura (Read-Only) para a API Webservice v1 do IXC Provedor.

Diretrizes de Segurança e Arquitetura:
1. Operação estritamente de leitura: todas as chamadas HTTP usam o cabeçalho fixo
   ``ixcsoft: listar`` e apenas tabelas homologadas na allowlist podem ser consultadas.
   Não existem métodos de criação, edição ou exclusão (PUT, DELETE ou POST de escrita).
2. Credenciais via variáveis de ambiente (``IXC_BASE_URL``, ``IXC_USER_ID``, ``IXC_API_HASH``),
   codificadas em Base64 no formato ``ID:HASH`` para ``Authorization: Basic``.
3. Sanitização automática (Data Masking / LGPD): CPF/CNPJ, RG, senhas, dados bancários/boletos,
   valores financeiros, e-mails, telefones e endereços residenciais são removidos ou mascarados
   na própria camada do cliente antes de chegarem a logs, prompts de IA ou mensagens externas.
4. Timeout curto por padrão (8s) e exceções que nunca expõem URL ou credenciais.
"""
from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests
from dotenv import load_dotenv

RAIZ = Path(__file__).resolve().parent.parent
load_dotenv(RAIZ / ".env")

TABELAS_PERMITIDAS = frozenset({
    "radusuarios",
    "radpop_radio_cliente_fibra",
    "cliente_contrato",
    "cliente",
    "su_oss_chamado",
})

OPERADORES_PERMITIDOS = frozenset({"=", "!=", "like", ">", "<", ">=", "<=", "in"})

# Campos permitidos por tabela (Allowlist estrita: tudo fora disso é descartado)
_CAMPOS_PERMITIDOS: dict[str, frozenset[str]] = {
    "radusuarios": frozenset({
        "id", "ativo", "online", "login", "ip", "mac",
        "id_cliente", "id_contrato", "id_transmissor", "id_grupo",
        "ultima_conexao_inicial", "ultima_conexao_final",
        "motivo_desconexao", "sinal_ultimo_atendimento",
        "conexao", "porta_http",
    }),
    "radpop_radio_cliente_fibra": frozenset({
        "id", "id_login", "id_cliente", "id_contrato", "id_transmissor",
        "id_caixa_ftth", "porta_ftth", "nome", "mac", "serial", "onu_numero",
        "onu_tipo", "ponid", "slotno", "ponno", "tipo_autenticacao",
        "sinal_rx", "sinal_tx", "temperatura", "voltagem", "distancia_onu",
        "vlan", "vlan_pppoe", "bairro", "cidade",
        "data_sinal", "causa_ultima_queda",
    }),
    "cliente_contrato": frozenset({
        "id", "id_cliente", "id_vd_contrato", "contrato",
        "status", "status_internet", "status_velocidade",
        "situacao_financeira_contrato", "pago_ate_data",
        "data_ativacao", "data_cancelamento", "desbloqueio_confianca",
    }),
    "cliente": frozenset({
        "id", "ativo", "tipo_pessoa", "cidade", "bairro", "filial_id",
    }),
    "su_oss_chamado": frozenset({
        "id", "protocolo", "id_cliente", "id_contrato", "id_login",
        "id_assunto", "status", "setor", "id_tecnico", "prioridade",
        "data_abertura", "data_agenda", "data_fechamento",
        "titulo", "mensagem_resposta",
    }),
}

# Denylist de segurança adicional: qualquer chave que case com estes termos nunca passa
_CHAVE_SENSIVEL_RE = re.compile(
    r"(cpf|cnpj|rg|identidade|ie_|senha|pass|secret|token|hash|pix|boleto|cartao|"
    r"fatura|valor|preco|salario|email|e_mail|fone|telefone|celular|whatsapp|"
    r"endereco|logradouro|complemento|numero_end|cep|latitude|longitude|gps|nascimento)",
    re.IGNORECASE,
)

# Regex para mascarar dados pessoais que atendentes possam ter digitado no título de uma O.S.
_CPF_CNPJ_TEXTO_RE = re.compile(
    r"\b(?:\d{3}\.?\d{3}\.?\d{3}-?\d{2}|\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2})\b"
)
_EMAIL_TEXTO_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_TEL_TEXTO_RE = re.compile(r"(?<!\w)(?:\+?55\s*)?(?:\(?\d{2}\)?\s*)?\d{4,5}[-\s]\d{4}(?!\w)")

STATUS_CONTRATO = {
    "A": "Ativo",
    "I": "Inativo",
    "P": "Pré-contrato",
    "N": "Negativado",
    "D": "Desistiu",
}

STATUS_INTERNET = {
    "A": "Ativo (Liberado)",
    "CM": "Bloqueio Manual",
    "CA": "Bloqueio Automático (Financeiro)",
    "FA": "Financeiro em Atraso",
    "AA": "Aguardando Assinatura",
    "D": "Desativado",
}

STATUS_CHAMADO = {
    "A": "Aberto",
    "AN": "Em Análise",
    "EN": "Encaminhado",
    "AS": "Assumido",
    "AG": "Agendado",
    "DS": "Em Deslocamento",
    "EX": "Em Execução",
    "F": "Finalizado",
    "RAG": "Reagendar",
}


class IXCErro(RuntimeError):
    """Erro operacional ou de configuração no cliente IXC (sem expor segredos/URL)."""


# Formato típico do Zabbix: "Cliente: joao-silva -> Esta down : -80"
_LOGIN_ALERTA_RE = re.compile(r"cliente:\s*(\S+?)(?:\s*-?>|\s|$)", re.IGNORECASE)


def extrair_termo_busca(texto: str) -> str:
    """Extrai o login de um texto de alerta do Zabbix ou devolve o próprio termo limpo.

    Preserva logins com hífen (ex.: ``joao-silva``), cortando apenas no separador ``->``.
    """
    limpo = " ".join(str(texto or "").split())
    m = _LOGIN_ALERTA_RE.search(limpo)
    return m.group(1).strip() if m else limpo


def _mascarar_texto_livre(texto: str, limite: int = 160) -> str:
    """Remove CPF/CNPJ, e-mail e telefone de campos de texto livre (ex.: título de O.S.)."""
    limpo = " ".join(str(texto or "").split())
    limpo = _CPF_CNPJ_TEXTO_RE.sub("[DOC_REDACTED]", limpo)
    limpo = _EMAIL_TEXTO_RE.sub("[EMAIL_REDACTED]", limpo)
    limpo = _TEL_TEXTO_RE.sub("[TEL_REDACTED]", limpo)
    return limpo[:limite]


def sanitizar_registro(tabela: str, registro: dict[str, Any]) -> dict[str, Any]:
    """Filtra um registro bruto do IXC mantendo apenas campos operacionais seguros."""
    if not isinstance(registro, dict):
        return {}
    permitidos = _CAMPOS_PERMITIDOS.get(tabela, frozenset())
    limpo: dict[str, Any] = {}
    for chave, valor in registro.items():
        chave_norm = str(chave).strip()
        if chave_norm not in permitidos or _CHAVE_SENSIVEL_RE.search(chave_norm):
            continue
        if valor is None or str(valor).strip().startswith("0000-00-00"):
            limpo[chave_norm] = ""
        elif chave_norm in {"titulo", "mensagem_resposta", "motivo_desconexao", "causa_ultima_queda"}:
            limpo[chave_norm] = _mascarar_texto_livre(str(valor))
        else:
            limpo[chave_norm] = str(valor).strip()[:120]
    if tabela == "cliente" and "id" in limpo:
        limpo["identificador_exibicao"] = f"Cliente #{limpo['id']}"
    return limpo


def _normalizar_base_url(url_bruta: str) -> str:
    url = (url_bruta or "").strip().rstrip("/")
    if not url:
        raise IXCErro("IXC_BASE_URL ausente no .env")
    # Remove /adm.php ou similares caso o usuário tenha colado a URL do painel web
    url = re.sub(r"/adm\.php.*$", "", url, flags=re.IGNORECASE).rstrip("/")
    partes = urlsplit(url)
    if (partes.scheme not in {"http", "https"} or not partes.hostname
            or partes.username or partes.password or partes.query or partes.fragment):
        raise IXCErro("IXC_BASE_URL deve ser uma URL HTTP(S) válida, sem credenciais ou query.")
    if not url.endswith("/webservice/v1"):
        url = f"{url}/webservice/v1"
    return url


def _montar_basic_auth(user_id: str, api_hash: str) -> str:
    uid = (user_id or "").strip()
    token = (api_hash or "").strip()
    # No IXC, o botão "Copiar Token" já traz "ID:HASH". Se o usuário preencher
    # IXC_USER_ID e também colar "ID:HASH" em IXC_API_HASH, evitamos duplicar "ID:ID:HASH".
    if ":" in token:
        prefixo, _, resto = token.partition(":")
        prefixo, resto = prefixo.strip(), resto.strip()
        if not uid or uid == prefixo:
            uid = prefixo
            token = resto
    if not uid or not token:
        raise IXCErro("IXC_USER_ID e IXC_API_HASH devem estar definidos no .env")
    if ":" in uid or ":" in token or any(c.isspace() for c in uid) or any(c.isspace() for c in token):
        raise IXCErro("IXC_USER_ID e IXC_API_HASH contêm formato inválido.")
    credencial = f"{uid}:{token}".encode()
    return base64.b64encode(credencial).decode("ascii")


@dataclass
class DiagnosticoIXC:
    """Resultado consolidado e sanitizado do cruzamento de um login/cliente/ONU no IXC."""

    termo_buscado: str
    encontrado: bool = False
    status_operacional: str = "NAO_ENCONTRADO"
    resumo: str = ""
    logins: list[dict[str, Any]] = field(default_factory=list)
    fibra_onus: list[dict[str, Any]] = field(default_factory=list)
    contratos: list[dict[str, Any]] = field(default_factory=list)
    clientes: list[dict[str, Any]] = field(default_factory=list)
    chamados_abertos: list[dict[str, Any]] = field(default_factory=list)
    avisos: list[str] = field(default_factory=list)

    @property
    def bloqueio_administrativo(self) -> bool:
        return self.status_operacional == "BLOQUEIO_ADMINISTRATIVO"

    @property
    def tem_os_aberta(self) -> bool:
        return bool(self.chamados_abertos)

    def to_dict(self) -> dict[str, Any]:
        return {
            "termo_buscado": self.termo_buscado,
            "encontrado": self.encontrado,
            "status_operacional": self.status_operacional,
            "bloqueio_administrativo": self.bloqueio_administrativo,
            "tem_os_aberta": self.tem_os_aberta,
            "resumo": self.resumo,
            "logins": self.logins,
            "fibra_onus": self.fibra_onus,
            "contratos": self.contratos,
            "clientes": self.clientes,
            "chamados_abertos": self.chamados_abertos,
            "avisos": self.avisos,
        }


class IXCClient:
    """Cliente Webservice v1 do IXC Provedor (Somente Leitura)."""

    def __init__(
        self,
        base_url: str | None = None,
        user_id: str | None = None,
        api_hash: str | None = None,
        timeout: float | None = None,
    ):
        self.base_url = _normalizar_base_url(
            base_url if base_url is not None else os.getenv("IXC_BASE_URL", "")
        )
        uid = user_id if user_id is not None else os.getenv("IXC_USER_ID", "")
        uhash = api_hash if api_hash is not None else os.getenv("IXC_API_HASH", "")
        token_b64 = _montar_basic_auth(uid, uhash)

        try:
            self.timeout = float(
                timeout if timeout is not None else os.getenv("IXC_TIMEOUT_S", "8")
            )
        except (TypeError, ValueError) as exc:
            raise IXCErro("IXC_TIMEOUT_S deve ser um número positivo.") from exc
        if not 1 <= self.timeout <= 30:
            raise IXCErro("IXC_TIMEOUT_S deve estar entre 1 e 30 segundos.")

        # O cabeçalho "ixcsoft: listar" é imutável para garantir modo Somente Leitura
        self._headers = {
            "ixcsoft": "listar",
            "Authorization": f"Basic {token_b64}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        # Sessão HTTP reutilizada (keep-alive): reduz latência em lotes de consultas.
        self._session = requests.Session()

    def close(self) -> None:
        """Libera as conexões HTTP mantidas pela sessão."""
        self._session.close()

    def __enter__(self) -> IXCClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __repr__(self) -> str:  # nunca expõe o token em logs/tracebacks
        return f"IXCClient(base_url={self.base_url!r}, timeout={self.timeout:g})"

    def listar(
        self,
        tabela: str,
        campo: str,
        valor: str | int,
        oper: str = "=",
        rp: int = 20,
        page: int = 1,
        sortname: str | None = None,
        sortorder: str = "desc",
    ) -> list[dict[str, Any]]:
        """Executa uma consulta de leitura (``ixcsoft: listar``) e retorna registros sanitizados."""
        tabela_limpa = (tabela or "").strip().lower()
        if tabela_limpa not in TABELAS_PERMITIDAS:
            raise IXCErro(f"Tabela não autorizada para leitura no NOC: {tabela_limpa!r}")
        if oper not in OPERADORES_PERMITIDOS:
            raise IXCErro(f"Operador de busca inválido: {oper!r}")
        if not re.fullmatch(r"[a-z0-9_]+", (campo or "").strip().lower()):
            raise IXCErro(f"Campo de busca inválido: {campo!r}")
        if not 1 <= rp <= 200:
            raise IXCErro("rp deve estar entre 1 e 200.")

        qtype = f"{tabela_limpa}.{campo.strip().lower()}"
        ordem_campo = sortname or f"{tabela_limpa}.id"
        payload = {
            "qtype": qtype,
            "query": str(valor).strip(),
            "oper": oper,
            "page": str(max(1, page)),
            "rp": str(rp),
            "sortname": ordem_campo,
            "sortorder": "asc" if sortorder.lower() == "asc" else "desc",
        }

        url = f"{self.base_url}/{tabela_limpa}"
        headers = dict(self._headers)
        headers["ixcsoft"] = "listar"  # garantia dupla de leitura

        try:
            resp = self._session.post(
                url,
                headers=headers,
                data=json.dumps(payload),
                timeout=self.timeout,
            )
        except requests.Timeout:
            raise IXCErro(f"Timeout ({self.timeout:g}s) ao consultar {tabela_limpa} no IXC.") from None
        except requests.RequestException as exc:
            raise IXCErro(f"Falha de conexão com o IXC ({type(exc).__name__}).") from None

        if resp.status_code in {401, 403}:
            raise IXCErro(f"Autenticação/permissão recusada pelo IXC (HTTP {resp.status_code}).")
        if not resp.ok:
            raise IXCErro(f"IXC retornou HTTP {resp.status_code} ao consultar {tabela_limpa}.")

        try:
            dados = resp.json()
        except ValueError:
            raise IXCErro(f"Resposta do IXC em {tabela_limpa} não é um JSON válido.") from None

        if not isinstance(dados, dict):
            raise IXCErro(f"Formato inesperado na resposta de {tabela_limpa} do IXC.")

        if str(dados.get("type", "")).lower() == "error":
            msg = _mascarar_texto_livre(str(dados.get("message", "erro na consulta")))
            raise IXCErro(f"Erro reportado pelo IXC em {tabela_limpa}: {msg}")

        registros = dados.get("registros") or []
        if not isinstance(registros, list):
            return []
        return [sanitizar_registro(tabela_limpa, r) for r in registros if isinstance(r, dict)]

    # ------------------------------------------------------------------
    # Consultas especializadas do NOC
    # ------------------------------------------------------------------

    def buscar_logins(self, termo: str, rp: int = 10) -> list[dict[str, Any]]:
        """Busca em ``radusuarios`` por login exato, IP, MAC ou ID de cliente."""
        termo = termo.strip()
        if not termo:
            return []
        # 1. Tenta por login exato
        achados = self.listar("radusuarios", "login", termo, oper="=", rp=rp)
        if achados:
            return achados
        # 2. Se parecer MAC (AA:BB:CC... ou AABB.CCDD...)
        if re.fullmatch(r"[0-9A-Fa-f]{2}(?:[:\-][0-9A-Fa-f]{2}){5}", termo):
            achados = self.listar("radusuarios", "mac", termo, oper="=", rp=rp)
            if achados:
                return achados
        # 3. Se parecer IPv4
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", termo):
            achados = self.listar("radusuarios", "ip", termo, oper="=", rp=rp)
            if achados:
                return achados
        # 4. Busca parcial por login (like)
        return self.listar("radusuarios", "login", termo, oper="like", rp=rp)

    def buscar_fibra(
        self,
        *,
        id_login: str | None = None,
        id_contrato: str | None = None,
        login_nome: str | None = None,
        id_cliente: str | None = None,
        serial_ou_mac: str | None = None,
        rp: int = 10,
    ) -> list[dict[str, Any]]:
        """Busca dados ópticos sincronizados em ``radpop_radio_cliente_fibra``."""
        if id_login and id_login != "0":
            res = self.listar("radpop_radio_cliente_fibra", "id_login", id_login, oper="=", rp=rp)
            if res:
                return res
        if login_nome:
            res = self.listar("radpop_radio_cliente_fibra", "nome", login_nome, oper="=", rp=rp)
            if res:
                return res
        if id_contrato and id_contrato != "0":
            res = self.listar("radpop_radio_cliente_fibra", "id_contrato", id_contrato, oper="=", rp=rp)
            if res:
                return res
        if serial_ou_mac:
            for campo in ("mac", "nome", "onu_numero"):
                res = self.listar("radpop_radio_cliente_fibra", campo, serial_ou_mac, oper="=", rp=rp)
                if res:
                    return res
        if id_cliente and id_cliente != "0":
            return self.listar("radpop_radio_cliente_fibra", "id_cliente", id_cliente, oper="=", rp=rp)
        return []

    def buscar_contratos(
        self,
        *,
        id_contrato: str | None = None,
        id_cliente: str | None = None,
        rp: int = 10,
    ) -> list[dict[str, Any]]:
        """Busca status contratual e de bloqueio em ``cliente_contrato``."""
        if id_contrato and id_contrato != "0":
            res = self.listar("cliente_contrato", "id", id_contrato, oper="=", rp=1)
            if res:
                return res
        if id_cliente and id_cliente != "0":
            return self.listar("cliente_contrato", "id_cliente", id_cliente, oper="=", rp=rp)
        return []

    def buscar_cliente(self, id_cliente: str) -> dict[str, Any] | None:
        if not id_cliente or id_cliente == "0":
            return None
        res = self.listar("cliente", "id", id_cliente, oper="=", rp=1)
        return res[0] if res else None

    def buscar_chamados_abertos(
        self,
        *,
        id_cliente: str | None = None,
        id_login: str | None = None,
        rp: int = 20,
    ) -> list[dict[str, Any]]:
        """Retorna apenas O.S. não finalizadas (``status != 'F'``) do cliente/login."""
        registros: list[dict[str, Any]] = []
        if id_login and id_login != "0":
            registros = self.listar("su_oss_chamado", "id_login", id_login, oper="=", rp=rp)
        if not registros and id_cliente and id_cliente != "0":
            registros = self.listar("su_oss_chamado", "id_cliente", id_cliente, oper="=", rp=rp)
        return [r for r in registros if r.get("status", "").upper() not in {"F", ""}]

    def diagnosticar(self, termo: str) -> DiagnosticoIXC:
        """Executa o pipeline completo de correlação de um login/MAC/serial/ID no IXC."""
        # Se vier no formato do alerta do Zabbix ("Cliente: login -> Esta down : -80"), extrai o login
        termo_limpo = extrair_termo_busca(termo)

        diag = DiagnosticoIXC(termo_buscado=termo_limpo)
        if not termo_limpo:
            diag.resumo = "Termo de busca vazio."
            return diag

        # 1. Se o usuário passou "#1234", busca direto pelo ID do cliente
        if termo_limpo.startswith("#") and termo_limpo[1:].isdigit():
            cid = termo_limpo[1:]
            cli = self.buscar_cliente(cid)
            if cli:
                diag.clientes.append(cli)
            diag.logins = self.listar("radusuarios", "id_cliente", cid, oper="=", rp=10)
        else:
            diag.logins = self.buscar_logins(termo_limpo, rp=5)
            if not diag.logins:
                # Tenta achar pela ONU (serial/MAC) em radpop_radio_cliente_fibra
                fibra = self.buscar_fibra(serial_ou_mac=termo_limpo, rp=5)
                if fibra:
                    diag.fibra_onus.extend(fibra)
                    id_login = fibra[0].get("id_login", "")
                    if id_login and id_login != "0":
                        diag.logins = self.listar("radusuarios", "id", id_login, oper="=", rp=5)

        ids_clientes = {
            r.get("id_cliente", "")
            for r in (diag.logins + diag.fibra_onus)
            if r.get("id_cliente") and r.get("id_cliente") != "0"
        }
        ids_contratos = {
            r.get("id_contrato", "")
            for r in (diag.logins + diag.fibra_onus)
            if r.get("id_contrato") and r.get("id_contrato") != "0"
        }

        # 2. Busca fibra/ONU se ainda não buscou (tenta por id_login, login_nome e id_contrato)
        if not diag.fibra_onus:
            for lg in diag.logins[:3]:
                try:
                    achados_f = self.buscar_fibra(
                        id_login=lg.get("id"),
                        id_contrato=lg.get("id_contrato"),
                        login_nome=lg.get("login"),
                        rp=5,
                    )
                    for f in achados_f:
                        if not any(x.get("id") == f.get("id") for x in diag.fibra_onus):
                            diag.fibra_onus.append(f)
                except IXCErro as exc:
                    diag.avisos.append(str(exc))

        # 3. Busca contratos
        for ctid in sorted(ids_contratos)[:3]:
            try:
                diag.contratos.extend(self.buscar_contratos(id_contrato=ctid))
            except IXCErro as exc:
                diag.avisos.append(str(exc))
        if not diag.contratos:
            for cid in sorted(ids_clientes)[:2]:
                try:
                    diag.contratos.extend(self.buscar_contratos(id_cliente=cid, rp=5))
                except IXCErro as exc:
                    diag.avisos.append(str(exc))

        # 4. Busca dados básicos não-sensíveis do cliente (opcional) e O.S. abertas
        for cid in sorted(ids_clientes)[:2]:
            if not any(c.get("id") == cid for c in diag.clientes):
                try:
                    cli = self.buscar_cliente(cid)
                    if cli:
                        diag.clientes.append(cli)
                except IXCErro as exc:
                    # Se o grupo de API não tiver permissão na tabela 'cliente' (comum por LGPD),
                    # ignora silenciosamente pois contrato, login, fibra e O.S. já bastam.
                    if "permissão para acessar o recurso cliente" not in str(exc).lower():
                        diag.avisos.append(str(exc))
            try:
                diag.chamados_abertos.extend(self.buscar_chamados_abertos(id_cliente=cid))
            except IXCErro as exc:
                diag.avisos.append(str(exc))

        diag.encontrado = bool(diag.logins or diag.fibra_onus or diag.contratos or diag.clientes)
        diag.status_operacional, diag.resumo = _classificar_diagnostico(diag)
        return diag


def _contrato_bloqueado(ct: dict[str, Any]) -> bool:
    st_contrato = ct.get("status", "").upper()
    st_net = ct.get("status_internet", "").upper()
    st_vel = ct.get("status_velocidade", "").upper()
    return st_contrato in {"I", "N", "D"} or st_net in {"CA", "CM", "FA", "D", "AA"} or st_vel == "R"


def _classificar_diagnostico(diag: DiagnosticoIXC) -> tuple[str, str]:
    if not diag.encontrado:
        return "NAO_ENCONTRADO", f"Nenhum registro encontrado no IXC para '{diag.termo_buscado}'."

    # 1. Verifica bloqueio contratual / financeiro (Curto-circuito administrativo).
    # Prioriza o contrato vinculado ao login/ONU: contratos antigos/cancelados do mesmo
    # cliente não podem mascarar uma falha técnica real no contrato vigente.
    ids_vinculados = {
        r.get("id_contrato") for r in (diag.logins + diag.fibra_onus)
        if r.get("id_contrato") and r.get("id_contrato") != "0"
    }
    vinculados = [ct for ct in diag.contratos if ct.get("id") in ids_vinculados]
    candidatos = vinculados or diag.contratos
    bloqueados = [ct for ct in candidatos if _contrato_bloqueado(ct)]
    ha_contrato_ok = any(not _contrato_bloqueado(ct) for ct in candidatos)
    if bloqueados and (vinculados or not ha_contrato_ok):
        ct = bloqueados[0]
        st_contrato = ct.get("status", "").upper()
        st_net = ct.get("status_internet", "").upper()
        desc_net = STATUS_INTERNET.get(st_net, st_net or "Restrito")
        desc_ct = STATUS_CONTRATO.get(st_contrato, st_contrato or "?")
        return (
            "BLOQUEIO_ADMINISTRATIVO",
            f"Contrato #{ct.get('id', '?')} ({desc_ct}) com restrição administrativa: {desc_net}.",
        )

    # 2. Verifica se o login próprio está inativo
    for lg in diag.logins:
        if lg.get("ativo", "S").upper() == "N":
            return (
                "BLOQUEIO_ADMINISTRATIVO",
                f"Login '{lg.get('login', '?')}' está marcado como INATIVO no Radius.",
            )

    # 3. Verifica se há O.S. em aberto
    online = any(lg.get("online", "").upper() == "S" for lg in diag.logins)
    if diag.chamados_abertos and not online:
        ch = diag.chamados_abertos[0]
        st_ch = STATUS_CHAMADO.get(ch.get("status", "").upper(), ch.get("status", "Aberto"))
        return (
            "OS_EM_ANDAMENTO",
            f"Cliente offline com O.S. #{ch.get('id', '?')} em andamento ({st_ch}: {ch.get('titulo', 'sem título')}).",
        )

    # 4. Verifica status de conexão técnica
    if diag.logins and not online:
        lg = diag.logins[0]
        onu_info = ""
        if diag.fibra_onus:
            f = diag.fibra_onus[0]
            rx = f.get("sinal_rx") or "?"
            causa = f.get("causa_ultima_queda") or lg.get("motivo_desconexao") or "sem causa registrada"
            onu_info = f" | RX IXC: {rx} dBm | Última queda: {causa}"
        return (
            "FALHA_TECNICA_OFFLINE",
            f"Contrato ativo e liberado, mas login '{lg.get('login', '?')}' está OFFLINE{onu_info}.",
        )

    if online:
        lg = next(l for l in diag.logins if l.get("online", "").upper() == "S")
        rx_str = ""
        if diag.fibra_onus and diag.fibra_onus[0].get("sinal_rx"):
            rx_str = f" | RX: {diag.fibra_onus[0]['sinal_rx']} dBm"
        return (
            "ONLINE_NORMAL",
            f"Login '{lg.get('login', '?')}' ONLINE (IP {lg.get('ip', '?')}{rx_str}) e contrato liberado.",
        )

    return "CADASTRO_LOCALIZADO", f"Registro localizado para '{diag.termo_buscado}'."


def formatar_diagnostico_ixc(diag: DiagnosticoIXC) -> str:
    """Formata o diagnóstico sanitizado do IXC para exibição no terminal ou chat."""
    icone = {
        "BLOQUEIO_ADMINISTRATIVO": "💰",
        "OS_EM_ANDAMENTO": "🛠️",
        "FALHA_TECNICA_OFFLINE": "🔴",
        "ONLINE_NORMAL": "🟢",
        "CADASTRO_LOCALIZADO": "ℹ️",
        "NAO_ENCONTRADO": "⚪",
    }.get(diag.status_operacional, "ℹ️")

    linhas = [
        f"{icone} IXC [{diag.status_operacional}] — {diag.termo_buscado}",
        f"   Resumo: {diag.resumo}",
    ]
    for lg in diag.logins[:3]:
        estado_rad = "ONLINE" if lg.get("online", "").upper() == "S" else "OFFLINE"
        linhas.append(
            f"   • Radius: login={lg.get('login', '?')} | {estado_rad} | "
            f"IP={lg.get('ip') or '-'} | MAC={lg.get('mac') or '-'} | "
            f"últ. queda={lg.get('ultima_conexao_final') or '-'}"
        )
    for f in diag.fibra_onus[:3]:
        pon_str = f.get("ponid") or f"{f.get('slotno') or '?'}/{f.get('ponno') or '?'}"
        linhas.append(
            f"   • Fibra/ONU: serial/mac={f.get('serial') or f.get('mac') or '?'} | "
            f"PON={pon_str} | "
            f"RX={f.get('sinal_rx') or '?'} dBm | TX={f.get('sinal_tx') or '?'} dBm | "
            f"causa={f.get('causa_ultima_queda') or '-'}"
        )
    for ct in diag.contratos[:3]:
        st_ct = STATUS_CONTRATO.get(ct.get("status", "").upper(), ct.get("status", "?"))
        st_net = STATUS_INTERNET.get(ct.get("status_internet", "").upper(), ct.get("status_internet", "?"))
        linhas.append(
            f"   • Contrato #{ct.get('id', '?')}: status={st_ct} | acesso={st_net} | "
            f"plano={ct.get('contrato') or '-'}"
        )
    for cli in diag.clientes[:2]:
        bairro = cli.get("bairro") or "-"
        linhas.append(
            f"   • Localidade ({cli.get('identificador_exibicao', 'Cliente')}): "
            f"bairro={bairro} | ativo={cli.get('ativo') or '?'}"
        )
    for ch in diag.chamados_abertos[:3]:
        st_ch = STATUS_CHAMADO.get(ch.get("status", "").upper(), ch.get("status", "?"))
        linhas.append(
            f"   • O.S. Aberta #{ch.get('id', '?')} ({st_ch} desde {ch.get('data_abertura') or '?'}): "
            f"{ch.get('titulo') or 'sem descrição'}"
        )
    for av in diag.avisos:
        linhas.append(f"   ⚠️ {av}")
    return "\n".join(linhas)
