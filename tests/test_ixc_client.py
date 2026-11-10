import base64
import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from clients.ixc import (
    IXCClient,
    IXCErro,
    formatar_diagnostico_ixc,
    sanitizar_registro,
)
from noc.enrich import cruzar_com_ixc


def test_autenticacao_base64_e_cabecalho_somente_leitura():
    cliente = IXCClient(
        base_url="https://ixc.example.com.br/",
        user_id="42",
        api_hash="token_secreto_123",
        timeout=5,
    )
    assert cliente.base_url == "https://ixc.example.com.br/webservice/v1"
    esperado_b64 = base64.b64encode(b"42:token_secreto_123").decode("ascii")
    assert cliente._headers["Authorization"] == f"Basic {esperado_b64}"
    assert cliente._headers["ixcsoft"] == "listar"


def test_bloqueia_tabela_ou_operador_nao_autorizado():
    cliente = IXCClient(
        base_url="https://ixc.example.com.br/webservice/v1",
        user_id="10",
        api_hash="hash_teste",
    )
    with pytest.raises(IXCErro, match="Tabela não autorizada"):
        cliente.listar("fn_areceber", "id", "1")

    with pytest.raises(IXCErro, match="Operador de busca inválido"):
        cliente.listar("radusuarios", "login", "teste", oper="DROP")


def test_sanitizacao_remove_cpf_senha_endereco_e_mascara_texto_livre():
    bruto_cliente = {
        "id": "501",
        "razao": "JOAO DA SILVA",
        "cnpj_cpf": "123.456.789-00",
        "ie_identidade": "1234567",
        "endereco": "Rua das Flores, 100",
        "cep": "79000-000",
        "telefone_celular": "(67) 99999-8888",
        "email": "joao@example.com",
        "bairro": "Centro",
        "cidade": "Campo Grande",
        "ativo": "S",
    }
    limpo_cli = sanitizar_registro("cliente", bruto_cliente)
    assert "cnpj_cpf" not in limpo_cli
    assert "razao" not in limpo_cli
    assert "endereco" not in limpo_cli
    assert "telefone_celular" not in limpo_cli
    assert "email" not in limpo_cli
    assert limpo_cli["bairro"] == "Centro"
    assert limpo_cli["identificador_exibicao"] == "Cliente #501"

    bruto_rad = {
        "id": "99",
        "login": "cliente_fibra01",
        "senha": "senha_super_secreta",
        "senha_md5": "abc12345",
        "online": "N",
        "ativo": "S",
        "ip": "192.0.2.50",
        "mac": "AA:BB:CC:DD:EE:FF",
        "id_cliente": "501",
        "id_contrato": "701",
    }
    limpo_rad = sanitizar_registro("radusuarios", bruto_rad)
    assert "senha" not in limpo_rad
    assert "senha_md5" not in limpo_rad
    assert limpo_rad["login"] == "cliente_fibra01"

    bruto_os = {
        "id": "8800",
        "status": "EN",
        "titulo": "Cliente CPF 123.456.789-00 sem sinal tel (67) 99888-7766 email a@b.com",
    }
    limpo_os = sanitizar_registro("su_oss_chamado", bruto_os)
    assert "123.456.789-00" not in limpo_os["titulo"]
    assert "99888-7766" not in limpo_os["titulo"]
    assert "a@b.com" not in limpo_os["titulo"]
    assert "[DOC_REDACTED]" in limpo_os["titulo"]
    assert "[TEL_REDACTED]" in limpo_os["titulo"]
    assert "[EMAIL_REDACTED]" in limpo_os["titulo"]


def test_pipeline_identifica_bloqueio_administrativo_e_os_aberta():
    cliente = IXCClient(
        base_url="https://ixc.example.com.br",
        user_id="42",
        api_hash="hash_ok",
    )

    def falso_post(url, headers, data, timeout):
        assert headers["ixcsoft"] == "listar"
        payload = json.loads(data)
        assert "qtype" in payload
        resp = MagicMock()
        resp.ok = True
        resp.status_code = 200
        if url.endswith("/radusuarios"):
            resp.json.return_value = {
                "registros": [{
                    "id": "10",
                    "login": "empresa_bloq",
                    "online": "N",
                    "ativo": "S",
                    "id_cliente": "200",
                    "id_contrato": "300",
                }]
            }
        elif url.endswith("/radpop_radio_cliente_fibra"):
            resp.json.return_value = {
                "registros": [{
                    "id": "1",
                    "id_login": "10",
                    "serial": "ZTEG12345678",
                    "sinal_rx": "-19.5",
                }]
            }
        elif url.endswith("/cliente_contrato"):
            resp.json.return_value = {
                "registros": [{
                    "id": "300",
                    "id_cliente": "200",
                    "status": "A",
                    "status_internet": "CA",  # Bloqueio Automático (Financeiro)
                    "contrato": "PLANO 500M",
                }]
            }
        elif url.endswith("/cliente"):
            resp.json.return_value = {"registros": [{"id": "200", "bairro": "Centro", "ativo": "S"}]}
        else:
            resp.json.return_value = {"registros": []}
        return resp

    with patch("clients.ixc.requests.Session.post", side_effect=falso_post):
        diag = cliente.diagnosticar("Cliente: empresa_bloq -> Esta down : -80")
        assert diag.termo_buscado == "empresa_bloq"
        assert diag.bloqueio_administrativo is True
        assert diag.status_operacional == "BLOQUEIO_ADMINISTRATIVO"
        texto = formatar_diagnostico_ixc(diag)
        assert "Bloqueio Automático (Financeiro)" in texto


def test_tolerancia_a_falhas_quando_ixc_da_timeout():
    cliente = IXCClient(
        base_url="https://ixc.example.com.br",
        user_id="42",
        api_hash="hash_ok",
        timeout=2,
    )
    with patch("clients.ixc.requests.Session.post", side_effect=requests.Timeout("demorou")):
        diagnosticos, avisos = cruzar_com_ixc(["cliente_teste"], ixc_client=cliente)
        assert diagnosticos == []
        assert len(avisos) == 1
        assert "Timeout" in avisos[0]


def test_token_ja_no_formato_id_hash_nao_duplica_id():
    cliente = IXCClient(
        base_url="https://ixc.example.com.br/adm.php",
        user_id="42",
        api_hash="42:abcdef0123",
    )
    assert cliente.base_url == "https://ixc.example.com.br/webservice/v1"
    esperado_b64 = base64.b64encode(b"42:abcdef0123").decode("ascii")
    assert cliente._headers["Authorization"] == f"Basic {esperado_b64}"
    assert "abcdef0123" not in repr(cliente)


def test_extrai_login_com_hifen_do_alerta_zabbix():
    from clients.ixc import extrair_termo_busca

    assert extrair_termo_busca("Cliente: joao-silva -> Esta down : -80") == "joao-silva"
    assert extrair_termo_busca("Cliente: maria->Esta down") == "maria"
    assert extrair_termo_busca("  ZTEG12345678 ") == "ZTEG12345678"


def test_contrato_antigo_cancelado_nao_mascara_falha_tecnica():
    from clients.ixc import DiagnosticoIXC, _classificar_diagnostico

    diag = DiagnosticoIXC(
        termo_buscado="cliente_x",
        encontrado=True,
        logins=[{"id": "1", "login": "cliente_x", "online": "N", "ativo": "S",
                 "id_cliente": "9", "id_contrato": ""}],
        contratos=[
            {"id": "100", "status": "I", "status_internet": "D"},  # contrato antigo
            {"id": "200", "status": "A", "status_internet": "A"},  # contrato vigente
        ],
    )
    status, _ = _classificar_diagnostico(diag)
    assert status == "FALHA_TECNICA_OFFLINE"

    diag.logins[0]["id_contrato"] = "100"
    status, _ = _classificar_diagnostico(diag)
    assert status == "BLOQUEIO_ADMINISTRATIVO"
