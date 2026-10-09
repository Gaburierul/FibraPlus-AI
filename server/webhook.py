"""
Servidor que recebe alertas do Ravi e do Zabbix, analisa cada origem em lotes separados e envia ao mensageiro.

Fluxo:
    Ravi --POST /ravi/webhook--> fila Ravi --+
                                            +--> correlator --> Gemini --> mensageiro
    Zabbix --POST /zabbix/webhook--> fila Zabbix --+

Executar (na pasta do projeto):
    uvicorn server.webhook:app --host 127.0.0.1 --port 8089

Variáveis de ambiente (.env) — ver README, seção "Webhook":
    RAVI_WEBHOOK_TOKEN     segredo Ravi; query string permanece aceita quando necessário
    ZABBIX_WEBHOOK_TOKEN   segredo Zabbix; enviado no cabeçalho X-Webhook-Token
    WEBHOOK_TOKEN          fallback legado enquanto as origens migram para segredos distintos
    NOC_WEBHOOK_MAX_BODY_BYTES limite de corpo JSON (padrão 1 MiB)
    MODO_TESTE             "true" (padrão) só registra; "false" envia ao mensageiro configurado
    DEBOUNCE_SILENCIO_S    segundos sem alerta novo para fechar o lote (padrão 45)
    DEBOUNCE_MAX_S         tempo máximo de um lote (padrão 180)
    NOC_SEVERIDADE_MINIMA  0..5; descarta alertas abaixo disso (padrão: não filtra)
    NOC_USAR_IA            "false" para usar só o resumo determinístico (padrão true)
    NOC_AI_IN_TEST_MODE    "true" para chamar Gemini em modo de teste (padrão false)
    NOC_AI_AUTO_SEND       "true" para incluir hipótese da IA em envios reais (padrão false)
    + GEMINI_API_KEY / NOC_AI_MODEL e EVOLUTION_* (ver clients/whatsapp.py)
"""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

RAIZ = Path(__file__).resolve().parent.parent
load_dotenv(RAIZ / ".env")

from noc.analyzer import analisar  # noqa: E402  (precisa do .env carregado)
from noc.correlator import correlacionar  # noqa: E402
from noc.debounce import AgrupadorAlertas  # noqa: E402
from noc.parser import Alerta  # noqa: E402
from noc.zabbix_event import (PayloadInvalido, chave_evento, eh_atualizacao,  # noqa: E402
                              payload_para_alerta, severidade_minima_ok)

PASTA_LOGS = RAIZ / "logs"
PASTA_LOGS.mkdir(exist_ok=True)

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[logging.StreamHandler(),
              RotatingFileHandler(PASTA_LOGS / "webhook.log", maxBytes=5_000_000,
                                  backupCount=5, encoding="utf-8")],
)
log = logging.getLogger("noc.webhook")


class _RedigirTokenQuery(logging.Filter):
    """Evita registrar em claro o token do Ravi enviado como query string."""
    def filter(self, record: logging.LogRecord) -> bool:
        if record.name == "uvicorn.access" and isinstance(record.args, tuple) and len(record.args) >= 3:
            argumentos = list(record.args)
            argumentos[2] = re.sub(
                r"([?&]token=)[^&\s]+", r"\1[REDACTED]", str(argumentos[2]), flags=re.IGNORECASE
            )
            record.args = tuple(argumentos)
        return True


logging.getLogger("uvicorn.access").addFilter(_RedigirTokenQuery())


def _bool_env(nome: str, padrao: bool) -> bool:
    valor = os.getenv(nome)
    if valor is None or not valor.strip():
        return padrao
    valor = valor.strip().lower()
    if valor in {"1", "true", "sim", "yes"}:
        return True
    if valor in {"0", "false", "não", "nao", "no"}:
        return False
    raise RuntimeError(f"{nome} inválido; use true ou false.")


def _float_env(nome: str, padrao: float, minimo: float, maximo: float) -> float:
    bruto = os.getenv(nome)
    if bruto is None or not bruto.strip():
        return padrao
    try:
        valor = float(bruto)
    except ValueError as exc:
        raise RuntimeError(f"{nome} deve ser numérico.") from exc
    if not minimo <= valor <= maximo:
        raise RuntimeError(f"{nome} deve estar entre {minimo:g} e {maximo:g}.")
    return valor


def _int_env(nome: str, padrao: int, minimo: int, maximo: int) -> int:
    bruto = os.getenv(nome)
    if bruto is None or not bruto.strip():
        return padrao
    try:
        valor = int(bruto)
    except ValueError as exc:
        raise RuntimeError(f"{nome} deve ser um inteiro.") from exc
    if not minimo <= valor <= maximo:
        raise RuntimeError(f"{nome} deve estar entre {minimo} e {maximo}.")
    return valor


TOKEN_LEGADO = os.getenv("WEBHOOK_TOKEN", "").strip()
RAVI_WEBHOOK_TOKENS = tuple(dict.fromkeys(
    token for token in (os.getenv("RAVI_WEBHOOK_TOKEN", "").strip(), TOKEN_LEGADO) if token
))
ZABBIX_WEBHOOK_TOKENS = tuple(dict.fromkeys(
    token for token in (os.getenv("ZABBIX_WEBHOOK_TOKEN", "").strip(), TOKEN_LEGADO) if token
))
MAX_WEBHOOK_BODY_BYTES = _int_env("NOC_WEBHOOK_MAX_BODY_BYTES", 1_048_576, 1_024, 10_485_760)
MODO_TESTE = _bool_env("MODO_TESTE", True)
USAR_IA = _bool_env("NOC_USAR_IA", True)
IA_AUTO_ENVIO = _bool_env("NOC_AI_AUTO_SEND", False)
IA_NO_TESTE = _bool_env("NOC_AI_IN_TEST_MODE", False)
MENSAGEIRO = os.getenv("NOC_MENSAGEIRO", "telegram").strip().lower()
SILENCIO_S = _float_env("DEBOUNCE_SILENCIO_S", 45, 1, 3600)
ESPERA_MAX_S = _float_env("DEBOUNCE_MAX_S", 180, 1, 3600)
_sev = os.getenv("NOC_SEVERIDADE_MINIMA", "").strip()
if _sev and (not _sev.isdigit() or not 0 <= int(_sev) <= 5):
    raise RuntimeError("NOC_SEVERIDADE_MINIMA deve ser um inteiro de 0 a 5.")
SEVERIDADE_MINIMA = int(_sev) if _sev else None

if not RAVI_WEBHOOK_TOKENS or not ZABBIX_WEBHOOK_TOKENS:
    raise RuntimeError(
        "Defina RAVI_WEBHOOK_TOKEN e ZABBIX_WEBHOOK_TOKEN no .env; "
        "WEBHOOK_TOKEN permanece disponível como fallback temporário."
    )
if not MODO_TESTE:
    if MENSAGEIRO not in {"telegram", "evolution"}:
        raise RuntimeError("NOC_MENSAGEIRO deve ser telegram ou evolution.")
    if MENSAGEIRO == "telegram":
        from clients.telegram import TelegramClient
        TelegramClient()  # valida token e timeout sem abrir conexão
        if not os.getenv("TELEGRAM_CHAT_ID", "").strip():
            raise RuntimeError("TELEGRAM_CHAT_ID ausente no .env.")
    else:
        from clients.whatsapp import EvolutionClient
        EvolutionClient()  # valida URL, instância, chave e timeout sem abrir conexão
        if not os.getenv("EVOLUTION_GROUP_JID", "").strip():
            raise RuntimeError("EVOLUTION_GROUP_JID ausente no .env.")


def _registrar_envio(registro: dict[str, Any]) -> None:
    with open(PASTA_LOGS / "envios.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(registro, ensure_ascii=False, default=str) + "\n")


def _processar_lote_sincrono(alertas: list[Alerta]) -> None:
    """Roda em thread separada: correlator e Gemini fazem I/O bloqueante."""
    correlacao = correlacionar(alertas, janela_min=10)
    registro: dict[str, Any] = {
        "quando": datetime.now().isoformat(timespec="seconds"),
        "alertas": len(alertas),
        "incidentes": len(correlacao.incidentes),
        "clientes_filtrados": correlacao.clientes_filtrados,
        "modo_teste": MODO_TESTE,
        "origens": sorted({a.origem.strip().upper() for a in alertas if a.origem.strip()}),
    }
    if not correlacao.incidentes:
        log.info("Lote sem infraestrutura | origens=%s | alertas de clientes=%d; nada a enviar",
                 "/".join(registro["origens"]) or "desconhecida", correlacao.clientes_filtrados)
        registro["acao"] = "ignorado_sem_infra"
        _registrar_envio(registro)
        return

    usar_ia_no_lote = USAR_IA and ((MODO_TESTE and IA_NO_TESTE) or (not MODO_TESTE and IA_AUTO_ENVIO))
    resultado = analisar(correlacao, usar_ia=usar_ia_no_lote)
    registro.update(origem=resultado.origem, erros=resultado.erros, tokens=resultado.tokens,
                    caracteres_mensagem=len(resultado.mensagem))
    if MODO_TESTE and USAR_IA and not IA_NO_TESTE:
        registro["ia_no_teste"] = "desativada; habilite NOC_AI_IN_TEST_MODE=true para permitir chamadas Gemini"
        log.info("Modo de teste sem chamada Gemini; defina NOC_AI_IN_TEST_MODE=true para habilitar")
    if USAR_IA and not MODO_TESTE and not IA_AUTO_ENVIO:
        registro["ia_auto_envio"] = "desativada; resumo determinístico enviado"
        log.info("Hipótese da IA não incluída no envio real; use NOC_AI_AUTO_SEND=true após validar o fluxo")
    for erro in resultado.erros:
        log.warning("Análise: %s", erro)

    if MODO_TESTE:
        log.info("MODO_TESTE — mensagem NÃO enviada (%s, %d caracteres)",
                 resultado.origem, len(resultado.mensagem))
        registro["acao"] = "teste"
    else:
        try:
            if MENSAGEIRO == "evolution":
                from clients.whatsapp import EvolutionClient
                destino = os.getenv("EVOLUTION_GROUP_JID", "")
                if not destino:
                    raise RuntimeError("EVOLUTION_GROUP_JID ausente no .env")
                EvolutionClient().enviar_texto(destino, resultado.mensagem)
            else:
                from clients.telegram import TelegramClient
                destino = os.getenv("TELEGRAM_CHAT_ID", "")
                if not destino:
                    raise RuntimeError("TELEGRAM_CHAT_ID ausente no .env")
                TelegramClient().enviar_texto(destino, resultado.mensagem)
                
            registro["acao"] = f"enviado_{MENSAGEIRO}"
            log.info("Mensagem enviada via %s ao grupo (%s, %d caracteres)", MENSAGEIRO, resultado.origem, len(resultado.mensagem))
        except Exception as exc:  # noqa: BLE001
            registro["acao"] = "falha_envio"
            registro["erro_envio"] = type(exc).__name__
            log.error("Falha ao enviar notificação (%s)", type(exc).__name__)
    _registrar_envio(registro)


async def _processar_lote(alertas: list[Alerta]) -> None:
    await asyncio.to_thread(_processar_lote_sincrono, alertas)


AGRUPADORES = {
    "RAVI": AgrupadorAlertas(_processar_lote, silencio_s=SILENCIO_S,
                             espera_max_s=ESPERA_MAX_S, nome="RAVI"),
    "ZABBIX": AgrupadorAlertas(_processar_lote, silencio_s=SILENCIO_S,
                               espera_max_s=ESPERA_MAX_S, nome="ZABBIX"),
}


@asynccontextmanager
async def _ciclo_de_vida(_: FastAPI):
    log.info("Webhook iniciado | modo_teste=%s | ia=%s | ia_no_teste=%s | ia_auto_envio=%s | "
             "silêncio=%ss | máx=%ss | sev_min=%s",
             MODO_TESTE, USAR_IA, IA_NO_TESTE, IA_AUTO_ENVIO,
             SILENCIO_S, ESPERA_MAX_S, SEVERIDADE_MINIMA)
    yield
    for origem, agrupador in AGRUPADORES.items():
        log.info("Encerrando: processando lote pendente | origem=%s | %d alerta(s)",
                 origem, agrupador.pendentes)
        await agrupador.descarregar()


app = FastAPI(
    title="FibraPlus NOC IA",
    lifespan=_ciclo_de_vida,
    docs_url="/docs" if MODO_TESTE else None,
    redoc_url="/redoc" if MODO_TESTE else None,
    openapi_url="/openapi.json" if MODO_TESTE else None,
)


@app.get("/health")
async def health() -> dict[str, Any]:
    # O poller só precisa deste estado para bloquear envio real acidental.
    return {"status": "ok", "modo_teste": MODO_TESTE}


async def _ler_payload_json(request: Request) -> dict[str, Any]:
    tamanho = request.headers.get("content-length", "").strip()
    if tamanho:
        try:
            tamanho_declarado = int(tamanho)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Content-Length inválido") from exc
        if tamanho_declarado < 0:
            raise HTTPException(status_code=400, detail="Content-Length inválido")
        if tamanho_declarado > MAX_WEBHOOK_BODY_BYTES:
            raise HTTPException(status_code=413, detail="corpo excede o limite configurado")

    corpo = bytearray()
    async for bloco in request.stream():
        if len(corpo) + len(bloco) > MAX_WEBHOOK_BODY_BYTES:
            raise HTTPException(status_code=413, detail="corpo excede o limite configurado")
        corpo.extend(bloco)
    try:
        payload = json.loads(corpo)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="corpo não é JSON UTF-8 válido") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="JSON deve ser um objeto")
    return payload


def _token_valido_para_origem(token: str, permitidos: tuple[str, ...]) -> bool:
    candidato = token.encode("utf-8")
    valido = False
    for esperado in permitidos:
        valido = hmac.compare_digest(candidato, esperado.encode("utf-8")) or valido
    return valido


@app.post("/ravi/webhook", status_code=202)
async def receber_ravi(request: Request, token: str = "", x_webhook_token: str = Header(default="")) -> JSONResponse:
    provided_token = token or x_webhook_token
    if not _token_valido_para_origem(provided_token, RAVI_WEBHOOK_TOKENS):
        raise HTTPException(status_code=401, detail="token inválido")
    payload = await _ler_payload_json(request)

    try:
        from noc.ravi_event import (chave_evento_ravi, payload_para_alerta_ravi,
                                    PayloadRaviIgnorado, PayloadRaviInvalido)
        alerta = payload_para_alerta_ravi(payload)
        agrupador = AGRUPADORES["RAVI"]
        novo = await agrupador.adicionar(alerta, chave=chave_evento_ravi(payload))
        log.info("%s | origem=RAVI | estado=%s | severidade=%s | no_lote=%d",
                 "Recebido" if novo else "Duplicado", alerta.status,
                 alerta.nivel, agrupador.pendentes)
        if not novo:
            return JSONResponse({"status": "duplicado", "alertas_no_lote": agrupador.pendentes}, status_code=202)
        return JSONResponse({"status": "na_fila_ravi", "alertas_no_lote": agrupador.pendentes}, status_code=202)
    except PayloadRaviIgnorado as exc:
        return JSONResponse({"status": "ignorado", "motivo": str(exc)}, status_code=202)
    except PayloadRaviInvalido as exc:
        log.warning("Payload Ravi ignorado/inválido: %s", exc)
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        log.error("Falha inesperada no parser do Ravi (%s)", type(exc).__name__)
        return JSONResponse({"status": "erro_interno"}, status_code=500)

@app.post("/zabbix/webhook", status_code=202)
async def receber(request: Request, x_webhook_token: str = Header(default="")) -> JSONResponse:
    if not _token_valido_para_origem(x_webhook_token, ZABBIX_WEBHOOK_TOKENS):
        raise HTTPException(status_code=401, detail="token inválido")
    payload = await _ler_payload_json(request)

    if eh_atualizacao(payload):
        return JSONResponse({"status": "ignorado", "motivo": "evento de atualização"}, status_code=202)
    try:
        alerta = payload_para_alerta(payload)
    except PayloadInvalido as exc:
        log.warning("Payload inválido: %s", exc)
        raise HTTPException(status_code=422, detail=str(exc))

    if not severidade_minima_ok(alerta, SEVERIDADE_MINIMA):
        return JSONResponse({"status": "ignorado", "motivo": "abaixo da severidade mínima"}, status_code=202)

    agrupador = AGRUPADORES["ZABBIX"]
    novo = await agrupador.adicionar(alerta, chave=chave_evento(payload))
    log.info("%s | origem=ZABBIX | estado=%s | severidade=%s | no_lote=%d",
             "Recebido" if novo else "Duplicado", alerta.status,
             alerta.nivel, agrupador.pendentes)
    return JSONResponse({"status": "na_fila" if novo else "duplicado",
                         "alertas_no_lote": agrupador.pendentes}, status_code=202)
