"""
Painel Web Local de Investigação de Incidentes — FibraPlus NOC.

Roda em processo e porta separados (padrão 127.0.0.1:8090) do servidor de
webhook (porta 8089 / Ngrok), garantindo que a interface de consulta fique
estritamente acessível localmente sem exposição à internet.

Execução:
    uvicorn server.painel:app --host 127.0.0.1 --port 8090
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

RAIZ = Path(__file__).resolve().parent.parent
if str(RAIZ) not in sys.path:
    sys.path.insert(0, str(RAIZ))

load_dotenv(RAIZ / ".env")

from noc.agente_investigacao import (  # noqa: E402
    MODELOS_DISPONIVEIS,
    MODELO_CHAT_PADRAO,
    investigar_streaming,
    resolver_modelo,
)
from noc.chat_store import ChatStore  # noqa: E402
from noc.custos import calcular_custo_tokens, resumo_consumo  # noqa: E402
from noc.ferramentas_noc import executar_ferramenta  # noqa: E402

PASTA_ESTATICOS = Path(__file__).resolve().parent / "static" / "painel"
store = ChatStore()

app = FastAPI(
    title="FibraPlus NOC — Painel de Investigação",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

if PASTA_ESTATICOS.exists():
    app.mount("/static", StaticFiles(directory=str(PASTA_ESTATICOS)), name="static")


# ---------------------------------------------------------------------------
# Schemas de requisição
# ---------------------------------------------------------------------------

class NovaConversaReq(BaseModel):
    titulo: str = Field(default="Nova verificação", max_length=100)
    modelo: str = Field(default=MODELO_CHAT_PADRAO, max_length=60)


class AtualizarConversaReq(BaseModel):
    titulo: str | None = Field(default=None, max_length=100)
    modelo: str | None = Field(default=None, max_length=60)


class NovaMensagemReq(BaseModel):
    conteudo: str = Field(..., min_length=1, max_length=32000)
    modelo: str | None = Field(default=None, max_length=60)


# ---------------------------------------------------------------------------
# Páginas e metadados
# ---------------------------------------------------------------------------

@app.get("/")
async def pagina_inicial():
    index_path = PASTA_ESTATICOS / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Interface do painel não encontrada.")
    return FileResponse(index_path)


@app.get("/api/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "servico": "painel_noc_local"}


@app.get("/api/config")
async def obter_config() -> dict[str, Any]:
    modelo_padrao, _ = resolver_modelo(MODELO_CHAT_PADRAO)
    return {
        "modelo_padrao": modelo_padrao,
        "modelos": list(MODELOS_DISPONIVEIS.values()),
        "integracoes": {
            "zabbix": bool(os.getenv("ZABBIX_URL") and os.getenv("ZABBIX_TOKEN")),
            "ixc": bool(os.getenv("IXC_BASE_URL") and os.getenv("IXC_API_HASH")),
            "ravicor": bool(os.getenv("RAVICOR_URL") and os.getenv("RAVICOR_TOKEN")),
            "gemini": bool(os.getenv("GEMINI_CHAT_API_KEY") or os.getenv("GEMINI_API_KEY")),
        },
    }


# ---------------------------------------------------------------------------
# Conversas (SQLite local)
# ---------------------------------------------------------------------------

@app.get("/api/conversas")
async def listar_conversas(busca: str = Query(default="", max_length=120)) -> dict[str, Any]:
    return {"conversas": store.listar_conversas(busca=busca)}


@app.post("/api/conversas", status_code=201)
async def criar_conversa(req: NovaConversaReq) -> dict[str, Any]:
    model_id, _ = resolver_modelo(req.modelo)
    return store.criar_conversa(titulo=req.titulo, modelo=model_id)


@app.get("/api/conversas/{conversa_id}")
async def obter_conversa(conversa_id: str) -> dict[str, Any]:
    conv = store.obter_conversa(conversa_id)
    if conv is None:
        raise HTTPException(status_code=404, detail="Conversa não encontrada.")
    for msg in conv.get("mensagens") or []:
        if msg.get("papel") == "assistant" and msg.get("tokens"):
            msg["custo_estimado"] = calcular_custo_tokens(msg.get("modelo", ""), msg["tokens"])
    return conv


@app.patch("/api/conversas/{conversa_id}")
async def atualizar_conversa(conversa_id: str, req: AtualizarConversaReq) -> dict[str, Any]:
    modelo_validado = resolver_modelo(req.modelo)[0] if req.modelo else None
    atualizou = store.atualizar_conversa(conversa_id, titulo=req.titulo, modelo=modelo_validado)
    if not atualizou:
        raise HTTPException(status_code=404, detail="Conversa não encontrada.")
    conv = store.obter_conversa(conversa_id)
    return conv or {"id": conversa_id}


@app.delete("/api/conversas/{conversa_id}")
async def excluir_conversa(conversa_id: str) -> dict[str, Any]:
    if not store.excluir_conversa(conversa_id):
        raise HTTPException(status_code=404, detail="Conversa não encontrada.")
    return {"ok": True, "id": conversa_id}


# ---------------------------------------------------------------------------
# Chat Investigativo com Streaming SSE (Hydrogen / Neon)
# ---------------------------------------------------------------------------

def _gerar_titulo_automatico(texto: str) -> str:
    limpo = " ".join(texto.split()).strip(" .?!;:")
    if len(limpo) <= 58:
        return limpo or "Verificação NOC"
    corte = limpo[:58].rsplit(" ", 1)[0]
    return (corte or limpo[:58]) + "…"


@app.post("/api/conversas/{conversa_id}/mensagens")
async def enviar_mensagem_chat(conversa_id: str, req: NovaMensagemReq):
    conv = store.obter_conversa(conversa_id)
    if conv is None:
        raise HTTPException(status_code=404, detail="Conversa não encontrada.")

    pergunta = req.conteudo.strip()
    if not pergunta:
        raise HTTPException(status_code=400, detail="A mensagem não pode estar vazia.")

    model_id, _ = resolver_modelo(req.modelo or conv.get("modelo"))
    historico_anterior = list(conv.get("mensagens") or [])

    # Salva a pergunta do analista imediatamente e renomeia se ainda estiver com título padrão
    store.salvar_mensagem(conversa_id, "user", pergunta, modelo=model_id)
    novo_titulo: str | None = None
    if not historico_anterior and conv.get("titulo") in {"Nova verificação", "Nova conversa"}:
        novo_titulo = _gerar_titulo_automatico(pergunta)
        store.atualizar_conversa(conversa_id, titulo=novo_titulo, modelo=model_id)

    loop = asyncio.get_running_loop()
    fila: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()

    def _executar_agente() -> None:
        try:
            for evento in investigar_streaming(
                pergunta,
                historico_mensagens=historico_anterior,
                modelo=model_id,
            ):
                if evento.get("tipo") == "concluido":
                    texto_final = str(evento.get("texto_completo") or "").strip()
                    if texto_final:
                        msg_salva = store.salvar_mensagem(
                            conversa_id,
                            "assistant",
                            texto_final,
                            modelo=str(evento.get("modelo") or model_id),
                            ferramentas=evento.get("ferramentas_usadas") or [],
                            tokens=evento.get("tokens") or {},
                        )
                        evento = {**evento, "mensagem_id": msg_salva["id"]}
                    if novo_titulo:
                        evento = {**evento, "novo_titulo": novo_titulo}
                loop.call_soon_threadsafe(fila.put_nowait, evento)
        except Exception as exc:  # noqa: BLE001
            loop.call_soon_threadsafe(
                fila.put_nowait,
                {"tipo": "erro", "mensagem": f"Erro interno na investigação ({type(exc).__name__})."},
            )
        finally:
            loop.call_soon_threadsafe(fila.put_nowait, None)

    threading.Thread(target=_executar_agente, daemon=True).start()

    async def _stream_sse():
        if novo_titulo:
            yield f"data: {json.dumps({'tipo': 'titulo', 'titulo': novo_titulo}, ensure_ascii=False)}\n\n"
        while True:
            item = await fila.get()
            if item is None:
                break
            yield f"data: {json.dumps(item, ensure_ascii=False)}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(
        _stream_sse(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Atalhos Rápidos (0 tokens de IA — consulta direta às ferramentas Python)
# ---------------------------------------------------------------------------

def _executar_rapido_json(nome_tool: str, args: dict[str, Any]) -> JSONResponse:
    ok, raw_json, _ = executar_ferramenta(nome_tool, args)
    try:
        dados = json.loads(raw_json)
    except ValueError:
        dados = {"ok": False, "erro": raw_json}
    return JSONResponse(dados, status_code=200 if ok else 502)


@app.get("/api/rapido/infra-ativa")
async def rapido_infra_ativa(
    escopo: str = Query(default="infra", pattern="^(infra|clientes|todos)$"),
    severidade_min: int = Query(default=2, ge=0, le=5),
    termo: str = Query(default="", max_length=80),
) -> JSONResponse:
    args: dict[str, Any] = {"escopo": escopo, "severidade_min": severidade_min, "limite": 60}
    if termo.strip():
        if "," in termo or ";" in termo:
            partes = [p.strip() for p in termo.replace(";", ",").split(",") if p.strip()]
            args["termos"] = partes
            args["qualquer_termo"] = True
        else:
            args["termos"] = termo.strip().split()
    return await asyncio.to_thread(_executar_rapido_json, "zabbix_problemas_ativos", args)


@app.get("/api/rapido/saude")
async def rapido_saude(testar_apis: bool = Query(default=True)) -> JSONResponse:
    return await asyncio.to_thread(
        _executar_rapido_json,
        "noc_saude_e_logs",
        {"ultimos_envios": 10, "testar_apis": testar_apis},
    )


@app.get("/api/rapido/ixc")
async def rapido_ixc(termo: str = Query(..., min_length=1, max_length=120)) -> JSONResponse:
    def _consultar() -> JSONResponse:
        ok, raw_diag, _ = executar_ferramenta("ixc_diagnosticar_cliente", {"termo": termo})
        diag = json.loads(raw_diag)
        sessoes: list[dict[str, Any]] = []
        if ok:
            logins = diag.get("logins") or []
            if logins and logins[0].get("login"):
                ok_rad, raw_rad, _ = executar_ferramenta(
                    "ixc_historico_radius", {"username": logins[0]["login"], "limite": 8}
                )
                if ok_rad:
                    sessoes = json.loads(raw_rad).get("sessoes") or []
            elif "." in termo and termo.replace(".", "").isdigit():
                ok_rad, raw_rad, _ = executar_ferramenta(
                    "ixc_historico_radius",
                    {"ip": termo, "prefixo_ip": termo.endswith("."), "limite": 10},
                )
                if ok_rad:
                    sessoes = json.loads(raw_rad).get("sessoes") or []
        diag["sessoes_radius"] = sessoes
        return JSONResponse(diag, status_code=200 if ok else 502)

    return await asyncio.to_thread(_consultar)


@app.get("/api/rapido/olt-pon")
async def rapido_olt_pon(host: str = Query(..., min_length=2, max_length=120)) -> JSONResponse:
    return await asyncio.to_thread(
        _executar_rapido_json,
        "zabbix_resumo_olt_pon",
        {"host_olt": host},
    )


@app.get("/api/rapido/hosts")
async def rapido_hosts(busca: str = Query(default="OLT", max_length=80)) -> JSONResponse:
    return await asyncio.to_thread(
        _executar_rapido_json,
        "zabbix_buscar_hosts",
        {"busca": busca, "limite": 40},
    )


@app.get("/api/rapido/consumo")
async def rapido_consumo() -> dict[str, Any]:
    return await asyncio.to_thread(resumo_consumo, chat_db_path=store.caminho)


if __name__ == "__main__":
    import uvicorn

    porta = int(os.getenv("NOC_PAINEL_PORT", "8090"))
    uvicorn.run("server.painel:app", host="127.0.0.1", port=porta, reload=False)
