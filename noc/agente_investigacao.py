"""
Agente investigativo interativo do NOC FibraPlus (Interactions API + Function Calling + SSE).

Opera estritamente sobre o catálogo de ferramentas somente leitura em
``noc.ferramentas_noc``, com suporte a streaming em tempo real e alternância
entre ``gemini-4-hydrogen`` (padrão rápido/equilibrado) e ``gemini-4-neon``
(investigações profundas) dentro da mesma conversa.
"""
from __future__ import annotations

import json
import os
import time
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from noc.consulta import FUSO
from noc.ferramentas_noc import (
    ROTULOS_FERRAMENTAS,
    TOOLS_DECLARATIONS,
    executar_ferramenta,
)

RAIZ = Path(__file__).resolve().parent.parent
load_dotenv(RAIZ / ".env")

REGRAS_TAGS = RAIZ / "docs" / "regras_tags_zabbix.md"

MODELO_CHAT_PADRAO = os.getenv("NOC_CHAT_MODEL", "").strip() or "gemini-4-hydrogen"
MODELO_CHAT_PROFUNDO = os.getenv("NOC_CHAT_MODEL_DEEP", "").strip() or "gemini-4-neon"

MODELOS_DISPONIVEIS: dict[str, dict[str, str]] = {
    "gemini-4-hydrogen": {
        "id": "gemini-4-hydrogen",
        "nome": "Hydrogen",
        "rotulo": "Gemini 4 Hydrogen",
        "perfil": "Rápido e equilibrado para verificações do dia a dia",
        "thinking_padrao": "low",
    },
    "gemini-4-neon": {
        "id": "gemini-4-neon",
        "nome": "Neon",
        "rotulo": "Gemini 4 Neon",
        "perfil": "Raciocínio profundo para correlações complexas",
        "thinking_padrao": "medium",
    },
}

MAX_RODADAS = 8
MAX_CHAMADAS_FERRAMENTA = 14
MAX_OUTPUT_TOKENS = 4096
MAX_MENSAGENS_HISTORICO = 14

try:
    CHAT_TIMEOUT_MS = int(float(os.getenv("GEMINI_TIMEOUT_S", "90")) * 1000)
except ValueError:
    CHAT_TIMEOUT_MS = 90_000
CHAT_TIMEOUT_MS = max(15_000, min(CHAT_TIMEOUT_MS, 240_000))


def resolver_modelo(modelo_solicitado: str | None = None) -> tuple[str, str]:
    """Retorna ``(model_id, thinking_level)`` validados dentro da allowlist de modelos do painel."""
    escolha = (modelo_solicitado or "").strip().lower()
    if escolha in {"hydrogen", "rapido", "rápido"}:
        escolha = "gemini-4-hydrogen"
    elif escolha in {"neon", "profundo"}:
        escolha = "gemini-4-neon"
    if escolha not in MODELOS_DISPONIVEIS:
        escolha = MODELO_CHAT_PADRAO if MODELO_CHAT_PADRAO in MODELOS_DISPONIVEIS else "gemini-4-hydrogen"
    return escolha, MODELOS_DISPONIVEIS[escolha]["thinking_padrao"]


def _instrucao_sistema_chat() -> str:
    regras = REGRAS_TAGS.read_text(encoding="utf-8") if REGRAS_TAGS.exists() else ""
    agora = datetime.now(FUSO).strftime("%d/%m/%Y %H:%M:%S (America/Campo_Grande, UTC-4)")
    return f"""
Você é o assistente técnico de investigação de incidentes do NOC da FibraPlus.
Data e hora atuais: {agora}.

## Seu papel
Ajudar o analista de NOC a investigar incidentes, checar equipamentos, analisar histórico de
métricas/tráfego/sinal óptico, auditar OLTs PON a PON e cruzar clientes com o IXC Provedor e o
Ravicor usando EXCLUSIVAMENTE as ferramentas somente leitura disponíveis.

## Regras de severidade da rede FibraPlus
{regras}

## Diretrizes de investigação e precisão
1. **Sempre consulte dados reais antes de responder.** Nunca invente nomes de hosts, IPs,
   horários, sinais ópticos, causas de queda, contratos ou protocolos. Se uma ferramenta não
   retornar evidência suficiente, diga explicitamente o que foi checado e o que faltou.
2. **Não correlacione eventos aleatoriamente.** Só aponte causa comum entre equipamentos ou
   POPs distintos quando houver vínculo técnico explícito nos dados (mesmo enlace/interface,
   sessão BGP/OSPF compartilhada, mesma OLT/PON ou queda simultânea documentada no mesmo site).
3. **Diferencie falhas físicas de administrativas e elétricas:**
   - Em OLTs ZTE/Zabbix: valor `-80` indica **LOS / rompimento óptico**; `-90` indica
     **DyingGasp / falta de energia elétrica**; `Sinal acima` indica atenuação óptica.
   - No IXC Provedor: diferencie claramente **falha técnica** (contrato ativo/liberado e login
     offline) de **bloqueio administrativo/financeiro** (`CA`, `CM`, `FA`, `D`, contrato
     Negativado/Inativo) e sinalize sempre que já existir **Ordem de Serviço aberta**.
4. **Eficiência nas ferramentas:**
   - Comece amplo (ex.: `zabbix_problemas_ativos` ou `zabbix_historico_eventos`) e aprofunde só
     nos hosts/PONs/clientes relevantes (`zabbix_resumo_olt_pon`, `zabbix_metricas_host`,
     `zabbix_historico_metrica`, `ixc_diagnosticar_cliente`, `ixc_historico_radius`).
   - Quando o analista perguntar sobre um cliente, IP ou serial, consulte o IXC diretamente.
5. **Privacidade / LGPD:** jamais peça ou tente inferir CPF, CNPJ, telefone, endereço
   residencial ou dados de faturas; trabalhe somente com dados técnicos operacionais.
6. **Formato da resposta:** escreva em português claro, sem abreviações obscuras, com
   concordância correta e estrutura objetiva em Markdown:
   - **Resumo executivo** (2–4 linhas direto ao ponto).
   - **Evidências encontradas** (use tabelas Markdown compactas para PONs, interfaces, séries ou
     múltiplos alertas).
   - **Diagnóstico / Próximas verificações sugeridas** (separando fatos confirmados de hipóteses).
""".strip()


def _montar_historico_inicial(
    historico_mensagens: list[dict[str, Any]],
    pergunta_atual: str,
) -> list[dict[str, Any]]:
    """Converte mensagens salvas no SQLite para o formato ``input`` da Interactions API."""
    steps: list[dict[str, Any]] = []
    for msg in historico_mensagens[-MAX_MENSAGENS_HISTORICO:]:
        papel = msg.get("papel", "")
        texto = str(msg.get("conteudo") or "").strip()
        if not texto:
            continue
        if papel == "user":
            steps.append({"type": "user_input", "content": [{"type": "text", "text": texto}]})
        elif papel == "assistant":
            steps.append({"type": "model_output", "content": [{"type": "text", "text": texto}]})
    steps.append({"type": "user_input", "content": [{"type": "text", "text": pergunta_atual.strip()}]})
    return steps


def _acumular_tokens(acumulado: dict[str, int], usage: Any) -> None:
    if not usage:
        return
    dados = usage.model_dump(exclude_none=True) if hasattr(usage, "model_dump") else (
        dict(usage) if isinstance(usage, dict) else {}
    )
    for k in (
        "total_input_tokens",
        "total_output_tokens",
        "total_thought_tokens",
        "total_tool_use_tokens",
        "total_cached_tokens",
        "total_tokens",
    ):
        v = dados.get(k)
        if isinstance(v, (int, float)):
            acumulado[k] = acumulado.get(k, 0) + int(v)


def _formatar_erro_api(exc: Exception, modelo: str) -> str:
    codigo = getattr(exc, "status_code", None) or getattr(exc, "code", None)
    texto = str(exc)
    low = texto.lower()
    if codigo == 402 or "prepayment credits" in low or "billing" in low:
        return (
            f"Os créditos pré-pagos da chave Gemini (GEMINI_API_KEY) estão esgotados (HTTP 402) para o modelo "
            f"{modelo}. Recarregue os créditos no Google AI Studio ou use as Consultas Rápidas (sem IA) na barra lateral."
        )
    if codigo == 429 or "rate limit" in low or "quota" in low:
        return (
            f"Limite de requisições da API Gemini atingido (HTTP 429) para {modelo}. "
            "Aguarde alguns segundos e tente novamente, ou alterne para o modelo Hydrogen."
        )
    if codigo == 503 or "high demand" in low or "overloaded" in low:
        return (
            f"O modelo {modelo} está temporariamente sobrecarregado nos servidores do Google (HTTP 503). "
            "Tente novamente em instantes ou alterne de modelo."
        )
    if codigo in {401, 403}:
        return "A chave GEMINI_API_KEY foi recusada pela API do Google (HTTP 401/403). Verifique o arquivo .env."
    return f"Falha ao consultar {modelo} ({type(exc).__name__}): {texto[:220]}"


def _criar_cliente_genai():
    from google import genai
    from google.genai import types

    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise ValueError("GEMINI_API_KEY não configurada no arquivo .env.")
    return genai.Client(
        api_key=api_key,
        http_options=types.HttpOptions(
            timeout=CHAT_TIMEOUT_MS,
            retry_options=types.HttpRetryOptions(attempts=1),
        ),
    )


def _reconstruir_steps_stream(
    step_buffers: dict[int, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Reconstrói lista de steps a partir dos deltas de streaming quando ``interaction.steps`` não vier populado."""
    resultado: list[dict[str, Any]] = []
    for idx in sorted(step_buffers):
        buf = step_buffers[idx]
        tipo = buf.get("type")
        if tipo == "thought":
            step_dict: dict[str, Any] = {"type": "thought"}
            if buf.get("signature"):
                step_dict["signature"] = buf["signature"]
            if buf.get("summary"):
                step_dict["summary"] = [{"type": "text", "text": buf["summary"]}]
            resultado.append(step_dict)
        elif tipo == "function_call":
            args_raw = buf.get("arguments_raw", "")
            args_dict = buf.get("arguments_initial") or {}
            if args_raw:
                try:
                    parsed = json.loads(args_raw)
                    if isinstance(parsed, dict):
                        args_dict = parsed
                except ValueError:
                    pass
            resultado.append({
                "type": "function_call",
                "id": buf.get("id", f"call_{idx}"),
                "name": buf.get("name", ""),
                "arguments": args_dict,
            })
        elif tipo == "model_output":
            txt = buf.get("text", "")
            if txt:
                resultado.append({
                    "type": "model_output",
                    "content": [{"type": "text", "text": txt}],
                })
    return resultado


def investigar_streaming(
    pergunta: str,
    *,
    historico_mensagens: list[dict[str, Any]] | None = None,
    modelo: str | None = None,
    client: Any = None,
) -> Iterator[dict[str, Any]]:
    """Executa investigação multi-etapas com Function Calling e streaming SSE.

    Emite dicionários com a chave ``tipo``:
    ``status``, ``pensamento``, ``ferramenta_inicio``, ``ferramenta_fim``,
    ``texto``, ``concluido`` ou ``erro``.
    """
    model_id, thinking_level = resolver_modelo(modelo)
    nome_amigavel = MODELOS_DISPONIVEIS[model_id]["rotulo"]

    try:
        genai_client = client if client is not None else _criar_cliente_genai()
    except Exception as exc:  # noqa: BLE001
        yield {"tipo": "erro", "mensagem": str(exc)}
        return

    history = _montar_historico_inicial(historico_mensagens or [], pergunta)
    system_instruction = _instrucao_sistema_chat()

    tokens_totais: dict[str, int] = {}
    ferramentas_log: list[dict[str, Any]] = []
    chamadas_realizadas = 0
    texto_final_acumulado: list[str] = []

    yield {"tipo": "status", "texto": f"Analisando solicitação com {nome_amigavel}..."}

    for rodada in range(1, MAX_RODADAS + 1):
        step_buffers: dict[int, dict[str, Any]] = {}
        assembled_steps: list[dict[str, Any]] | None = None
        texto_rodada: list[str] = []

        try:
            stream = genai_client.interactions.create(
                model=model_id,
                input=history,
                system_instruction=system_instruction,
                tools=TOOLS_DECLARATIONS,
                store=False,
                stream=True,
                generation_config={
                    "thinking_level": thinking_level,
                    "thinking_summaries": "auto",
                    "max_output_tokens": MAX_OUTPUT_TOKENS,
                },
            )

            for event in stream:
                etype = getattr(event, "event_type", None)
                if etype == "error":
                    err_obj = getattr(event, "error", None)
                    msg_err = getattr(err_obj, "message", None) or str(err_obj or "Erro no streaming Gemini.")
                    yield {"tipo": "erro", "mensagem": msg_err}
                    return

                if etype == "step.start":
                    idx = getattr(event, "index", len(step_buffers))
                    step = getattr(event, "step", None)
                    stype = getattr(step, "type", None) or ""
                    buf: dict[str, Any] = {"type": stype}
                    if stype == "function_call":
                        buf["id"] = getattr(step, "id", "") or ""
                        buf["name"] = getattr(step, "name", "") or ""
                        buf["arguments_initial"] = getattr(step, "arguments", None) or {}
                        buf["arguments_raw"] = ""
                    step_buffers[idx] = buf

                elif etype == "step.delta":
                    idx = getattr(event, "index", 0)
                    delta = getattr(event, "delta", None)
                    dtype = getattr(delta, "type", None)
                    buf = step_buffers.setdefault(idx, {})

                    if dtype == "text":
                        chunk = getattr(delta, "text", "") or ""
                        if chunk:
                            buf["text"] = buf.get("text", "") + chunk
                            texto_rodada.append(chunk)
                            texto_final_acumulado.append(chunk)
                            yield {"tipo": "texto", "delta": chunk}
                    elif dtype == "thought_summary":
                        content = getattr(delta, "content", None)
                        chunk = getattr(content, "text", "") if content is not None else getattr(delta, "text", "")
                        if chunk:
                            buf["summary"] = buf.get("summary", "") + chunk
                            yield {"tipo": "pensamento", "texto": chunk}
                    elif dtype == "thought_signature":
                        sig = getattr(delta, "signature", "") or ""
                        if sig:
                            buf["signature"] = buf.get("signature", "") + sig
                    elif dtype == "arguments_delta":
                        frag = getattr(delta, "arguments", "") or ""
                        if frag:
                            buf["arguments_raw"] = buf.get("arguments_raw", "") + frag

                elif etype == "interaction.completed":
                    inter = getattr(event, "interaction", None)
                    if inter is not None:
                        _acumular_tokens(tokens_totais, getattr(inter, "usage", None))
                        steps_inter = getattr(inter, "steps", None)
                        if steps_inter:
                            assembled_steps = [
                                s.model_dump(exclude_none=True) if hasattr(s, "model_dump") else dict(s)
                                for s in steps_inter
                            ]
        except Exception as exc:  # noqa: BLE001
            yield {"tipo": "erro", "mensagem": _formatar_erro_api(exc, nome_amigavel)}
            return

        steps_turno = assembled_steps if assembled_steps is not None else _reconstruir_steps_stream(step_buffers)
        function_calls = [s for s in steps_turno if s.get("type") == "function_call"]

        if not function_calls:
            # Caso o modelo tenha retornado texto apenas no step montado sem delta (ex.: mocks)
            if not texto_rodada:
                for s in steps_turno:
                    if s.get("type") == "model_output":
                        for parte in s.get("content") or []:
                            if isinstance(parte, dict) and parte.get("type") == "text" and parte.get("text"):
                                texto_final_acumulado.append(parte["text"])
                                yield {"tipo": "texto", "delta": parte["text"]}
            yield {
                "tipo": "concluido",
                "modelo": model_id,
                "modelo_rotulo": nome_amigavel,
                "texto_completo": "".join(texto_final_acumulado),
                "ferramentas_usadas": ferramentas_log,
                "tokens": tokens_totais,
            }
            return

        # Preserva exatamente os steps do modelo (incluindo thought + signature + function_call)
        history.extend(steps_turno)

        for fc in function_calls:
            nome_tool = str(fc.get("name") or "")
            call_id = str(fc.get("id") or f"call_{rodada}_{chamadas_realizadas}")
            raw_args = fc.get("arguments")
            if isinstance(raw_args, str):
                try:
                    args_dict = json.loads(raw_args)
                except ValueError:
                    args_dict = {}
            elif isinstance(raw_args, dict):
                args_dict = raw_args
            else:
                args_dict = {}

            if chamadas_realizadas >= MAX_CHAMADAS_FERRAMENTA:
                res_json = json.dumps(
                    {
                        "ok": False,
                        "erro": (
                            f"Limite de {MAX_CHAMADAS_FERRAMENTA} consultas por turno atingido. "
                            "Consolide a resposta com as evidências já coletadas."
                        ),
                    },
                    ensure_ascii=False,
                )
                history.append({
                    "type": "function_result",
                    "name": nome_tool,
                    "call_id": call_id,
                    "is_error": True,
                    "result": [{"type": "text", "text": res_json}],
                })
                continue

            chamadas_realizadas += 1
            rotulo = ROTULOS_FERRAMENTAS.get(nome_tool, f"Executando {nome_tool}")
            yield {
                "tipo": "ferramenta_inicio",
                "nome": nome_tool,
                "rotulo": rotulo,
                "argumentos": args_dict,
            }

            t0 = time.monotonic()
            ok, res_json, resumo = executar_ferramenta(nome_tool, args_dict)
            duracao_ms = round((time.monotonic() - t0) * 1000)

            registro_tool = {
                "nome": nome_tool,
                "rotulo": rotulo,
                "argumentos": args_dict,
                "ok": ok,
                "resumo": resumo,
                "duracao_ms": duracao_ms,
            }
            ferramentas_log.append(registro_tool)
            yield {"tipo": "ferramenta_fim", **registro_tool}

            history.append({
                "type": "function_result",
                "name": nome_tool,
                "call_id": call_id,
                "is_error": not ok,
                "result": [{"type": "text", "text": res_json}],
            })

        yield {"tipo": "status", "texto": f"Correlacionando evidências com {nome_amigavel}..."}

    # Limite de rodadas atingido
    aviso_limite = (
        "\n\n> Limite máximo de rodadas de investigação atingido neste turno. "
        "Caso precise aprofundar em um equipamento ou cliente específico, envie uma nova pergunta direcionada."
    )
    texto_final_acumulado.append(aviso_limite)
    yield {"tipo": "texto", "delta": aviso_limite}
    yield {
        "tipo": "concluido",
        "modelo": model_id,
        "modelo_rotulo": nome_amigavel,
        "texto_completo": "".join(texto_final_acumulado),
        "ferramentas_usadas": ferramentas_log,
        "tokens": tokens_totais,
    }
