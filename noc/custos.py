"""
Cálculo e agregação de consumo estimado de tokens e custos (USD / BRL) da API Gemini.

Lê os registros reais gravados localmente em:
- ``logs/envios.jsonl`` (envios automáticos do webhook NOC)
- ``logs/painel_chat.sqlite3`` (investigações realizadas no Painel Local)

Os preços seguem a tabela padrão oficial do Google AI Studio
(https://ai.google.dev/gemini-api/docs/pricing) em USD por 1 milhão de tokens.
"""
from __future__ import annotations

import json
import os
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from noc.consulta import FUSO

RAIZ = Path(__file__).resolve().parent.parent
ENVIOS_PATH_PADRAO = RAIZ / "logs" / "envios.jsonl"
CHAT_DB_PADRAO = RAIZ / "logs" / "painel_chat.sqlite3"

# Preços oficiais Paid Tier (USD por 1M tokens).
# Tokens de raciocínio (thinking) são faturados na mesma tarifa de saída.
PRECOS_USD_POR_1M: dict[str, dict[str, float]] = {
    "gemini-3.5-flash-lite": {"in": 0.30, "out": 2.50, "cache": 0.30},
    "gemini-3.1-flash-lite": {"in": 0.10, "out": 0.40, "cache": 0.10},
    "gemini-3.5-flash": {"in": 0.50, "out": 3.00, "cache": 0.05},
    "gemini-3.8-flash": {"in": 0.50, "out": 3.00, "cache": 0.05},
    "gemini-4-hydrogen": {"in": 1.50, "out": 7.50, "cache": 0.075},
    "gemini-4-neon": {"in": 3.00, "out": 15.00, "cache": 0.15},
    "gemini-4-argon": {"in": 2.00, "out": 12.00, "cache": 0.10},
    "gemini-4-carbon": {"in": 5.00, "out": 25.00, "cache": 0.25},
}

_PRECO_FALLBACK = PRECOS_USD_POR_1M["gemini-3.5-flash-lite"]


def obter_cotacao_usd_brl() -> float:
    bruto = os.getenv("NOC_USD_BRL", "5.85").strip().replace(",", ".")
    try:
        val = float(bruto)
        return val if 1.0 <= val <= 30.0 else 5.85
    except ValueError:
        return 5.85


def _tabela_modelo(modelo: str) -> dict[str, float]:
    chave = (modelo or "").strip().lower().removeprefix("models/")
    if chave in PRECOS_USD_POR_1M:
        return PRECOS_USD_POR_1M[chave]
    for conhecido, precos in PRECOS_USD_POR_1M.items():
        if chave.startswith(conhecido):
            return precos
    return _PRECO_FALLBACK


def calcular_custo_tokens(
    modelo: str,
    tokens: dict[str, Any] | None,
    usd_brl: float | None = None,
) -> dict[str, float]:
    """Calcula o custo estimado (USD e BRL) a partir do dicionário ``usage`` da API Gemini."""
    if not tokens or not isinstance(tokens, dict):
        return {"usd": 0.0, "brl": 0.0}
    cotacao = usd_brl if usd_brl is not None else obter_cotacao_usd_brl()
    precos = _tabela_modelo(modelo)

    tin = int(tokens.get("total_input_tokens") or 0)
    tout = int(tokens.get("total_output_tokens") or 0)
    tthought = int(tokens.get("total_thought_tokens") or 0)
    tcached = int(tokens.get("total_cached_tokens") or 0)

    # Caso só exista total_tokens (registros muito antigos), assume proporção conservadora
    if tin == 0 and tout == 0 and int(tokens.get("total_tokens") or 0) > 0:
        total = int(tokens["total_tokens"])
        tin = int(total * 0.85)
        tout = total - tin

    in_sem_cache = max(0, tin - tcached)
    usd = (
        in_sem_cache * precos["in"]
        + tcached * precos["cache"]
        + (tout + tthought) * precos["out"]
    ) / 1_000_000.0
    return {
        "usd": round(usd, 6),
        "brl": round(usd * cotacao, 4),
    }


def _parse_data_iso(valor: str) -> datetime | None:
    texto = (valor or "").strip()
    if not texto:
        return None
    try:
        dt = datetime.fromisoformat(texto)
        return dt if dt.tzinfo is not None else dt.replace(tzinfo=FUSO)
    except ValueError:
        return None


def _carregar_eventos_webhook(envios_path: Path, modelo_padrao_webhook: str) -> list[dict[str, Any]]:
    if not envios_path.exists():
        return []
    itens: list[dict[str, Any]] = []
    for linha in envios_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not linha.strip():
            continue
        try:
            d = json.loads(linha)
        except ValueError:
            continue
        if d.get("origem") != "ia":
            continue
        tok = d.get("tokens")
        if not isinstance(tok, dict) or not tok:
            continue
        dt = _parse_data_iso(str(d.get("quando") or ""))
        if dt is None:
            continue
        modelo = str(d.get("modelo") or modelo_padrao_webhook).strip()
        itens.append({
            "dt": dt,
            "fonte": "webhook",
            "modelo": modelo,
            "tokens": tok,
        })
    return itens


def _carregar_eventos_chat(chat_db_path: Path) -> list[dict[str, Any]]:
    if not chat_db_path.exists():
        return []
    itens: list[dict[str, Any]] = []
    try:
        conn = sqlite3.connect(chat_db_path, timeout=5)
        try:
            rows = conn.execute(
                """
                SELECT modelo, tokens_json, criada_em
                FROM mensagens
                WHERE papel = 'assistant' AND tokens_json != '{}' AND tokens_json != ''
                """
            ).fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        return []

    for modelo, tokens_json, criada_em in rows:
        try:
            tok = json.loads(tokens_json or "{}")
        except ValueError:
            continue
        if not isinstance(tok, dict) or not tok:
            continue
        dt = _parse_data_iso(str(criada_em or ""))
        if dt is None:
            continue
        itens.append({
            "dt": dt,
            "fonte": "painel",
            "modelo": str(modelo or "gemini-4-hydrogen").strip(),
            "tokens": tok,
        })
    return itens


def _bucket_vazio() -> dict[str, Any]:
    return {
        "chamadas": 0,
        "chamadas_webhook": 0,
        "chamadas_painel": 0,
        "tokens_entrada": 0,
        "tokens_saida": 0,
        "tokens_total": 0,
        "usd": 0.0,
        "brl": 0.0,
        "brl_webhook": 0.0,
        "brl_painel": 0.0,
    }


def _somar_bucket(bucket: dict[str, Any], fonte: str, tok: dict[str, Any], custo: dict[str, float]) -> None:
    tin = int(tok.get("total_input_tokens") or 0)
    tout = int(tok.get("total_output_tokens") or 0) + int(tok.get("total_thought_tokens") or 0)
    ttot = int(tok.get("total_tokens") or (tin + tout))
    bucket["chamadas"] += 1
    if fonte == "webhook":
        bucket["chamadas_webhook"] += 1
        bucket["brl_webhook"] += custo["brl"]
    else:
        bucket["chamadas_painel"] += 1
        bucket["brl_painel"] += custo["brl"]
    bucket["tokens_entrada"] += tin
    bucket["tokens_saida"] += tout
    bucket["tokens_total"] += ttot
    bucket["usd"] += custo["usd"]
    bucket["brl"] += custo["brl"]


def _arredondar_bucket(b: dict[str, Any]) -> dict[str, Any]:
    return {
        **b,
        "usd": round(b["usd"], 4),
        "brl": round(b["brl"], 2),
        "brl_webhook": round(b["brl_webhook"], 2),
        "brl_painel": round(b["brl_painel"], 2),
    }


def resumo_consumo(
    *,
    envios_path: Path | None = None,
    chat_db_path: Path | None = None,
    usd_brl: float | None = None,
    agora: datetime | None = None,
) -> dict[str, Any]:
    """Consolida o consumo estimado (hoje, 7 dias, 30 dias, mês atual, por modelo e diário)."""
    cotacao = usd_brl if usd_brl is not None else obter_cotacao_usd_brl()
    ref = agora if agora is not None else datetime.now(FUSO)
    if ref.tzinfo is None:
        ref = ref.replace(tzinfo=FUSO)

    modelo_webhook = os.getenv("NOC_AI_MODEL", "gemini-3.5-flash-lite").strip() or "gemini-3.5-flash-lite"
    eventos = _carregar_eventos_webhook(envios_path or ENVIOS_PATH_PADRAO, modelo_webhook)
    eventos.extend(_carregar_eventos_chat(chat_db_path or CHAT_DB_PADRAO))

    hoje_data = ref.date()
    inicio_7d = (ref - timedelta(days=6)).replace(hour=0, minute=0, second=0, microsecond=0)
    inicio_30d = (ref - timedelta(days=29)).replace(hour=0, minute=0, second=0, microsecond=0)
    inicio_14d = (ref - timedelta(days=13)).replace(hour=0, minute=0, second=0, microsecond=0)

    b_hoje = _bucket_vazio()
    b_7d = _bucket_vazio()
    b_30d = _bucket_vazio()
    b_mes = _bucket_vazio()
    b_total = _bucket_vazio()

    por_modelo: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "modelo": "",
        "chamadas_30d": 0,
        "tokens_30d": 0,
        "usd_30d": 0.0,
        "brl_30d": 0.0,
    })
    por_dia: dict[str, dict[str, Any]] = {}

    for ev in eventos:
        dt: datetime = ev["dt"]
        fonte: str = ev["fonte"]
        modelo: str = ev["modelo"]
        tok: dict[str, Any] = ev["tokens"]
        custo = calcular_custo_tokens(modelo, tok, usd_brl=cotacao)

        _somar_bucket(b_total, fonte, tok, custo)
        if dt.date() == hoje_data:
            _somar_bucket(b_hoje, fonte, tok, custo)
        if dt >= inicio_7d:
            _somar_bucket(b_7d, fonte, tok, custo)
        if dt >= inicio_30d:
            _somar_bucket(b_30d, fonte, tok, custo)
            m = por_modelo[modelo]
            m["modelo"] = modelo
            m["chamadas_30d"] += 1
            m["tokens_30d"] += int(tok.get("total_tokens") or 0)
            m["usd_30d"] += custo["usd"]
            m["brl_30d"] += custo["brl"]
        if dt.year == ref.year and dt.month == ref.month:
            _somar_bucket(b_mes, fonte, tok, custo)
        if dt >= inicio_14d:
            chave_dia = dt.strftime("%Y-%m-%d")
            if chave_dia not in por_dia:
                por_dia[chave_dia] = {
                    "data": dt.strftime("%d/%m/%Y"),
                    "iso": chave_dia,
                    "chamadas_webhook": 0,
                    "chamadas_painel": 0,
                    "tokens_total": 0,
                    "brl": 0.0,
                }
            row = por_dia[chave_dia]
            if fonte == "webhook":
                row["chamadas_webhook"] += 1
            else:
                row["chamadas_painel"] += 1
            row["tokens_total"] += int(tok.get("total_tokens") or 0)
            row["brl"] += custo["brl"]

    modelos_lista = [
        {
            **m,
            "usd_30d": round(m["usd_30d"], 4),
            "brl_30d": round(m["brl_30d"], 2),
        }
        for m in sorted(por_modelo.values(), key=lambda x: -x["brl_30d"])
    ]

    dias_lista = [
        {**d, "brl": round(d["brl"], 2)}
        for d in sorted(por_dia.values(), key=lambda x: x["iso"], reverse=True)
    ]

    media_diaria_7d = round(b_7d["brl"] / 7.0, 2)
    projecao_mensal = round((b_30d["brl"] / 30.0) * 30.0, 2)

    return {
        "ok": True,
        "atualizado_em": ref.strftime("%d/%m/%Y %H:%M:%S"),
        "cotacao_usd_brl": cotacao,
        "hoje": _arredondar_bucket(b_hoje),
        "ultimos_7d": _arredondar_bucket(b_7d),
        "ultimos_30d": _arredondar_bucket(b_30d),
        "mes_atual": _arredondar_bucket(b_mes),
        "historico_total": _arredondar_bucket(b_total),
        "media_diaria_7d_brl": media_diaria_7d,
        "projecao_mensal_brl": projecao_mensal,
        "por_modelo_30d": modelos_lista,
        "diario_14d": dias_lista,
    }
