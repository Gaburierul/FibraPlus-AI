"""
Análise por IA (Gemini - Interactions API) com saída estruturada e fallback.

Se a IA falhar (sem chave, sem rede, cota, resposta inválida), é gerada uma
mensagem determinística a partir da correlação — o NOC nunca fica sem alerta.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel, Field, ValidationError

from noc.correlator import Correlacao, Incidente

MODELO_PADRAO = os.getenv("NOC_AI_MODEL", "gemini-3.8-flash")
LIMITE_WHATSAPP = 3500  # caracteres (margem segura para uma mensagem)
MAX_OCORRENCIAS_IA = 250  # evita estourar custo em "tempestades" de alertas
RAIZ = Path(__file__).resolve().parent.parent
REGRAS_TAGS = RAIZ / "docs" / "regras_tags_zabbix.md"

EMOJI = {"CRITICO": "🚨", "ALERTA": "⚠️", "INFORMATIVO": "ℹ️", "NORMALIZADO": "✅"}
ROTULO = {"CRITICO": "CRÍTICO", "ALERTA": "ALERTA", "INFORMATIVO": "INFORMATIVO", "NORMALIZADO": "NORMALIZADO"}


class AnaliseNOC(BaseModel):
    """Contrato da resposta da IA (validado com Pydantic)."""

    classificacao: Literal["CRITICO", "ALERTA", "INFORMATIVO", "NORMALIZADO"] = Field(
        description="Classificação geral seguindo a regra de tags (1/2/3) e o estado atual.")
    titulo: str = Field(description="Título curto do evento (máx. 80 caracteres).")
    resumo: str = Field(description="O que aconteceu, onde e quando, em 2-3 frases.")
    causa_raiz_provavel: str = Field(description="Hipótese de causa raiz e o encadeamento causa->efeito.")
    confianca: Literal["alta", "media", "baixa"] = Field(
        description="Confiança na causa raiz, considerando os dados disponíveis.")
    evidencias: list[str] = Field(description="Fatos dos alertas que sustentam a hipótese (horários, hosts).")
    equipamentos_afetados: list[str] = Field(description="Hostnames EXATAMENTE como aparecem nos dados.")
    acoes_recomendadas: list[str] = Field(description="Próximos passos objetivos para o NOC, em ordem de prioridade.")
    dados_faltantes: list[str] = Field(description="O que precisaria ser verificado para confirmar a hipótese.")
    mensagem_whatsapp: str = Field(description="Mensagem final pronta para o grupo do WhatsApp.")


@dataclass
class ResultadoAnalise:
    mensagem: str
    origem: str  # "ia" | "fallback"
    analise: Optional[AnaliseNOC] = None
    tokens: Optional[dict] = None
    erros: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Prompt
# --------------------------------------------------------------------------- #
def _instrucao_sistema() -> str:
    regras = REGRAS_TAGS.read_text(encoding="utf-8") if REGRAS_TAGS.exists() else ""
    return f"""
Você é um Engenheiro de NOC Nível 3 sênior do provedor FibraPlus (Mato Grosso do Sul).
Você recebe alertas do Zabbix JÁ PRÉ-PROCESSADOS (agrupados em incidentes por janela de tempo,
com estado consolidado: ATIVO, RESOLVIDO ou OSCILANDO) e deve produzir um diagnóstico único.

## Regras de severidade da empresa (OBRIGATÓRIAS)
{regras}

- Se houver tag topológica, ela prevalece sobre o "Nível" do Zabbix.
- Se NÃO houver tags, use o campo `classificacao_regra` (derivado da severidade Zabbix) e
  deixe claro em `dados_faltantes` que a classificação não usou tags.
- Se todas as ocorrências estiverem RESOLVIDAS, a classificação é NORMALIZADO.

## Como raciocinar
1. Ordene cronologicamente e procure o PRIMEIRO evento de camada mais baixa
   (físico/óptico -> link -> OSPF/IGP -> BGP -> PPPoE/serviços -> coleta SNMP).
2. Eventos em vários equipamentos/sites no mesmo segundo indicam causa comum
   (enlace compartilhado, energia, equipamento central, route reflector).
3. "No SNMP data collection" logo após falha de roteamento geralmente é EFEITO
   (perda da rota de gerência), não causa.
4. Diferencie oscilação (flapping) de queda contínua.
5. Nome com macro não resolvida (ex.: {{ITEM.NAME1}}) é falha de template: itens distintos
   podem aparecer com o mesmo nome. Mencione isso como observação, sem exagerar.
6. Hostnames seguem SITE-...-FABRICANTE-FUNÇÃO (ex.: CPE-MSD-HUAWEI-BNG01: site CPE-MSD,
   função BNG01). BNG = concentrador PPPoE, RR = route reflector BGP, PE = roteador de borda,
   OLT = GPON. Não invente nomes de cidades: se não tiver certeza, use o código do site.
7. NUNCA invente equipamentos, IPs, horários ou números que não estejam nos dados.
   Se os dados forem insuficientes, diga isso e use confiança "baixa".

## Formato de `mensagem_whatsapp`
- Sintaxe WhatsApp: *negrito*, _itálico_. NÃO use markdown (#, **, tabelas).
- Primeira linha: emoji + *CLASSIFICAÇÃO* + título. (🚨 crítico, ⚠️ alerta, ℹ️ informativo, ✅ normalizado)
- Blocos curtos: 📍 Local | 🕒 Janela | 🧠 Causa provável | 🖥️ Afetados | 🛠️ Ações | 📌 Status.
- Agrupe equipamentos repetidos. Máximo ~{LIMITE_WHATSAPP} caracteres.
- Escreva em português do Brasil, direto e técnico.
""".strip()


def _montar_entrada(correlacao: Correlacao) -> tuple[str, list[str]]:
    avisos: list[str] = []
    incidentes = [i.to_dict() for i in correlacao.incidentes]
    total = sum(len(i["ocorrencias"]) for i in incidentes)
    if total > MAX_OCORRENCIAS_IA:
        avisos.append(f"Lote com {total} ocorrências; enviando apenas as {MAX_OCORRENCIAS_IA} mais relevantes à IA.")
        restante = MAX_OCORRENCIAS_IA
        for inc in incidentes:
            inc["ocorrencias"] = inc["ocorrencias"][:max(restante, 0)]
            restante -= len(inc["ocorrencias"])
        incidentes = [i for i in incidentes if i["ocorrencias"]]
    payload = {
        "incidentes": incidentes,
        "alertas_de_clientes_filtrados": correlacao.clientes_filtrados,
        "observacoes_do_pre_processamento": correlacao.observacoes,
    }
    texto = ("Analise os incidentes abaixo e responda no schema solicitado.\n\n"
             + json.dumps(payload, ensure_ascii=False, indent=1))
    return texto, avisos


# --------------------------------------------------------------------------- #
# Chamada à IA
# --------------------------------------------------------------------------- #
def _chamar_gemini(entrada: str, modelo: str, thinking: str, tentativas: int = 3):
    from google import genai
    from google.genai import errors

    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    ultimo_erro: Optional[Exception] = None
    for tentativa in range(1, tentativas + 1):
        try:
            return client.interactions.create(
                model=modelo,
                input=entrada,
                system_instruction=_instrucao_sistema(),
                generation_config={"thinking_level": thinking},
                response_format=[{
                    "type": "text",
                    "mime_type": "application/json",
                    "schema": AnaliseNOC.model_json_schema(),
                }],
                store=False,  # dados de rede não ficam armazenados no servidor
            )
        except errors.APIError as exc:
            ultimo_erro = exc
            codigo = getattr(exc, "code", None)
            if codigo in (429, 500, 502, 503, 504) and tentativa < tentativas:
                time.sleep(2 ** tentativa)
                continue
            raise
    raise RuntimeError(f"Falha após {tentativas} tentativas: {ultimo_erro}")


def _extrair_tokens(interaction) -> Optional[dict]:
    uso = getattr(interaction, "usage", None)
    if not uso:
        return None
    dados = uso.model_dump(exclude_none=True) if hasattr(uso, "model_dump") else dict(uso)
    return {k: v for k, v in dados.items() if isinstance(v, (int, float))}


def _sanitizar(analise: AnaliseNOC, correlacao: Correlacao) -> list[str]:
    """Guarda-corpos contra alucinação e mensagens grandes demais."""
    avisos: list[str] = []
    conhecidos = {o.equipamento.lower(): o.equipamento for o in correlacao.ocorrencias}
    inventados = [e for e in analise.equipamentos_afetados if e.lower() not in conhecidos]
    if inventados:
        avisos.append(f"IA citou equipamentos fora dos dados (removidos): {', '.join(inventados)}")
        analise.equipamentos_afetados = [conhecidos[e.lower()] for e in analise.equipamentos_afetados
                                         if e.lower() in conhecidos]
    regra = _classificacao_geral(correlacao)
    if analise.classificacao != regra:
        avisos.append(f"IA classificou como {analise.classificacao}, regra de tags indica {regra}.")
    analise.mensagem_whatsapp = analise.mensagem_whatsapp.replace("**", "*").strip()
    if len(analise.mensagem_whatsapp) > LIMITE_WHATSAPP:
        analise.mensagem_whatsapp = analise.mensagem_whatsapp[:LIMITE_WHATSAPP - 20].rstrip() + "\n_(truncado)_"
        avisos.append("Mensagem truncada para caber no WhatsApp.")
    return avisos


# --------------------------------------------------------------------------- #
# Fallback determinístico
# --------------------------------------------------------------------------- #
def _classificacao_geral(correlacao: Correlacao) -> str:
    if not correlacao.incidentes:
        return "NORMALIZADO"
    from noc.correlator import ORDEM_CLASSIFICACAO
    return min((i.classificacao for i in correlacao.incidentes), key=lambda c: ORDEM_CLASSIFICACAO[c])


def _linha_incidente(inc: Incidente) -> str:
    janela = ""
    if inc.inicio:
        janela = inc.inicio.strftime("%H:%M:%S")
        if inc.fim and inc.fim != inc.inicio:
            janela += f"–{inc.fim.strftime('%H:%M:%S')}"
    linhas = [f"{EMOJI[inc.classificacao]} *{ROTULO[inc.classificacao]}* | 🕒 {janela or 's/ horário'}",
              f"📍 Sites: {', '.join(inc.sites)} | Categorias: {', '.join(inc.categorias)}"]
    for o in sorted(inc.ocorrencias, key=lambda o: (o.estado == "RESOLVIDO", o.inicio or datetime.min)):
        estado = {"ATIVO": "🔴", "OSCILANDO": "🟠", "RESOLVIDO": "🟢"}[o.estado]
        extra = f" ({o.vezes}x)" if o.vezes > 1 else ""
        peso = f" [{o.peso[1]}]" if o.peso else ""
        linhas.append(f"{estado} {o.equipamento}: {o.problema}{extra}{peso}")
    return "\n".join(linhas)


def mensagem_fallback(correlacao: Correlacao, motivo: str = "") -> str:
    if not correlacao.incidentes:
        return "✅ *NORMALIZADO* — nenhum alerta de infraestrutura no lote analisado."
    geral = _classificacao_geral(correlacao)
    partes = [f"{EMOJI[geral]} *{ROTULO[geral]}* — Resumo automático de alertas (sem IA)"]
    partes += [_linha_incidente(i) for i in correlacao.incidentes]
    if correlacao.clientes_filtrados:
        partes.append(f"_{correlacao.clientes_filtrados} alerta(s) de clientes omitidos._")
    if motivo:
        partes.append(f"_Diagnóstico por IA indisponível: {motivo}_")
    texto = "\n\n".join(partes)
    return texto if len(texto) <= LIMITE_WHATSAPP else texto[:LIMITE_WHATSAPP - 20] + "\n_(truncado)_"


# --------------------------------------------------------------------------- #
# API pública
# --------------------------------------------------------------------------- #
def analisar(correlacao: Correlacao, usar_ia: bool = True, modelo: str = MODELO_PADRAO,
             thinking: str = "medium") -> ResultadoAnalise:
    if not correlacao.incidentes:
        return ResultadoAnalise(mensagem=mensagem_fallback(correlacao), origem="fallback")

    if not usar_ia:
        return ResultadoAnalise(mensagem=mensagem_fallback(correlacao), origem="fallback")

    if not os.getenv("GEMINI_API_KEY"):
        motivo = "GEMINI_API_KEY ausente no .env"
        return ResultadoAnalise(mensagem=mensagem_fallback(correlacao, motivo), origem="fallback", erros=[motivo])

    entrada, avisos = _montar_entrada(correlacao)
    try:
        interaction = _chamar_gemini(entrada, modelo, thinking)
        bruto = interaction.output_text or ""
        analise = AnaliseNOC.model_validate_json(bruto)
    except ValidationError as exc:
        motivo = "resposta da IA fora do formato esperado"
        return ResultadoAnalise(mensagem=mensagem_fallback(correlacao, motivo), origem="fallback",
                                erros=avisos + [f"{motivo}: {exc.errors()[:2]}"])
    except Exception as exc:  # noqa: BLE001
        motivo = f"{type(exc).__name__}: {str(exc)[:160]}"
        return ResultadoAnalise(mensagem=mensagem_fallback(correlacao, motivo), origem="fallback",
                                erros=avisos + [motivo])

    avisos += _sanitizar(analise, correlacao)
    return ResultadoAnalise(mensagem=analise.mensagem_whatsapp, origem="ia", analise=analise,
                            tokens=_extrair_tokens(interaction), erros=avisos)
