"""
Envio de texto ao mensageiro configurado (Telegram ou Evolution/WhatsApp).

Centraliza a escolha por ``NOC_MENSAGEIRO`` e o destino padrão do ``.env`` para
que webhook e scripts não repitam essa lógica.

Variáveis de ambiente (.env):
    NOC_MENSAGEIRO        "telegram" (padrão) ou "evolution"
    TELEGRAM_CHAT_ID      destino quando NOC_MENSAGEIRO=telegram
    EVOLUTION_GROUP_JID   destino quando NOC_MENSAGEIRO=evolution
"""
from __future__ import annotations

import os
from typing import Optional

MENSAGEIROS = ("telegram", "evolution")
LIMITE_TEXTO = 4000  # margem para o limite de 4096 caracteres do Telegram


def mensageiro_configurado() -> str:
    mensageiro = os.getenv("NOC_MENSAGEIRO", "telegram").strip().lower()
    if mensageiro not in MENSAGEIROS:
        raise RuntimeError(f"NOC_MENSAGEIRO inválido: {mensageiro!r}. Use telegram ou evolution.")
    return mensageiro


def enviar_mensagem(texto: str, mensageiro: Optional[str] = None) -> str:
    """Envia ``texto`` ao destino padrão e devolve o nome do mensageiro usado.

    Erros dos clientes (``TelegramErro``/``EvolutionErro``) são propagados sem
    alteração para que o chamador decida como registrá-los.
    """
    mensageiro = mensageiro or mensageiro_configurado()
    if len(texto) > LIMITE_TEXTO:
        texto = texto[:LIMITE_TEXTO - 40].rstrip() + "\n\n[mensagem truncada]"

    if mensageiro == "evolution":
        from clients.whatsapp import EvolutionClient
        destino = os.getenv("EVOLUTION_GROUP_JID", "").strip()
        if not destino:
            raise RuntimeError("EVOLUTION_GROUP_JID ausente no .env")
        EvolutionClient().enviar_texto(destino, texto)
    elif mensageiro == "telegram":
        from clients.telegram import TelegramClient
        destino = os.getenv("TELEGRAM_CHAT_ID", "").strip()
        if not destino:
            raise RuntimeError("TELEGRAM_CHAT_ID ausente no .env")
        TelegramClient().enviar_texto(destino, texto)
    else:
        raise RuntimeError(f"Mensageiro desconhecido: {mensageiro!r}")
    return mensageiro
