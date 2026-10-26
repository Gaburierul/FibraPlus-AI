"""
Script para testar o envio de mensagem pelo Telegram de forma avulsa.

Uso: python scripts/testar_telegram.py (preparar) ou python scripts/testar_telegram.py --enviar
"""
import os
import sys
import argparse
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
from dotenv import load_dotenv

load_dotenv(RAIZ / ".env")
from clients.telegram import TelegramClient

def main():
    parser = argparse.ArgumentParser(description="Prepara um teste de envio para o Telegram.")
    parser.add_argument("--enviar", action="store_true", help="Envia a mensagem de teste ao chat configurado.")
    args = parser.parse_args()
    try:
        cliente = TelegramClient()
        destino = os.getenv("TELEGRAM_CHAT_ID", "")
        if not destino:
            print("Defina a variável TELEGRAM_CHAT_ID no seu .env")
            return
        
        texto = "✅ *Teste do FibraPlus NOC IA*\nSe você recebeu esta mensagem, a integração com o Telegram está funcionando!"
        if not args.enviar:
            print(f"Teste preparado para TELEGRAM_CHAT_ID configurado ({len(texto)} caracteres). Não enviado.")
            print("Use --enviar para enviar a mensagem de teste.")
            return
        res = cliente.enviar_texto(destino, texto)
        print(f"Sucesso! Telegram confirmou o envio (HTTP {res.get('status', 'ok')}).")
    except Exception as e:
        print(f"Erro ao enviar ({type(e).__name__}).")

if __name__ == "__main__":
    main()
