"""
Script para listar os IDs dos últimos grupos/chats onde o bot recebeu mensagem.
Uso: python scripts/descobrir_grupo_telegram.py
"""
import os
import sys
from pathlib import Path
import requests
from dotenv import load_dotenv

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
load_dotenv(RAIZ / ".env")

def main():
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        print("Erro: TELEGRAM_BOT_TOKEN não encontrado no .env")
        return

    print("Buscando mensagens recentes enviadas para o bot...")
    url = f"https://api.telegram.org/bot{token}/getUpdates"
    
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        dados = resp.json()
        if not isinstance(dados, dict) or dados.get("ok") is not True:
            print("A API do Telegram não confirmou a consulta.", file=sys.stderr)
            return

        resultados = dados.get("result", [])
        if not resultados:
            print("\nNenhuma mensagem recente encontrada.")
            print("DICA: Vá no grupo do Telegram, adicione o bot lá, e envie uma mensagem qualquer marcando o bot (ex: @SeuBot oi). Depois rode este script de novo!")
            return
            
        chats_encontrados = {}
        for item in resultados:
            msg = item.get("message", item.get("my_chat_member", {}))
            chat = msg.get("chat")
            if chat:
                chat_id = chat.get("id")
                nome = chat.get("title") or chat.get("first_name", "Desconhecido")
                tipo = chat.get("type")
                chats_encontrados[chat_id] = f"{nome} (Tipo: {tipo})"
                
        print("\n--- CHATS/GRUPOS ENCONTRADOS ---")
        for cid, desc in chats_encontrados.items():
            print(f"Nome: {desc}")
            print(f"ID para copiar no .env: {cid}")
            print("-" * 30)
            
    except Exception as e:
        # A exceção HTTP pode incluir a URL, que contém o token do bot.
        print(f"Erro ao consultar a API do Telegram ({type(e).__name__}).")

if __name__ == "__main__":
    main()
