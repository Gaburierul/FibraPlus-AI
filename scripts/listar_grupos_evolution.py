"""
Lista os grupos da instância da Evolution API para descobrir o JID do grupo do NOC.

Uso:  python scripts/listar_grupos_evolution.py
Copie o "id" do grupo desejado (termina em @g.us) para EVOLUTION_GROUP_JID no .env.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dotenv import load_dotenv  # noqa: E402

load_dotenv()

from clients.whatsapp import EvolutionClient, EvolutionErro  # noqa: E402


def main() -> int:
    try:
        grupos = EvolutionClient().listar_grupos()
    except EvolutionErro as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 1
    if not grupos:
        print("Nenhum grupo encontrado nesta instância.")
        return 0
    for g in grupos:
        print(f"{g.get('id', '?'):40}  {g.get('subject', '(sem nome)')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
