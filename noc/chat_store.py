"""
Armazenamento local em SQLite (modo WAL) para conversas do Painel de Investigação NOC.

Salva histórico de sessões, mensagens, modelo utilizado (Hydrogen/Neon),
ferramentas acionadas e consumo de tokens em ``logs/painel_chat.sqlite3``.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from noc.consulta import FUSO

RAIZ = Path(__file__).resolve().parent.parent
CAMINHO_DB_PADRAO = RAIZ / "logs" / "painel_chat.sqlite3"


def _agora_iso() -> str:
    return datetime.now(FUSO).isoformat(timespec="seconds")


class ChatStore:
    """Persistência thread-safe de conversas do painel NOC em SQLite."""

    def __init__(self, caminho: Path | str | None = None):
        self.caminho = Path(caminho) if caminho is not None else CAMINHO_DB_PADRAO
        self.caminho.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._inicializar()

    def _conectar(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.caminho, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _inicializar(self) -> None:
        with self._lock, self._conectar() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS conversas (
                    id TEXT PRIMARY KEY,
                    titulo TEXT NOT NULL,
                    modelo TEXT NOT NULL,
                    criada_em TEXT NOT NULL,
                    atualizada_em TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS mensagens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    conversa_id TEXT NOT NULL,
                    papel TEXT NOT NULL,
                    conteudo TEXT NOT NULL,
                    modelo TEXT NOT NULL DEFAULT '',
                    ferramentas_json TEXT NOT NULL DEFAULT '[]',
                    tokens_json TEXT NOT NULL DEFAULT '{}',
                    criada_em TEXT NOT NULL,
                    FOREIGN KEY (conversa_id) REFERENCES conversas(id) ON DELETE CASCADE
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_mensagens_conversa ON mensagens(conversa_id, id)"
            )
            conn.commit()

    def criar_conversa(self, titulo: str = "Nova verificação", modelo: str = "gemini-4-hydrogen") -> dict[str, Any]:
        cid = uuid.uuid4().hex[:12]
        agora = _agora_iso()
        titulo_limpo = " ".join((titulo or "Nova verificação").split())[:100] or "Nova verificação"
        with self._lock, self._conectar() as conn:
            conn.execute(
                "INSERT INTO conversas (id, titulo, modelo, criada_em, atualizada_em) VALUES (?, ?, ?, ?, ?)",
                (cid, titulo_limpo, modelo, agora, agora),
            )
            conn.commit()
        return {
            "id": cid,
            "titulo": titulo_limpo,
            "modelo": modelo,
            "criada_em": agora,
            "atualizada_em": agora,
            "total_mensagens": 0,
        }

    def listar_conversas(self, busca: str = "", limite: int = 60) -> list[dict[str, Any]]:
        termo = (busca or "").strip().lower()
        with self._lock, self._conectar() as conn:
            if termo:
                like = f"%{termo}%"
                rows = conn.execute(
                    """
                    SELECT c.id, c.titulo, c.modelo, c.criada_em, c.atualizada_em,
                           COUNT(m.id) AS total_mensagens
                    FROM conversas c
                    LEFT JOIN mensagens m ON m.conversa_id = c.id
                    WHERE LOWER(c.titulo) LIKE ?
                       OR EXISTS (
                           SELECT 1 FROM mensagens m2
                           WHERE m2.conversa_id = c.id AND LOWER(m2.conteudo) LIKE ?
                       )
                    GROUP BY c.id
                    ORDER BY c.atualizada_em DESC
                    LIMIT ?
                    """,
                    (like, like, max(1, min(limite, 200))),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT c.id, c.titulo, c.modelo, c.criada_em, c.atualizada_em,
                           COUNT(m.id) AS total_mensagens
                    FROM conversas c
                    LEFT JOIN mensagens m ON m.conversa_id = c.id
                    GROUP BY c.id
                    ORDER BY c.atualizada_em DESC
                    LIMIT ?
                    """,
                    (max(1, min(limite, 200)),),
                ).fetchall()
        return [dict(r) for r in rows]

    def obter_conversa(self, conversa_id: str) -> dict[str, Any] | None:
        with self._lock, self._conectar() as conn:
            row = conn.execute(
                "SELECT id, titulo, modelo, criada_em, atualizada_em FROM conversas WHERE id = ?",
                (conversa_id,),
            ).fetchone()
            if row is None:
                return None
            msgs = conn.execute(
                """
                SELECT id, papel, conteudo, modelo, ferramentas_json, tokens_json, criada_em
                FROM mensagens
                WHERE conversa_id = ?
                ORDER BY id ASC
                """,
                (conversa_id,),
            ).fetchall()

        mensagens = []
        for m in msgs:
            try:
                ferramentas = json.loads(m["ferramentas_json"] or "[]")
            except ValueError:
                ferramentas = []
            try:
                tokens = json.loads(m["tokens_json"] or "{}")
            except ValueError:
                tokens = {}
            mensagens.append({
                "id": m["id"],
                "papel": m["papel"],
                "conteudo": m["conteudo"],
                "modelo": m["modelo"],
                "ferramentas": ferramentas,
                "tokens": tokens,
                "criada_em": m["criada_em"],
            })

        dados = dict(row)
        dados["mensagens"] = mensagens
        return dados

    def atualizar_conversa(
        self,
        conversa_id: str,
        *,
        titulo: str | None = None,
        modelo: str | None = None,
    ) -> bool:
        campos: list[str] = []
        valores: list[Any] = []
        if titulo is not None:
            limpo = " ".join(titulo.split())[:100]
            if limpo:
                campos.append("titulo = ?")
                valores.append(limpo)
        if modelo is not None:
            campos.append("modelo = ?")
            valores.append(modelo)
        if not campos:
            return False
        campos.append("atualizada_em = ?")
        valores.append(_agora_iso())
        valores.append(conversa_id)
        with self._lock, self._conectar() as conn:
            cur = conn.execute(
                f"UPDATE conversas SET {', '.join(campos)} WHERE id = ?",
                valores,
            )
            conn.commit()
            return cur.rowcount > 0

    def excluir_conversa(self, conversa_id: str) -> bool:
        with self._lock, self._conectar() as conn:
            cur = conn.execute("DELETE FROM conversas WHERE id = ?", (conversa_id,))
            conn.commit()
            return cur.rowcount > 0

    def salvar_mensagem(
        self,
        conversa_id: str,
        papel: str,
        conteudo: str,
        *,
        modelo: str = "",
        ferramentas: list[dict[str, Any]] | None = None,
        tokens: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        agora = _agora_iso()
        ferr_json = json.dumps(ferramentas or [], ensure_ascii=False)
        tok_json = json.dumps(tokens or {}, ensure_ascii=False)
        with self._lock, self._conectar() as conn:
            cur = conn.execute(
                """
                INSERT INTO mensagens (conversa_id, papel, conteudo, modelo, ferramentas_json, tokens_json, criada_em)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (conversa_id, papel, conteudo, modelo, ferr_json, tok_json, agora),
            )
            msg_id = cur.lastrowid
            if modelo:
                conn.execute(
                    "UPDATE conversas SET atualizada_em = ?, modelo = ? WHERE id = ?",
                    (agora, modelo, conversa_id),
                )
            else:
                conn.execute(
                    "UPDATE conversas SET atualizada_em = ? WHERE id = ?",
                    (agora, conversa_id),
                )
            conn.commit()
        return {
            "id": msg_id,
            "papel": papel,
            "conteudo": conteudo,
            "modelo": modelo,
            "ferramentas": ferramentas or [],
            "tokens": tokens or {},
            "criada_em": agora,
        }
