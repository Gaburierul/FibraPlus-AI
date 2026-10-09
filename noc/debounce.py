"""
Fila de agrupamento (debounce) de alertas.

Problema: quando um equipamento de borda cai, o Zabbix dispara dezenas de
alertas em poucos segundos. Chamar a IA para cada um estoura cota e inunda o
grupo do WhatsApp.

Solução: o primeiro alerta abre um lote. Enquanto continuarem chegando alertas,
o lote fica aberto. Ele é fechado e processado quando:
  * passam `silencio_s` segundos sem nenhum alerta novo, OU
  * o lote completa `espera_max_s` segundos desde o primeiro alerta
    (evita que uma tempestade contínua atrase o aviso indefinidamente).

Enquanto um lote está sendo analisado, alertas novos já abrem o lote seguinte.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Hashable

from noc.parser import Alerta

log = logging.getLogger("noc.debounce")

ProcessarLote = Callable[[list[Alerta]], Awaitable[None]]


@dataclass
class _Lote:
    aberto_em: float
    ultimo_em: float
    alertas: list[Alerta] = field(default_factory=list)
    vistos: set[Hashable] = field(default_factory=set)


class AgrupadorAlertas:
    def __init__(self, processar: ProcessarLote, silencio_s: float = 45, espera_max_s: float = 180,
                 max_alertas: int = 500, nome: str = "alertas"):
        if silencio_s <= 0 or espera_max_s < silencio_s:
            raise ValueError("exige 0 < silencio_s <= espera_max_s")
        self._processar = processar
        self.silencio_s = silencio_s
        self.espera_max_s = espera_max_s
        self.max_alertas = max_alertas
        self.nome = nome
        self._lote: _Lote | None = None
        self._tarefa: asyncio.Task | None = None
        self._lock = asyncio.Lock()
        self._em_processamento: set[asyncio.Task] = set()

    @property
    def pendentes(self) -> int:
        return len(self._lote.alertas) if self._lote else 0

    async def adicionar(self, alerta: Alerta, chave: Hashable | None = None) -> bool:
        """Coloca o alerta no lote atual. Retorna False se for duplicata dentro do lote."""
        async with self._lock:
            agora = time.monotonic()
            if self._lote is None:
                self._lote = _Lote(aberto_em=agora, ultimo_em=agora)
                self._tarefa = asyncio.create_task(self._vigiar())
                log.info("Novo lote aberto | origem=%s", self.nome)
            lote = self._lote
            if chave is not None:
                if chave in lote.vistos:
                    return False
                lote.vistos.add(chave)
            lote.alertas.append(alerta)
            lote.ultimo_em = agora
            if len(lote.alertas) >= self.max_alertas:
                log.warning("Lote origem=%s atingiu %d alertas; fechando antecipadamente",
                            self.nome, self.max_alertas)
                self._fechar_lote_sem_lock()
            return True

    async def _vigiar(self) -> None:
        """Dorme até o lote ficar em silêncio ou estourar o tempo máximo."""
        try:
            while True:
                async with self._lock:
                    lote = self._lote
                    if lote is None:
                        return
                    agora = time.monotonic()
                    prazo = min(lote.ultimo_em + self.silencio_s, lote.aberto_em + self.espera_max_s)
                    if agora >= prazo:
                        self._fechar_lote_sem_lock()
                        return
                await asyncio.sleep(max(0.05, prazo - agora))
        except asyncio.CancelledError:
            pass

    def _fechar_lote_sem_lock(self) -> None:
        lote, self._lote = self._lote, None
        tarefa_vigia, self._tarefa = self._tarefa, None
        if tarefa_vigia and tarefa_vigia is not asyncio.current_task():
            tarefa_vigia.cancel()
        if not lote or not lote.alertas:
            return
        duracao = time.monotonic() - lote.aberto_em
        log.info("Lote fechado | origem=%s | %d alerta(s) em %.0fs",
                 self.nome, len(lote.alertas), duracao)
        tarefa = asyncio.create_task(self._executar(lote.alertas))
        self._em_processamento.add(tarefa)
        tarefa.add_done_callback(self._em_processamento.discard)

    async def _executar(self, alertas: list[Alerta]) -> None:
        try:
            await self._processar(alertas)
        except Exception:  # noqa: BLE001 — um lote com erro não pode derrubar o servidor
            log.exception("Falha ao processar lote origem=%s com %d alerta(s)",
                          self.nome, len(alertas))

    async def descarregar(self) -> None:
        """Fecha o lote atual imediatamente e espera todo processamento terminar (desligamento)."""
        async with self._lock:
            self._fechar_lote_sem_lock()
        if self._em_processamento:
            await asyncio.gather(*self._em_processamento, return_exceptions=True)

