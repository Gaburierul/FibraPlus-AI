/* FibraPlus NOC — Painel de Investigação (Vanilla JS, zero build) */
(function () {
  "use strict";

  const state = {
    conversaId: null,
    modelo: "gemini-4-hydrogen",
    conversas: [],
    streaming: false,
    abortCtrl: null,
    quickMode: null,
    quickPromptContext: "",
  };

  const el = {
    sidebar: document.getElementById("sidebar"),
    backdrop: document.getElementById("sidebar-backdrop"),
    btnMenuMobile: document.getElementById("btn-menu-mobile"),
    btnNovaConversa: document.getElementById("btn-nova-conversa"),
    btnTema: document.getElementById("btn-tema"),
    buscaConversas: document.getElementById("busca-conversas"),
    listaConversas: document.getElementById("lista-conversas"),
    historyCount: document.getElementById("history-count"),
    tituloAtivo: document.getElementById("titulo-ativo"),
    statusIntegracoes: document.getElementById("status-integracoes"),
    chatFeed: document.getElementById("chat-feed"),
    emptyState: document.getElementById("empty-state"),
    messagesContainer: document.getElementById("messages-container"),
    formChat: document.getElementById("form-chat"),
    inputMensagem: document.getElementById("input-mensagem"),
    composerMeta: document.getElementById("composer-meta"),
    btnEnviar: document.getElementById("btn-enviar"),
    btnCancelar: document.getElementById("btn-cancelar"),
    quickPanel: document.getElementById("quick-panel"),
    quickPanelTitle: document.getElementById("quick-panel-title"),
    quickPanelSub: document.getElementById("quick-panel-sub"),
    quickPanelControls: document.getElementById("quick-panel-controls"),
    quickPanelBody: document.getElementById("quick-panel-body"),
    btnFecharQuick: document.getElementById("btn-fechar-quick"),
    btnQuickEnviarChat: document.getElementById("btn-quick-enviar-chat"),
    btnAbrirConsumo: document.getElementById("btn-abrir-consumo"),
    sidebarCostVal: document.getElementById("sidebar-cost-val"),
  };

  /* ---------------------------------------------------------------------- */
  /* Utilitários seguros                                                    */
  /* ---------------------------------------------------------------------- */

  function esc(str) {
    return String(str == null ? "" : str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function nomeModeloCurto(id) {
    if (!id) return "Hydrogen";
    if (id.includes("neon")) return "Neon";
    if (id.includes("hydrogen")) return "Hydrogen";
    return id;
  }

  function fmtBrl(valor) {
    const num = Number(valor || 0);
    return "R$ " + num.toLocaleString("pt-BR", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  }

  function fmtDataCurta(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return String(iso).slice(0, 16);
    const pad = (n) => String(n).padStart(2, "0");
    return `${pad(d.getDate())}/${pad(d.getMonth() + 1)} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  function scrollToBottom() {
    el.chatFeed.scrollTop = el.chatFeed.scrollHeight;
  }

  /* Renderizador Markdown seguro (com escape prévio de HTML e suporte a tabelas) */
  function renderMarkdown(raw) {
    const texto = String(raw || "").replace(/\r\n/g, "\n");
    const codeBlocks = [];
    const semBlocos = texto.replace(/```([a-zA-Z0-9_-]*)\n([\s\S]*?)```/g, (_, _lang, code) => {
      const idx = codeBlocks.length;
      codeBlocks.push(`<pre><code>${esc(code.replace(/\n$/, ""))}</code></pre>`);
      return `\u0000CODEBLOCK_${idx}\u0000`;
    });

    function inline(s) {
      let out = esc(s);
      out = out.replace(/`([^`]+)`/g, "<code>$1</code>");
      out = out.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
      out = out.replace(/(^|[\s(])\*([^*\n]+)\*(?=[\s).,;:]|$)/g, "$1<em>$2</em>");
      return out;
    }

    const lines = semBlocos.split("\n");
    const html = [];
    let i = 0;

    while (i < lines.length) {
      const line = lines[i];
      const trim = line.trim();

      if (!trim) {
        i++;
        continue;
      }

      if (/^\u0000CODEBLOCK_\d+\u0000$/.test(trim)) {
        const idx = Number(trim.match(/\d+/)[0]);
        html.push(codeBlocks[idx]);
        i++;
        continue;
      }

      // Cabeçalhos
      const hm = trim.match(/^(#{1,4})\s+(.+)$/);
      if (hm) {
        const lvl = hm[1].length;
        html.push(`<h${lvl}>${inline(hm[2])}</h${lvl}>`);
        i++;
        continue;
      }

      // Tabela Markdown
      if (trim.includes("|") && i + 1 < lines.length && /^\s*\|?[\s:-]+\|[\s|:-]*$/.test(lines[i + 1])) {
        const parseRow = (r) =>
          r.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim());
        const headers = parseRow(line);
        i += 2;
        const rows = [];
        while (i < lines.length && lines[i].trim().includes("|") && !lines[i].trim().startsWith("#")) {
          rows.push(parseRow(lines[i]));
          i++;
        }
        const th = headers.map((h) => `<th>${inline(h)}</th>`).join("");
        const trs = rows
          .map((r) => `<tr>${headers.map((_, ci) => `<td>${inline(r[ci] || "")}</td>`).join("")}</tr>`)
          .join("");
        html.push(`<div class="table-wrap"><table class="noc-table"><thead><tr>${th}</tr></thead><tbody>${trs}</tbody></table></div>`);
        continue;
      }

      // Citação
      if (trim.startsWith(">")) {
        const qLines = [];
        while (i < lines.length && lines[i].trim().startsWith(">")) {
          qLines.push(inline(lines[i].trim().replace(/^>\s?/, "")));
          i++;
        }
        html.push(`<blockquote>${qLines.join("<br />")}</blockquote>`);
        continue;
      }

      // Lista não ordenada
      if (/^[-*•]\s+/.test(trim)) {
        const items = [];
        while (i < lines.length && /^\s*[-*•]\s+/.test(lines[i])) {
          items.push(`<li>${inline(lines[i].trim().replace(/^[-*•]\s+/, ""))}</li>`);
          i++;
        }
        html.push(`<ul>${items.join("")}</ul>`);
        continue;
      }

      // Lista ordenada
      if (/^\d+\.\s+/.test(trim)) {
        const items = [];
        while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) {
          items.push(`<li>${inline(lines[i].trim().replace(/^\d+\.\s+/, ""))}</li>`);
          i++;
        }
        html.push(`<ol>${items.join("")}</ol>`);
        continue;
      }

      // Parágrafo
      const pLines = [];
      while (
        i < lines.length &&
        lines[i].trim() &&
        !/^(#{1,4})\s+/.test(lines[i].trim()) &&
        !/^[-*•]\s+/.test(lines[i].trim()) &&
        !/^\d+\.\s+/.test(lines[i].trim()) &&
        !lines[i].trim().startsWith(">") &&
        !/^\u0000CODEBLOCK_\d+\u0000$/.test(lines[i].trim())
      ) {
        pLines.push(inline(lines[i].trim()));
        i++;
      }
      html.push(`<p>${pLines.join("<br />")}</p>`);
    }

    return html.join("\n");
  }

  /* ---------------------------------------------------------------------- */
  /* Tema Claro / Escuro & Seletor de Modelo                                */
  /* ---------------------------------------------------------------------- */

  function alternarTema() {
    const atual = document.documentElement.getAttribute("data-theme") || "light";
    const proximo = atual === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", proximo);
    localStorage.setItem("noc_theme", proximo);
  }

  function definirModelo(modelId) {
    state.modelo = modelId;
    document.querySelectorAll(".model-opt").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.model === modelId);
    });
    const perfil = modelId.includes("neon")
      ? "Neon (raciocínio profundo)"
      : "Hydrogen (rápido e equilibrado)";
    el.composerMeta.textContent = `Modelo ativo: ${perfil}`;
  }

  /* ---------------------------------------------------------------------- */
  /* API de Configuração & Conversas                                        */
  /* ---------------------------------------------------------------------- */

  async function carregarConfig() {
    try {
      const resp = await fetch("/api/config");
      if (!resp.ok) return;
      const cfg = await resp.json();
      if (cfg.modelo_padrao) definirModelo(cfg.modelo_padrao);
      const integ = cfg.integracoes || {};
      const nomes = [
        ["zabbix", "Zabbix"],
        ["ixc", "IXC"],
        ["ravicor", "Ravicor"],
      ];
      el.statusIntegracoes.innerHTML = nomes
        .map(
          ([k, label]) =>
            `<span class="status-pill ${integ[k] ? "ok" : "off"}"><span class="dot"></span>${label}</span>`
        )
        .join("");
    } catch (_) {
      // Silencioso no boot
    }
  }

  async function carregarConversas(busca = "") {
    const url = busca ? `/api/conversas?busca=${encodeURIComponent(busca)}` : "/api/conversas";
    const resp = await fetch(url);
    if (!resp.ok) return;
    const data = await resp.json();
    state.conversas = data.conversas || [];
    el.historyCount.textContent = String(state.conversas.length);
    renderListaConversas();
  }

  function renderListaConversas() {
    if (!state.conversas.length) {
      el.listaConversas.innerHTML =
        `<li style="padding:10px 6px;font-size:12px;color:var(--text-muted);">Nenhuma verificação salva ainda.</li>`;
      return;
    }
    el.listaConversas.innerHTML = state.conversas
      .map(
        (c) => `
      <li class="conv-item ${c.id === state.conversaId ? "active" : ""}" data-id="${esc(c.id)}">
        <div class="conv-info">
          <span class="conv-title" title="${esc(c.titulo)}">${esc(c.titulo)}</span>
          <span class="conv-meta">
            <span>${esc(nomeModeloCurto(c.modelo))}</span>
            <span>·</span>
            <span>${esc(fmtDataCurta(c.atualizada_em))}</span>
          </span>
        </div>
        <button class="conv-del" data-del="${esc(c.id)}" type="button" title="Excluir conversa" aria-label="Excluir conversa">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
        </button>
      </li>`
      )
      .join("");
  }

  async function abrirConversa(conversaId) {
    const resp = await fetch(`/api/conversas/${encodeURIComponent(conversaId)}`);
    if (!resp.ok) return;
    const conv = await resp.json();
    state.conversaId = conv.id;
    el.tituloAtivo.textContent = conv.titulo || "Verificação NOC";
    if (conv.modelo) definirModelo(conv.modelo);
    renderMensagens(conv.mensagens || []);
    renderListaConversas();
    fecharSidebarMobile();
  }

  function novaVerificacao() {
    state.conversaId = null;
    el.tituloAtivo.textContent = "Nova verificação";
    el.messagesContainer.innerHTML = "";
    el.emptyState.classList.remove("hidden");
    renderListaConversas();
    el.inputMensagem.focus();
    fecharSidebarMobile();
  }

  async function excluirConversa(conversaId) {
    const resp = await fetch(`/api/conversas/${encodeURIComponent(conversaId)}`, { method: "DELETE" });
    if (!resp.ok) return;
    if (state.conversaId === conversaId) {
      novaVerificacao();
    }
    await carregarConversas(el.buscaConversas.value);
  }

  /* ---------------------------------------------------------------------- */
  /* Renderização de Mensagens e Streaming SSE                              */
  /* ---------------------------------------------------------------------- */

  function criarHtmlFerramentas(ferramentas, aberto) {
    if (!ferramentas || !ferramentas.length) return "";
    const qtd = ferramentas.length;
    const rotuloQtd = qtd === 1 ? "1 consulta executada" : `${qtd} consultas executadas`;
    const itens = ferramentas
      .map((f) => {
        const cls = f.running ? "running" : f.ok === false ? "err" : "ok";
        const ms = f.duracao_ms != null ? `${f.duracao_ms} ms` : "";
        return `
        <div class="tool-step">
          <div class="tool-step-left">
            <span class="tool-dot ${cls}"></span>
            <span class="tool-name">${esc(f.rotulo || f.nome)}</span>
            <span class="tool-summary">${esc(f.resumo || "")}</span>
          </div>
          <span class="tool-ms">${esc(ms)}</span>
        </div>`;
      })
      .join("");
    return `
      <details class="tools-accordion" ${aberto ? "open" : ""}>
        <summary>
          <span>Etapas de consulta (${esc(rotuloQtd)})</span>
          <span style="font-size:11px;color:var(--text-muted);">Expandir / recolher</span>
        </summary>
        <div class="tools-list">${itens}</div>
      </details>`;
  }

  function criarCardMensagem(msg) {
    const card = document.createElement("article");
    card.className = `msg-card ${msg.papel === "user" ? "user" : "assistant"}`;
    const autor = msg.papel === "user" ? "Analista NOC" : "Verificação NOC";
    const chip = msg.papel === "assistant" && msg.modelo
      ? `<span class="model-chip">${esc(nomeModeloCurto(msg.modelo))}</span>`
      : "";
    const copyBtn = msg.papel === "assistant"
      ? `<button class="btn-copy-md" type="button">Copiar</button>`
      : "";
    const ferrHtml = msg.papel === "assistant" ? criarHtmlFerramentas(msg.ferramentas, false) : "";
    const tok = msg.tokens || {};
    const custo = msg.custo_estimado || null;
    const custoTxt = custo && typeof custo.brl === "number"
      ? `<span>Custo est.: ${esc(fmtBrl(custo.brl))}</span>`
      : "";
    const thoughtTxt = tok.total_thought_tokens
      ? ` · raciocínio ${esc(tok.total_thought_tokens)}`
      : "";
    const footerHtml =
      msg.papel === "assistant" && tok.total_tokens
        ? `<div class="msg-footer">
             <span>Modelo: ${esc(msg.modelo || state.modelo)}</span>
             <span>Tokens: ${esc(tok.total_tokens)} (entrada ${esc(tok.total_input_tokens || 0)} · saída ${esc(tok.total_output_tokens || 0)}${thoughtTxt})</span>
             ${custoTxt}
           </div>`
        : "";

    card.innerHTML = `
      <div class="msg-header">
        <div class="msg-author"><span>${autor}</span>${chip}</div>
        <div class="msg-actions">
          <span>${esc(fmtDataCurta(msg.criada_em))}</span>
          ${copyBtn}
        </div>
      </div>
      ${ferrHtml}
      <div class="md-body">${msg.papel === "user" ? `<p>${esc(msg.conteudo).replace(/\n/g, "<br />")}</p>` : renderMarkdown(msg.conteudo)}</div>
      ${footerHtml}
    `;

    const btnCopy = card.querySelector(".btn-copy-md");
    if (btnCopy) {
      btnCopy.addEventListener("click", () => {
        navigator.clipboard.writeText(msg.conteudo || "").then(() => {
          btnCopy.textContent = "Copiado";
          setTimeout(() => (btnCopy.textContent = "Copiar"), 1500);
        });
      });
    }
    return card;
  }

  function renderMensagens(mensagens) {
    el.messagesContainer.innerHTML = "";
    if (!mensagens.length) {
      el.emptyState.classList.remove("hidden");
      return;
    }
    el.emptyState.classList.add("hidden");
    mensagens.forEach((m) => el.messagesContainer.appendChild(criarCardMensagem(m)));
    scrollToBottom();
  }

  async function enviarPergunta(textoBruto) {
    const pergunta = (textoBruto || "").trim();
    if (!pergunta || state.streaming) return;

    fecharQuickPanel();
    el.emptyState.classList.add("hidden");

    // Cria conversa no SQLite se for a primeira mensagem
    if (!state.conversaId) {
      const respCria = await fetch("/api/conversas", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ titulo: "Nova verificação", modelo: state.modelo }),
      });
      if (!respCria.ok) return;
      const nova = await respCria.json();
      state.conversaId = nova.id;
    }

    // Exibe mensagem do analista
    el.messagesContainer.appendChild(
      criarCardMensagem({ papel: "user", conteudo: pergunta, criada_em: new Date().toISOString() })
    );

    // Cria card vivo da resposta
    const card = document.createElement("article");
    card.className = "msg-card assistant";
    card.innerHTML = `
      <div class="msg-header">
        <div class="msg-author">
          <span>Verificação NOC</span>
          <span class="model-chip">${esc(nomeModeloCurto(state.modelo))}</span>
        </div>
        <div class="msg-actions">
          <button class="btn-copy-md hidden" type="button">Copiar</button>
        </div>
      </div>
      <div class="live-status"><span class="spinner"></span><span class="live-status-text">Iniciando investigação...</span></div>
      <div class="live-tools-slot"></div>
      <details class="thought-box hidden"><summary>Resumo do raciocínio</summary><div class="thought-content"></div></details>
      <div class="md-body"></div>
      <div class="msg-footer hidden"></div>
    `;
    el.messagesContainer.appendChild(card);
    scrollToBottom();

    const statusEl = card.querySelector(".live-status");
    const statusTextEl = card.querySelector(".live-status-text");
    const toolsSlot = card.querySelector(".live-tools-slot");
    const thoughtBox = card.querySelector(".thought-box");
    const thoughtContent = card.querySelector(".thought-content");
    const mdBody = card.querySelector(".md-body");
    const footerEl = card.querySelector(".msg-footer");
    const copyBtn = card.querySelector(".btn-copy-md");

    const ferramentasAtivas = [];
    let textoAcumulado = "";
    let pensamentoAcumulado = "";

    state.streaming = true;
    state.abortCtrl = new AbortController();
    el.btnEnviar.disabled = true;
    el.btnCancelar.classList.remove("hidden");
    el.inputMensagem.value = "";
    ajustarAlturaTextarea();

    try {
      const resp = await fetch(`/api/conversas/${encodeURIComponent(state.conversaId)}/mensagens`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ conteudo: pergunta, modelo: state.modelo }),
        signal: state.abortCtrl.signal,
      });

      if (!resp.ok) {
        const errData = await resp.json().catch(() => ({}));
        throw new Error(errData.detail || `Erro HTTP ${resp.status}`);
      }

      const reader = resp.body.getReader();
      const decoder = new TextDecoder("utf-8");
      let buffer = "";

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const blocos = buffer.split("\n\n");
        buffer = blocos.pop() || "";

        for (const bloco of blocos) {
          const linhas = bloco.split("\n").filter((l) => l.startsWith("data:"));
          for (const linha of linhas) {
            const payload = linha.slice(5).trim();
            if (!payload || payload === "[DONE]") continue;
            let ev;
            try {
              ev = JSON.parse(payload);
            } catch (_) {
              continue;
            }

            if (ev.tipo === "titulo" && ev.titulo) {
              el.tituloAtivo.textContent = ev.titulo;
            } else if (ev.tipo === "status") {
              statusTextEl.textContent = ev.texto || "Processando...";
            } else if (ev.tipo === "pensamento") {
              pensamentoAcumulado += ev.texto || "";
              thoughtBox.classList.remove("hidden");
              thoughtContent.textContent = pensamentoAcumulado;
            } else if (ev.tipo === "ferramenta_inicio") {
              ferramentasAtivas.push({
                call_id: ev.call_id || "",
                nome: ev.nome,
                rotulo: ev.rotulo,
                resumo: "consultando...",
                running: true,
              });
              statusTextEl.textContent = `${ev.rotulo || ev.nome}...`;
              toolsSlot.innerHTML = criarHtmlFerramentas(ferramentasAtivas, true);
              scrollToBottom();
            } else if (ev.tipo === "ferramenta_fim") {
              const alvo =
                (ev.call_id && ferramentasAtivas.find((f) => f.call_id === ev.call_id)) ||
                ferramentasAtivas.find((f) => f.nome === ev.nome && f.running);
              if (alvo) {
                alvo.running = false;
                alvo.ok = ev.ok;
                alvo.resumo = ev.resumo;
                alvo.duracao_ms = ev.duracao_ms;
              }
              toolsSlot.innerHTML = criarHtmlFerramentas(ferramentasAtivas, true);
              scrollToBottom();
            } else if (ev.tipo === "texto") {
              textoAcumulado += ev.delta || "";
              statusEl.classList.add("hidden");
              mdBody.innerHTML = renderMarkdown(textoAcumulado);
              scrollToBottom();
            } else if (ev.tipo === "concluido") {
              statusEl.classList.add("hidden");
              if (ev.texto_completo) {
                textoAcumulado = ev.texto_completo;
                mdBody.innerHTML = renderMarkdown(textoAcumulado);
              }
              if (ferramentasAtivas.length) {
                toolsSlot.innerHTML = criarHtmlFerramentas(ferramentasAtivas, false);
              }
              if (ev.tokens && ev.tokens.total_tokens) {
                footerEl.classList.remove("hidden");
                const custoSpan = ev.custo_estimado && typeof ev.custo_estimado.brl === "number"
                  ? `<span>Custo est.: ${esc(fmtBrl(ev.custo_estimado.brl))}</span>`
                  : "";
                const thoughtSpan = ev.tokens.total_thought_tokens
                  ? ` · raciocínio ${esc(ev.tokens.total_thought_tokens)}`
                  : "";
                footerEl.innerHTML = `
                  <span>Modelo: ${esc(ev.modelo || state.modelo)}</span>
                  <span>Tokens: ${esc(ev.tokens.total_tokens)} (entrada ${esc(ev.tokens.total_input_tokens || 0)} · saída ${esc(ev.tokens.total_output_tokens || 0)}${thoughtSpan})</span>
                  ${custoSpan}`;
              }
              copyBtn.classList.remove("hidden");
              copyBtn.onclick = () => {
                navigator.clipboard.writeText(textoAcumulado).then(() => {
                  copyBtn.textContent = "Copiado";
                  setTimeout(() => (copyBtn.textContent = "Copiar"), 1500);
                });
              };
            } else if (ev.tipo === "erro") {
              statusEl.classList.add("hidden");
              mdBody.innerHTML = `<div class="error-banner">${esc(ev.mensagem || "Erro ao processar solicitação.")}</div>`;
            }
          }
        }
      }
    } catch (err) {
      statusEl.classList.add("hidden");
      if (err.name === "AbortError") {
        mdBody.innerHTML += `<p style="color:var(--text-muted);font-size:12.5px;"><em>Investigação interrompida pelo analista.</em></p>`;
      } else {
        mdBody.innerHTML = `<div class="error-banner">${esc(err.message || "Falha de comunicação com o painel local.")}</div>`;
      }
    } finally {
      state.streaming = false;
      state.abortCtrl = null;
      el.btnEnviar.disabled = false;
      el.btnCancelar.classList.add("hidden");
      await carregarConversas(el.buscaConversas.value);
      carregarResumoConsumoBarra();
      scrollToBottom();
    }
  }

  /* ---------------------------------------------------------------------- */
  /* Painel de Consultas Rápidas (0 tokens de IA)                           */
  /* ---------------------------------------------------------------------- */

  function fecharQuickPanel() {
    el.quickPanel.classList.add("hidden");
    state.quickMode = null;
    document.querySelectorAll(".quick-btn, .cost-pill-btn").forEach((b) => b.classList.remove("active"));
  }

  function abrirQuickPanel(modo) {
    state.quickMode = modo;
    state.quickPromptContext = "";
    el.quickPanel.classList.remove("hidden");
    el.btnQuickEnviarChat.classList.toggle("hidden", modo === "consumo");
    document.querySelectorAll(".quick-btn, .cost-pill-btn").forEach((b) => {
      b.classList.toggle("active", b.dataset.quick === modo);
    });
    fecharSidebarMobile();

    if (modo === "consumo") {
      el.quickPanelTitle.textContent = "Consumo estimado de créditos Gemini (R$)";
      el.quickPanelSub.textContent = "Cálculo em tempo real a partir dos tokens gravados em logs/envios.jsonl e no histórico local do painel.";
      el.quickPanelControls.innerHTML = `<button class="btn-primary btn-sm" id="q-consumo-go" type="button">Atualizar</button>`;
      document.getElementById("q-consumo-go").onclick = () => executarQuickConsumo();
      executarQuickConsumo();
    } else if (modo === "infra") {
      el.quickPanelTitle.textContent = "Problemas ativos de infraestrutura (Zabbix)";
      el.quickPanelSub.textContent = "Leitura direta em tempo real, sem consumo de IA.";
      el.quickPanelControls.innerHTML = `
        <input class="quick-input" id="q-infra-termo" placeholder="Filtrar por cidade, host ou protocolo (opcional)..." />
        <select class="quick-select" id="q-infra-escopo">
          <option value="infra" selected>Somente infraestrutura</option>
          <option value="clientes">Somente clientes / ONUs</option>
          <option value="todos">Todos</option>
        </select>
        <button class="btn-primary btn-sm" id="q-infra-go" type="button">Atualizar</button>`;
      document.getElementById("q-infra-go").onclick = () => executarQuickInfra();
      document.getElementById("q-infra-termo").onkeydown = (e) => {
        if (e.key === "Enter") executarQuickInfra();
      };
      executarQuickInfra();
    } else if (modo === "saude") {
      el.quickPanelTitle.textContent = "Saúde operacional do NOC";
      el.quickPanelSub.textContent = "Conectividade Zabbix/IXC e últimos lotes do servidor webhook.";
      el.quickPanelControls.innerHTML = `<button class="btn-primary btn-sm" id="q-saude-go" type="button">Testar novamente</button>`;
      document.getElementById("q-saude-go").onclick = () => executarQuickSaude();
      executarQuickSaude();
    } else if (modo === "ixc") {
      el.quickPanelTitle.textContent = "Diagnóstico direto no IXC Provedor";
      el.quickPanelSub.textContent = "Busca sanitizada (LGPD) por login PPPoE, MAC, serial de ONU, IP ou #id_cliente + radacct.";
      el.quickPanelControls.innerHTML = `
        <input class="quick-input" id="q-ixc-termo" placeholder="Ex.: login_cliente, ZTEG..., 100.80.x.x ou #12345" />
        <button class="btn-primary btn-sm" id="q-ixc-go" type="button">Consultar IXC</button>`;
      el.quickPanelBody.innerHTML = `<p style="color:var(--text-muted);margin:0;">Informe um login, MAC, serial da ONU, IP ou <code>#id_cliente</code> acima e clique em <strong>Consultar IXC</strong>.</p>`;
      const inp = document.getElementById("q-ixc-termo");
      document.getElementById("q-ixc-go").onclick = () => executarQuickIxc(inp.value);
      inp.onkeydown = (e) => {
        if (e.key === "Enter") executarQuickIxc(inp.value);
      };
      inp.focus();
    } else if (modo === "olt") {
      el.quickPanelTitle.textContent = "Saúde PON a PON de OLT (Zabbix)";
      el.quickPanelSub.textContent = "Consolida ONUs provisionadas, online, LOSS (-80) e DyingGasp (-90) por porta PON.";
      el.quickPanelControls.innerHTML = `
        <select class="quick-select" id="q-olt-select"><option value="">Carregando OLTs do Zabbix...</option></select>
        <input class="quick-input" id="q-olt-input" placeholder="Ou digite o nome da OLT..." />
        <button class="btn-primary btn-sm" id="q-olt-go" type="button">Analisar OLT</button>`;
      el.quickPanelBody.innerHTML = `<p style="color:var(--text-muted);margin:0;">Selecione uma OLT na lista ou informe o nome do equipamento.</p>`;
      carregarListaOlts();
      const sel = document.getElementById("q-olt-select");
      const inp = document.getElementById("q-olt-input");
      document.getElementById("q-olt-go").onclick = () => executarQuickOlt(inp.value || sel.value);
      sel.onchange = () => {
        if (sel.value) {
          inp.value = sel.value;
          executarQuickOlt(sel.value);
        }
      };
    }
  }

  async function executarQuickInfra() {
    const termo = (document.getElementById("q-infra-termo")?.value || "").trim();
    const escopo = document.getElementById("q-infra-escopo")?.value || "infra";
    el.quickPanelBody.innerHTML = `<div class="live-status"><span class="spinner"></span>Consultando Zabbix...</div>`;
    try {
      const resp = await fetch(`/api/rapido/infra-ativa?escopo=${encodeURIComponent(escopo)}&termo=${encodeURIComponent(termo)}`);
      const d = await resp.json();
      if (!d.ok) throw new Error(d.erro || "Falha ao consultar Zabbix");
      const probs = d.problemas || [];
      state.quickPromptContext = `Analise os problemas ativos no Zabbix (escopo=${escopo}${termo ? `, filtro=${termo}` : ""}) e identifique prioridades e possíveis causas raízes.`;

      const sevBadge = (n, txt) => {
        if (n >= 4) return `<span class="badge badge-danger">${esc(txt)}</span>`;
        if (n === 3) return `<span class="badge badge-warn">${esc(txt)}</span>`;
        return `<span class="badge badge-neutral">${esc(txt)}</span>`;
      };

      const rows = probs.length
        ? probs
            .map(
              (p) => `<tr>
                <td>${sevBadge(p.severidade_num, p.severidade)}</td>
                <td class="mono">${esc(p.host)}</td>
                <td>${esc(p.problema)}</td>
                <td class="mono">${esc(p.desde)}</td>
              </tr>`
            )
            .join("")
        : `<tr><td colspan="4" style="color:var(--ok);font-weight:600;">Nenhum problema ativo para este filtro.</td></tr>`;

      el.quickPanelBody.innerHTML = `
        <div class="kpi-row">
          <div class="kpi-card"><span class="kpi-label">Infra ativa</span><span class="kpi-val">${esc(d.total_infra)}</span></div>
          <div class="kpi-card"><span class="kpi-label">Clientes / ONUs</span><span class="kpi-val">${esc(d.total_clientes)}</span></div>
          <div class="kpi-card"><span class="kpi-label">Atualizado</span><span class="kpi-val" style="font-size:13px;">${esc(d.consulta_em)}</span></div>
        </div>
        <div class="table-wrap">
          <table class="noc-table">
            <thead><tr><th>Severidade</th><th>Equipamento</th><th>Problema</th><th>Desde</th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>`;
    } catch (err) {
      el.quickPanelBody.innerHTML = `<div class="error-banner">${esc(err.message)}</div>`;
    }
  }

  async function executarQuickSaude() {
    el.quickPanelBody.innerHTML = `<div class="live-status"><span class="spinner"></span>Testando APIs e lendo logs...</div>`;
    try {
      const resp = await fetch("/api/rapido/saude?testar_apis=true");
      const d = await resp.json();
      const apis = d.conectividade_apis || {};
      const zbx = apis.zabbix || {};
      const ixc = apis.ixc || {};
      state.quickPromptContext = "Verifique a saúde geral do NOC, conectividade das APIs e os últimos envios do webhook.";

      const envios = (d.envios_recentes || []).slice().reverse();
      const rows = envios.length
        ? envios
            .map(
              (e) => `<tr>
                <td class="mono">${esc(e.quando || "-")}</td>
                <td>${esc((e.origens || []).join("/") || "-")}</td>
                <td class="mono">${esc(e.alertas ?? 0)}</td>
                <td>${esc(e.acao || "-")}</td>
                <td>${esc(e.origem || "-")}</td>
              </tr>`
            )
            .join("")
        : `<tr><td colspan="5">Nenhum registro recente em logs/envios.jsonl.</td></tr>`;

      el.quickPanelBody.innerHTML = `
        <div class="kpi-row">
          <div class="kpi-card">
            <span class="kpi-label">API Zabbix</span>
            <span class="kpi-val" style="font-size:14px;">${zbx.ok ? `<span class="badge badge-ok">Online · ${zbx.latencia_ms} ms</span>` : `<span class="badge badge-danger">Indisponível</span>`}</span>
          </div>
          <div class="kpi-card">
            <span class="kpi-label">API IXC (Leitura)</span>
            <span class="kpi-val" style="font-size:14px;">${ixc.ok ? `<span class="badge badge-ok">Online · ${ixc.latencia_ms} ms</span>` : `<span class="badge badge-danger">Indisponível</span>`}</span>
          </div>
        </div>
        <div class="table-wrap">
          <table class="noc-table">
            <thead><tr><th>Data / Hora</th><th>Origem</th><th>Alertas</th><th>Ação</th><th>Análise</th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>`;
    } catch (err) {
      el.quickPanelBody.innerHTML = `<div class="error-banner">${esc(err.message)}</div>`;
    }
  }

  async function executarQuickIxc(termoBruto) {
    const termo = (termoBruto || "").trim();
    if (!termo) return;
    el.quickPanelBody.innerHTML = `<div class="live-status"><span class="spinner"></span>Consultando IXC Provedor (${esc(termo)})...</div>`;
    try {
      const resp = await fetch(`/api/rapido/ixc?termo=${encodeURIComponent(termo)}`);
      const d = await resp.json();
      if (d.ok === false) throw new Error(d.erro || "Falha ao consultar IXC");
      state.quickPromptContext = `Faça uma investigação completa para o cliente/termo '${termo}' cruzando o IXC (Radius, radacct, fibra, contrato e O.S.) com o Zabbix.`;

      const stMap = {
        ONLINE_NORMAL: "badge-ok",
        FALHA_TECNICA_OFFLINE: "badge-danger",
        BLOQUEIO_ADMINISTRATIVO: "badge-warn",
        OS_EM_ANDAMENTO: "badge-warn",
      };
      const cls = stMap[d.status_operacional] || "badge-neutral";

      const loginsHtml = (d.logins || [])
        .map(
          (l) => `<tr>
            <td class="mono">${esc(l.login)}</td>
            <td>${l.online === "S" ? '<span class="badge badge-ok">ONLINE</span>' : '<span class="badge badge-danger">OFFLINE</span>'}</td>
            <td class="mono">${esc(l.ip || "-")}</td>
            <td class="mono">${esc(l.mac || "-")}</td>
            <td class="mono">${esc(l.ultima_conexao_final || "-")}</td>
          </tr>`
        )
        .join("");

      const fibraHtml = (d.fibra_onus || [])
        .map(
          (f) => `<tr>
            <td class="mono">${esc(f.serial || f.mac || "-")}</td>
            <td class="mono">${esc(f.ponid || `${f.slotno || "?"}/${f.ponno || "?"}`)}</td>
            <td class="mono">${esc(f.sinal_rx || "?")} dBm</td>
            <td class="mono">${esc(f.sinal_tx || "?")} dBm</td>
            <td>${esc(f.causa_ultima_queda || "-")}</td>
          </tr>`
        )
        .join("");

      const radHtml = (d.sessoes_radius || [])
        .map(
          (s) => `<tr>
            <td class="mono">${esc(s.username || "-")}</td>
            <td class="mono">${esc(s.framedipaddress || "-")}</td>
            <td class="mono">${esc(s.acctstarttime || "-")}</td>
            <td class="mono">${esc(s.acctstoptime || "ativa")}</td>
            <td>${esc(s.acctterminatecause || "-")}</td>
          </tr>`
        )
        .join("");

      el.quickPanelBody.innerHTML = `
        <div style="margin-bottom:10px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
          <span class="badge ${cls}">${esc(d.status_operacional)}</span>
          <strong>${esc(d.resumo || "")}</strong>
        </div>
        ${loginsHtml ? `<div class="table-wrap"><table class="noc-table"><thead><tr><th>Login</th><th>Radius</th><th>IP</th><th>MAC</th><th>Última queda</th></tr></thead><tbody>${loginsHtml}</tbody></table></div>` : ""}
        ${fibraHtml ? `<div class="table-wrap"><table class="noc-table"><thead><tr><th>ONU / Serial</th><th>PON</th><th>RX</th><th>TX</th><th>Causa última queda</th></tr></thead><tbody>${fibraHtml}</tbody></table></div>` : ""}
        ${radHtml ? `<div class="table-wrap"><table class="noc-table"><thead><tr><th>Usuário (radacct)</th><th>IP</th><th>Início</th><th>Fim</th><th>Motivo desconexão</th></tr></thead><tbody>${radHtml}</tbody></table></div>` : ""}`;
    } catch (err) {
      el.quickPanelBody.innerHTML = `<div class="error-banner">${esc(err.message)}</div>`;
    }
  }

  async function carregarListaOlts() {
    const sel = document.getElementById("q-olt-select");
    if (!sel) return;
    try {
      const resp = await fetch("/api/rapido/hosts?busca=OLT");
      const d = await resp.json();
      const hosts = (d.hosts || []).sort((a, b) => (a.name || "").localeCompare(b.name || ""));
      sel.innerHTML =
        `<option value="">Selecione uma OLT (${hosts.length})...</option>` +
        hosts.map((h) => `<option value="${esc(h.name)}">${esc(h.name)}</option>`).join("");
    } catch (_) {
      sel.innerHTML = `<option value="">Não foi possível listar OLTs</option>`;
    }
  }

  async function executarQuickOlt(host) {
    const alvo = (host || "").trim();
    if (!alvo) return;
    el.quickPanelBody.innerHTML = `<div class="live-status"><span class="spinner"></span>Consolidando PONs de ${esc(alvo)}...</div>`;
    try {
      const resp = await fetch(`/api/rapido/olt-pon?host=${encodeURIComponent(alvo)}`);
      const d = await resp.json();
      if (!d.ok) throw new Error(d.erro || "Falha ao consultar OLT");
      const tot = d.totais || {};
      state.quickPromptContext = `Analise a saúde da OLT ${d.host}: verifique PONs com mais LOSS ou DyingGasp, uplinks da OLT e cruze uma amostra de clientes afetados no IXC.`;

      const pons = d.pons_afetadas || [];
      const rows = pons.length
        ? pons
            .map(
              (p) => `<tr>
                <td class="mono">${esc(p.pon)}</td>
                <td class="mono">${esc(p.provisionadas)}</td>
                <td class="mono">${esc(p.online)}</td>
                <td class="mono">${p.loss ? `<span class="badge badge-danger">${esc(p.loss)}</span>` : "0"}</td>
                <td class="mono">${p.dyinggasp ? `<span class="badge badge-warn">${esc(p.dyinggasp)}</span>` : "0"}</td>
                <td class="mono">${esc(p.offline)}</td>
                <td class="mono">${esc(p.percentual_queda)}%</td>
              </tr>`
            )
            .join("")
        : `<tr><td colspan="7" style="color:var(--ok);font-weight:600;">Nenhuma porta PON com ONUs em LOSS/DyingGasp/Offline.</td></tr>`;

      const motivos = Object.entries(d.clientes_ativos_por_motivo || {})
        .map(([k, v]) => `<span class="badge badge-neutral">${esc(k)}: ${esc(v)}</span>`)
        .join(" ");

      el.quickPanelBody.innerHTML = `
        <div class="kpi-row">
          <div class="kpi-card"><span class="kpi-label">PONs</span><span class="kpi-val">${esc(tot.pons_monitoradas ?? 0)}</span></div>
          <div class="kpi-card"><span class="kpi-label">Online / Prov.</span><span class="kpi-val">${esc(tot.online ?? 0)} / ${esc(tot.provisionadas ?? 0)}</span></div>
          <div class="kpi-card"><span class="kpi-label">LOSS (-80)</span><span class="kpi-val" style="color:var(--danger);">${esc(tot.loss ?? 0)}</span></div>
          <div class="kpi-card"><span class="kpi-label">DyingGasp (-90)</span><span class="kpi-val" style="color:var(--warn);">${esc(tot.dyinggasp ?? 0)}</span></div>
        </div>
        ${motivos ? `<div style="margin-bottom:10px;display:flex;gap:6px;flex-wrap:wrap;">${motivos}</div>` : ""}
        <div class="table-wrap">
          <table class="noc-table">
            <thead><tr><th>Porta PON</th><th>Prov.</th><th>Online</th><th>LOSS</th><th>DyingGasp</th><th>Offline</th><th>Queda</th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>`;
    } catch (err) {
      el.quickPanelBody.innerHTML = `<div class="error-banner">${esc(err.message)}</div>`;
    }
  }

  async function carregarResumoConsumoBarra() {
    if (!el.sidebarCostVal) return;
    try {
      const resp = await fetch("/api/rapido/consumo");
      if (!resp.ok) return;
      const c = await resp.json();
      el.sidebarCostVal.textContent = `${fmtBrl(c.hoje?.brl)} hoje · ${fmtBrl(c.ultimos_30d?.brl)}/30d`;
    } catch (_) {
      el.sidebarCostVal.textContent = "Indisponível";
    }
  }

  async function executarQuickConsumo() {
    el.quickPanelBody.innerHTML = `<div class="live-status"><span class="spinner"></span>Calculando consumo estimado...</div>`;
    try {
      const resp = await fetch("/api/rapido/consumo");
      const c = await resp.json();
      if (!c.ok) throw new Error("Não foi possível calcular o consumo.");
      if (el.sidebarCostVal) {
        el.sidebarCostVal.textContent = `${fmtBrl(c.hoje?.brl)} hoje · ${fmtBrl(c.ultimos_30d?.brl)}/30d`;
      }

      const modelosRows = (c.por_modelo_30d || []).length
        ? c.por_modelo_30d
            .map(
              (m) => `<tr>
                <td class="mono">${esc(m.modelo)}</td>
                <td>${m.brl_economia_30d > 0 ? `<span class="badge badge-ok">Free Tier (Economia ${esc(fmtBrl(m.brl_economia_30d))})</span>` : `<span class="badge badge-neutral">Paid Tier</span>`}</td>
                <td class="mono">${esc(m.chamadas_30d)}</td>
                <td class="mono">${Number(m.tokens_30d || 0).toLocaleString("pt-BR")}</td>
                <td class="mono"><strong>${esc(fmtBrl(m.brl_30d))}</strong></td>
              </tr>`
            )
            .join("")
        : `<tr><td colspan="5">Nenhuma chamada com IA registrada nos últimos 30 dias.</td></tr>`;

      const diarioRows = (c.diario_14d || []).length
        ? c.diario_14d
            .map(
              (d) => `<tr>
                <td class="mono">${esc(d.data)}</td>
                <td class="mono">${esc(d.chamadas_webhook)}${c.webhook_free_tier && d.chamadas_webhook ? ' <span class="badge badge-ok">Grátis</span>' : ""}</td>
                <td class="mono">${esc(d.chamadas_painel)}</td>
                <td class="mono">${Number(d.tokens_total || 0).toLocaleString("pt-BR")}</td>
                <td class="mono"><strong>${esc(fmtBrl(d.brl))}</strong></td>
              </tr>`
            )
            .join("")
        : `<tr><td colspan="5">Sem dados nos últimos 14 dias.</td></tr>`;

      const sub30d = c.webhook_free_tier
        ? `Painel ${fmtBrl(c.ultimos_30d?.brl_painel)} · Webhook Free Tier (economia ${fmtBrl(c.ultimos_30d?.brl_webhook_economia)})`
        : `Webhook ${fmtBrl(c.ultimos_30d?.brl_webhook)} · Painel ${fmtBrl(c.ultimos_30d?.brl_painel)}`;

      el.quickPanelBody.innerHTML = `
        <div class="kpi-row">
          <div class="kpi-card">
            <span class="kpi-label">Hoje (faturado)</span>
            <span class="kpi-val">${esc(fmtBrl(c.hoje?.brl))}</span>
            <span class="kpi-label" style="margin-top:3px;text-transform:none;">${esc(c.hoje?.chamadas_painel || 0)} painel · ${esc(c.hoje?.chamadas_webhook || 0)} webhook</span>
          </div>
          <div class="kpi-card">
            <span class="kpi-label">Últimos 7 dias</span>
            <span class="kpi-val">${esc(fmtBrl(c.ultimos_7d?.brl))}</span>
            <span class="kpi-label" style="margin-top:3px;text-transform:none;">Média ${esc(fmtBrl(c.media_diaria_7d_brl))}/dia</span>
          </div>
          <div class="kpi-card">
            <span class="kpi-label">Últimos 30 dias</span>
            <span class="kpi-val">${esc(fmtBrl(c.ultimos_30d?.brl))}</span>
            <span class="kpi-label" style="margin-top:3px;text-transform:none;">${esc(sub30d)}</span>
          </div>
          <div class="kpi-card">
            <span class="kpi-label">Mês atual</span>
            <span class="kpi-val">${esc(fmtBrl(c.mes_atual?.brl))}</span>
            <span class="kpi-label" style="margin-top:3px;text-transform:none;">Câmbio R$ ${Number(c.cotacao_usd_brl || 5.85).toFixed(2)}/US$</span>
          </div>
        </div>
        <div class="table-wrap">
          <table class="noc-table">
            <thead><tr><th>Modelo (30 dias)</th><th>Regime</th><th>Chamadas</th><th>Tokens</th><th>Custo faturado</th></tr></thead>
            <tbody>${modelosRows}</tbody>
          </table>
        </div>
        <div class="table-wrap">
          <table class="noc-table">
            <thead><tr><th>Data (últimos 14 dias)</th><th>Webhook</th><th>Painel Chat</th><th>Tokens totais</th><th>Custo faturado</th></tr></thead>
            <tbody>${diarioRows}</tbody>
          </table>
        </div>`;
    } catch (err) {
      el.quickPanelBody.innerHTML = `<div class="error-banner">${esc(err.message)}</div>`;
    }
  }

  /* ---------------------------------------------------------------------- */
  /* Eventos e Inicialização                                                */
  /* ---------------------------------------------------------------------- */

  function ajustarAlturaTextarea() {
    el.inputMensagem.style.height = "auto";
    el.inputMensagem.style.height = Math.min(el.inputMensagem.scrollHeight, 180) + "px";
  }

  function fecharSidebarMobile() {
    el.sidebar.classList.remove("open");
    el.backdrop.classList.add("hidden");
  }

  el.btnMenuMobile.addEventListener("click", () => {
    el.sidebar.classList.toggle("open");
    el.backdrop.classList.toggle("hidden", !el.sidebar.classList.contains("open"));
  });
  el.backdrop.addEventListener("click", fecharSidebarMobile);

  el.btnTema.addEventListener("click", alternarTema);
  el.btnNovaConversa.addEventListener("click", novaVerificacao);
  el.btnFecharQuick.addEventListener("click", fecharQuickPanel);

  el.btnQuickEnviarChat.addEventListener("click", () => {
    const prompt = state.quickPromptContext;
    fecharQuickPanel();
    if (prompt) {
      enviarPergunta(prompt);
    }
  });

  document.querySelectorAll(".model-opt").forEach((btn) => {
    btn.addEventListener("click", () => definirModelo(btn.dataset.model));
  });

  document.querySelectorAll(".quick-btn, .cost-pill-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (state.quickMode === btn.dataset.quick) {
        fecharQuickPanel();
      } else {
        abrirQuickPanel(btn.dataset.quick);
      }
    });
  });

  document.querySelectorAll(".starter-card").forEach((card) => {
    card.addEventListener("click", () => enviarPergunta(card.dataset.prompt));
  });

  el.listaConversas.addEventListener("click", (e) => {
    const delBtn = e.target.closest("[data-del]");
    if (delBtn) {
      e.stopPropagation();
      excluirConversa(delBtn.dataset.del);
      return;
    }
    const item = e.target.closest(".conv-item");
    if (item && item.dataset.id) {
      abrirConversa(item.dataset.id);
    }
  });

  let debounceBusca = null;
  el.buscaConversas.addEventListener("input", () => {
    clearTimeout(debounceBusca);
    debounceBusca = setTimeout(() => carregarConversas(el.buscaConversas.value), 180);
  });

  el.inputMensagem.addEventListener("input", ajustarAlturaTextarea);
  el.inputMensagem.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      el.formChat.requestSubmit();
    }
  });

  el.formChat.addEventListener("submit", (e) => {
    e.preventDefault();
    enviarPergunta(el.inputMensagem.value);
  });

  el.btnCancelar.addEventListener("click", () => {
    if (state.abortCtrl) state.abortCtrl.abort();
  });

  // Boot
  definirModelo(state.modelo);
  carregarConfig();
  carregarConversas();
  carregarResumoConsumoBarra();
})();
