# FibraPlus AI NOC

Este é o cérebro automatizado do NOC da FibraPlus. O sistema lê alertas caóticos disparados pelo Zabbix (no formato enviado ao WhatsApp), realiza a correlação lógica dos eventos no tempo e utiliza a Inteligência Artificial (Google Gemini) para gerar um diagnóstico consolidado e limpo da causa raiz.

## 🚀 Funcionalidades

- **Parser Resiliente:** Processa mensagens de texto brutas originadas de grupos de WhatsApp, limpando prefixos de cópia (ex: data/telefone) e extraindo metadados críticos.
- **Correlação Lógica (Debounce):** Agrupa alertas que ocorrem dentro de uma mesma janela de tempo (ex: 10 minutos). Se uma fibra rompe e causa a queda de BGP, OSPF e PPPoE em cascata, tudo vira um único "Incidente".
- **Sistema de Fallback:** Funciona perfeitamente mesmo se a IA estiver fora do ar. A lógica matemática do script agrupa os alertas, identifica oscilações (Flapping 🟠) e quedas (ATIVO 🔴), garantindo que a operação nunca pare.
- **Integração Zabbix & Ravicor:** Lógica desenhada para cruzar o equipamento afetado com os dados do Zabbix (via JSON-RPC) e Ravicor (via REST API).
- **Diagnóstico assistido por IA:** Usa a Interactions API do Gemini com saída estruturada para propor uma hipótese. A severidade e os fatos da mensagem são montados pelo código a partir dos alertas; a hipótese é marcada como não confirmada.

## ⚙️ Instalação

1. Clone este repositório.
2. Certifique-se de ter o Python instalado (3.10 ou superior).
3. Ative o ambiente virtual e instale as dependências:
   ```bash
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```
4. Crie um arquivo `.env` na raiz do projeto com base no escopo abaixo:
   ```env
   ZABBIX_URL=https://zabbix.example.com/api_jsonrpc.php
   ZABBIX_TOKEN=seu_token_aqui
   RAVICOR_URL=https://ravi.example.com/api/api.php
   RAVICOR_TOKEN=seu_token_aqui
   GEMINI_API_KEY=sua_chave_gemini_aqui
   NOC_AI_MODEL=gemini-3.5-flash-lite
   NOC_AI_THINKING=minimal
   GEMINI_TIMEOUT_S=45
   ZABBIX_TIMEOUT_S=15
   RAVICOR_TIMEOUT_S=15
   MESSAGING_TIMEOUT_S=20
   WEBHOOK_TOKEN=um_token_aleatorio_compartilhado_com_o_zabbix
   MODO_TESTE=true
   NOC_USAR_IA=true
   NOC_AI_AUTO_SEND=false
   NOC_AI_IN_TEST_MODE=false
   NOC_WEBHOOK_URL=http://127.0.0.1:8089/zabbix/webhook
   NOC_ZABBIX_POLL_INTERVAL_S=30
   NOC_ZABBIX_INITIAL_LOOKBACK_MIN=5
   NOC_ZABBIX_SEVERIDADE_MINIMA=2
   NOC_MENSAGEIRO=telegram
   TELEGRAM_BOT_TOKEN=seu_token_do_bot
   TELEGRAM_CHAT_ID=id_do_chat
   ```

   Mantenha o modo de teste até validar o fluxo. Em modo de teste, o Gemini fica desativado por padrão (`NOC_AI_IN_TEST_MODE=false`), evitando consumo de cota. Em modo real (`MODO_TESTE=false`), o webhook envia o resumo determinístico. A hipótese breve do Gemini só entra no envio automático quando `NOC_AI_AUTO_SEND=true`.

## 🧠 Como Usar (Testando a IA localmente)

Para analisar um log de texto com alertas do Zabbix (Prova de Conceito):

```bash
# Rodar com a IA do Gemini
python scripts/ai_noc_analyzer.py --arquivo samples/alertas/07_entrada_user.txt

# Rodar APENAS a correlação lógica (Modo Offline / Sem IA)
python scripts/ai_noc_analyzer.py --arquivo samples/alertas/07_entrada_user.txt --offline
```

Para escolher o esforço de raciocínio, use `--thinking low|medium|high` (ou `minimal` nos modelos que aceitam esse nível). O padrão é `NOC_AI_THINKING`; as requisições Gemini têm timeout configurado por `GEMINI_TIMEOUT_S`.

O Gemini usa `gemini-3.5-flash-lite` por padrão e `NOC_AI_THINKING=minimal`; `low`, `medium` e `high` podem ser escolhidos quando a análise exigir mais raciocínio. As chamadas de envio ao Telegram e Evolution usam timeout configurável por `MESSAGING_TIMEOUT_S`. Em falhas de rede, o cliente não repete automaticamente um POST de envio, pois a API pode ter aceitado a mensagem antes da conexão cair; novas tentativas ficam restritas a respostas HTTP 429.

Alertas do Ravicor recebem severidade determinística: rota, OLT ou link indisponível recebem nível 5; degradação, atenuação, perda ou oscilação recebem nível 4; eventos sem regra específica ficam no nível 3. A classificação de tags topológicas do Zabbix continua definida em `docs/regras_tags_zabbix.md`.

O relatório de ativos não envia mensagem por padrão e não chama Gemini implicitamente. `python scripts/relatorio_ativos.py --horas 1 --enviar` consulta o Zabbix, gera o resumo determinístico e envia a mensagem. Acrescente `--usar-ia` para autorizar uma chamada Gemini e acrescentar uma hipótese breve e não confirmada. `--offline` continua disponível como alias explícito. `NOC_AI_AUTO_SEND` controla apenas a hipótese de IA nos envios automáticos do webhook.

## Integração do Zabbix sem Media Type

O Zabbix 7.x pode ser consultado pela API JSON-RPC usando um token com permissão de leitura para os eventos e hosts. Para esse caminho não é necessário criar Action ou Media Type no Zabbix: o processo local consulta `event.get`, mantém um cursor SQLite em `logs/zabbix_poller.sqlite3` e encaminha problemas e recuperações para `/zabbix/webhook`. A ponte usa apenas a biblioteca padrão SQLite e não chama Gemini nem envia mensagens diretamente.

Inicie o webhook em um terminal:

```powershell
$env:PYTHONIOENCODING="utf-8"
.venv\Scripts\python.exe -m uvicorn server.webhook:app --host 127.0.0.1 --port 8089
```

Em outro terminal, faça uma consulta única segura (o processo exige `MODO_TESTE=true` por padrão):

```powershell
$env:PYTHONIOENCODING="utf-8"
.venv\Scripts\python.exe scripts\poller_zabbix.py --uma-vez
```

Para manter a consulta ativa, retire `--uma-vez`:

```powershell
.venv\Scripts\python.exe scripts\poller_zabbix.py
```

O intervalo padrão é 30 segundos, com severidade mínima 2 e uma janela inicial de cinco minutos. Na primeira execução, eventos anteriores a essa janela não são reenviados; ocorrências ativas antigas podem ser consultadas pelo relatório de ativos. Ajuste com `NOC_ZABBIX_POLL_INTERVAL_S`, `NOC_ZABBIX_SEVERIDADE_MINIMA` e `NOC_ZABBIX_INITIAL_LOOKBACK_MIN`. Para apontar a outro endpoint, configure `NOC_WEBHOOK_URL`. O cursor e os problemas abertos ficam no SQLite local; execute apenas uma instância do poller por arquivo e faça backup desse arquivo se quiser preservar o estado ao migrar a ponte.

Se o webhook estiver em `MODO_TESTE=false`, a ponte se recusa a iniciar sem a opção explícita `--permitir-envio-real`. Esse modo pode enviar alertas ao mensageiro definido. Se uma chamada HTTP for aceita pelo servidor, mas a confirmação se perder antes de o cursor ser salvo, a próxima consulta pode repetir esse evento; o agrupador elimina duplicatas apenas enquanto o alerta permanece no mesmo lote.

O comando de `uvicorn` mantém o webhook disponível somente enquanto o processo roda. Para alertas Ravi recebidos de fora, o túnel `ssh -R 80:localhost:8089 nokey@localhost.run` também precisa permanecer conectado. A ponte Zabbix precisa permanecer ativa e ter acesso de rede à API Zabbix. Desligar o computador encerra esses processos; disponibilidade contínua exige hospedar o webhook e o poller em um servidor sempre ligado e garantir acesso seguro desse servidor à API Zabbix.

O script `zabbix/webhook_fibraplus_ia.js` permanece como alternativa caso um administrador possa cadastrar um tipo de mídia Webhook e uma Action. A tela de Actions e o catálogo de integrações não substituem a permissão de administração de Media Types.

## 🏗️ Estrutura do Projeto

* `noc/parser.py`: Limpa a string do WhatsApp e extrai os alertas individuais.
* `noc/correlator.py`: Junta eventos de uma mesma janela de tempo em `Incidentes`.
* `noc/analyzer.py`: Encapsula o Pydantic + Interações da API do Gemini para saída estruturada.
* `clients/`: Conectores para Zabbix e Ravicor.
* `scripts/`: Entrypoints para rodar no terminal.
* `samples/`: Casos de testes com logs reais para validação do modelo.

## 📝 Regras de Negócio
A classificação de Severidade da IA respeita topologia. Tags nativas do Zabbix (`backbone`, `edge`) ditam o peso do alerta de `1` (Crítico) a `3` (Informativo), ignorando a severidade puramente técnica da trigger. Ver detalhes em `docs/regras_tags_zabbix.md`.
