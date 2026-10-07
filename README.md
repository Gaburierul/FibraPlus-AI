# FibraPlus AI NOC

Este é o cérebro automatizado do NOC da FibraPlus. O sistema lê alertas caóticos disparados pelo Zabbix (no formato enviado ao WhatsApp), realiza a correlação lógica dos eventos no tempo e utiliza a Inteligência Artificial (Google Gemini) para gerar um diagnóstico consolidado e limpo da causa raiz.

## 🚀 Funcionalidades

- **Parser Resiliente:** Processa mensagens de texto brutas originadas de grupos de WhatsApp, limpando prefixos de cópia (ex: data/telefone) e extraindo metadados críticos.
- **Correlação Lógica (Debounce):** Agrupa alertas que ocorrem dentro de uma mesma janela de tempo (ex: 10 minutos). Se uma fibra rompe e causa a queda de BGP, OSPF e PPPoE em cascata, tudo vira um único "Incidente".
- **Sistema de Fallback:** Funciona perfeitamente mesmo se a IA estiver fora do ar. A lógica matemática do script agrupa os alertas, identifica oscilações (Flapping 🟠) e quedas (ATIVO 🔴), garantindo que a operação nunca pare.
- **Integração Zabbix & Ravicor:** Lógica desenhada para cruzar o equipamento afetado com os dados do Zabbix (via JSON-RPC) e Ravicor (via REST API).
- **IA Generativa Nível NOC L3:** Usa o modelo `gemini-3.5-flash-lite` (ou 3.8-flash) com a funcionalidade de *Structured Output* para raciocinar de trás pra frente e isolar a causa raiz, retornando o texto perfeitamente formatado para repasse aos técnicos.

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
   ZABBIX_URL=https://zabbix.fibraplus.com.br/api_jsonrpc.php
   ZABBIX_TOKEN=seu_token_aqui
   RAVICOR_URL=https://ravi.fibraplus.com.br/api/api.php
   RAVICOR_TOKEN=seu_token_aqui
   GEMINI_API_KEY=sua_chave_gemini_aqui
   ```

## 🧠 Como Usar (Testando a IA localmente)

Para analisar um log de texto com alertas do Zabbix (Prova de Conceito):

```bash
# Rodar com a IA do Gemini
python scripts/ai_noc_analyzer.py --arquivo samples/alertas/07_entrada_user.txt

# Rodar APENAS a correlação lógica (Modo Offline / Sem IA)
python scripts/ai_noc_analyzer.py --arquivo samples/alertas/07_entrada_user.txt --offline
```

## 🏗️ Estrutura do Projeto

* `noc/parser.py`: Limpa a string do WhatsApp e extrai os alertas individuais.
* `noc/correlator.py`: Junta eventos de uma mesma janela de tempo em `Incidentes`.
* `noc/analyzer.py`: Encapsula o Pydantic + Interações da API do Gemini para saída estruturada.
* `clients/`: Conectores para Zabbix e Ravicor.
* `scripts/`: Entrypoints para rodar no terminal.
* `samples/`: Casos de testes com logs reais para validação do modelo.

## 📝 Regras de Negócio
A classificação de Severidade da IA respeita topologia. Tags nativas do Zabbix (`backbone`, `edge`) ditam o peso do alerta de `1` (Crítico) a `3` (Informativo), ignorando a severidade puramente técnica da trigger. Ver detalhes em `docs/regras_tags_zabbix.md`.
