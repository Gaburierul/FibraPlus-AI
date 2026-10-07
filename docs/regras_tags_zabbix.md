# Regras de Negócio e Severidade - Monitoramento FibraPlus

Este documento instrui a IA sobre como interpretar a gravidade dos alertas vindos do Zabbix com base nas etiquetas (tags) de topologia da rede.

## Sistema de Custos/Pesos das Tags
Qualquer etiqueta de topologia ou região (ex: `backbone`, `edge`, etc.) associada a um valor numérico de 1 a 3 deve ser tratada sob a seguinte matriz de criticidade:

* **Valor 1 (Crítico):** 
  - Representa o core da rede ou links vitais. 
  - **Ação:** Deve ser tratado como prioridade máxima ("Incidente Crítico"). Parada que gera alto impacto global.

* **Valor 2 (Alerta):** 
  - Representa anéis secundários, distribuição ou falha de redundância. 
  - **Ação:** Atenção necessária ("Warning"). Pode indicar degradação ou risco de queda caso o equipamento principal também falhe.

* **Valor 3 (Informativo):** 
  - Representa bordas finais, avisos de oscilação ou equipamentos com isolamento de impacto.
  - **Ação:** Tratado como "Aviso Informativo". Geralmente não requer pânico imediato do NOC, a menos que acumule com outras falhas.

### Exemplo Prático
- Um alerta contendo a tag `backbone: 1` = **CRÍTICO** (Caiu o mundo).
- Um alerta contendo a tag `edge: 2` = **ALERTA** (Borda degradada).
- Um alerta contendo a tag `backbone: 3` = **INFORMATIVO** (Queda em um elo de menor impacto no backbone).

> **Nota para a IA:** Sempre que puxar eventos do Zabbix, priorize a leitura e o destaque visual para os alertas contendo valor **1** em suas tags de localização.
