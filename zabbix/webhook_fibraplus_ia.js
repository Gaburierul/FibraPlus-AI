// Tipo de mídia Webhook do Zabbix 7.x -> FibraPlus NOC IA
// Cole este código no campo "Script" do tipo de mídia (Alertas > Tipos de mídia).
//
// Parâmetros do tipo de mídia (Nome -> Valor):
//   url                  http://127.0.0.1:8089/zabbix/webhook
//   token                <mesmo valor de WEBHOOK_TOKEN no .env>
//   event_id             {EVENT.ID}
//   event_value          {EVENT.VALUE}
//   event_update_status  {EVENT.UPDATE.STATUS}
//   host_name            {HOST.NAME}
//   host_ip              {HOST.IP}
//   event_name           {EVENT.NAME}
//   event_nseverity      {EVENT.NSEVERITY}
//   event_severity       {EVENT.SEVERITY}
//   event_date           {EVENT.DATE}
//   event_time           {EVENT.TIME}
//   recovery_date        {EVENT.RECOVERY.DATE}
//   recovery_time        {EVENT.RECOVERY.TIME}
//   event_duration       {EVENT.DURATION}
//   event_tags_json      {EVENT.TAGSJSON}
//   http_proxy           (opcional, deixe vazio)

var Fibraplus = {
    enviar: function (params) {
        var campos = [
            'event_id', 'event_value', 'event_update_status', 'host_name', 'host_ip',
            'event_name', 'event_nseverity', 'event_severity', 'event_date', 'event_time',
            'recovery_date', 'recovery_time', 'event_duration', 'event_tags_json'
        ];
        var corpo = {};
        campos.forEach(function (c) {
            corpo[c] = (typeof params[c] === 'string') ? params[c] : '';
        });

        var req = new HttpRequest();
        req.addHeader('Content-Type: application/json');
        req.addHeader('X-Webhook-Token: ' + params.token);
        if (params.http_proxy) {
            req.setProxy(params.http_proxy);
        }

        Zabbix.log(4, '[FibraPlus NOC IA] enviando evento ' + corpo.event_id + ' para ' + params.url);
        var resposta = req.post(params.url, JSON.stringify(corpo));
        var status = req.getStatus();

        if (status < 200 || status >= 300) {
            throw 'Falha HTTP ' + status + ': ' + resposta;
        }
        return resposta;
    }
};

try {
    var params = JSON.parse(value);
    if (!params.url || !params.token) {
        throw 'Parâmetros "url" e "token" são obrigatórios.';
    }
    Fibraplus.enviar(params);
    return 'OK';
} catch (erro) {
    Zabbix.log(3, '[FibraPlus NOC IA] erro: ' + erro);
    throw 'Erro no webhook FibraPlus NOC IA: ' + erro;
}
