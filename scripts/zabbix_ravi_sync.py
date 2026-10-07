import json
from clients.zabbix import ZabbixClient
from clients.ravicor import RavicorClient

def main():
    print("Iniciando Verificação Cruzada (Zabbix <-> Ravicor)...")
    try:
        z = ZabbixClient()
        r = RavicorClient()
        
        # 1. Puxar TODOS os equipamentos do Ravicor (Concentradoras + Dispositivos) para a memória
        ravi_db = {}
        
        # 1.1 Concentradoras
        concentradoras = r._call('concentradora', 'list').get('data', [])
        for c in concentradoras:
            ravi_db[c.get('nome', '').lower()] = c
            
        # 1.2 Dispositivos por grupo
        grupos = r.list_device_groups()
        for g in grupos:
            devs = r.list_devices(group_id=g['id'])
            for d in devs:
                ravi_db[d.get('name', '').lower()] = d
                
        print(f"Base do Ravicor carregada: {len(ravi_db)} equipamentos/servicos mapeados.")
        
        # 2. Puxar incidentes de Infra do Zabbix (Top 5 mais recentes)
        # Vamos usar a API direto pra pegar triggers recentes e seus hosts
        problemas = z.get_problems(limit=10)
        infra_probs = [p for p in problemas if not p.get('name', '').lower().startswith('cliente')]
        
        print("\n--- RESULTADO DO CRUZAMENTO ---")
        for p in infra_probs[:5]:
            nome_alerta = p['name']
            
            # Pegar o host do Zabbix a partir do trigger (objectid)
            triggers = z._call('trigger.get', {'triggerids': p['objectid'], 'selectHosts': ['host', 'name']})
            if not triggers or not triggers[0]['hosts']:
                continue
                
            zabbix_host = triggers[0]['hosts'][0]['host']
            zabbix_host_lower = zabbix_host.lower()
            
            print(f"Alerta Zabbix: {nome_alerta}")
            print(f"   Equipamento: {zabbix_host}")
            
            # 3. Magica: Cruzar com os dados do Ravicor
            if zabbix_host_lower in ravi_db:
                dado_ravi = ravi_db[zabbix_host_lower]
                print(f"   [ENCONTRADO NO RAVICOR]")
                print(f"      - IP Ravi: {dado_ravi.get('ip', 'N/A')}")
                if 'marca' in dado_ravi:
                    print(f"      - Tipo de Cadastro: Concentradora (ID: {dado_ravi.get('id')})")
                else:
                    print(f"      - Tipo de Cadastro: Dispositivo (Grupo ID: {dado_ravi.get('group_id')})")
            else:
                print(f"   [AVISO] Equipamento existe no Zabbix, mas nao localizado no Ravicor (Nomes diferentes?)")
            print("-" * 50)

    except Exception as e:
        print(f"Erro durante a sincronização: {e}")

if __name__ == '__main__':
    main()
