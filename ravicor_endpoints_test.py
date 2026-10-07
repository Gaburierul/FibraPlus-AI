from clients.ravicor import RavicorClient

def main():
    r = RavicorClient()
    
    operacoes_para_testar = ["list_devices", "get_all", "get_devices", "devices", "get_all_devices"]
    
    print("=== BUSCANDO A OPERAÇÃO CORRETA PARA DISPOSITIVOS ===")
    for op in operacoes_para_testar:
        print(f"Testando operation='{op}'...")
        resposta = r._call("dispositivo", op)
        if "msg" not in resposta or "Invalid" not in resposta.get("msg", ""):
            print(f"🎯 BINGO! A operação correta é: '{op}'")
            print(f"   Dados retornados: {str(resposta)[:150]}...\n")
            break

if __name__ == "__main__":
    main()