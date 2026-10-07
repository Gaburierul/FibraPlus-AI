"""
Servidor MCP do FibraPlus-AI.
Expõe as ferramentas do Zabbix e do Ravicor para a IA.
"""

from mcp.server.fastmcp import FastMCP
from clients.zabbix import ZabbixClient
from clients.ravicor import RavicorClient

# Inicializa o servidor e os clientes
mcp = FastMCP("FibraPlus-AI", dependencies=["mcp", "requests", "python-dotenv"])
zabbix = ZabbixClient()
ravicor = RavicorClient()

# ==========================================
# Ferramentas do Zabbix
# ==========================================

@mcp.tool()
def get_zabbix_hosts(search: str = None, limit: int = 50) -> list:
    """
    Lista os hosts monitorados no Zabbix.
    
    Args:
        search: Termo opcional para filtrar pelo nome do host (ex: 'HUAWEI').
        limit: Número máximo de resultados (padrão 50).
        
    Returns:
        Uma lista de dicionários contendo hostid, host (hostname), name e status.
    """
    return zabbix.get_hosts(search=search, limit=limit)

@mcp.tool()
def get_zabbix_problems(limit: int = 20, severity_min: int = 0) -> list:
    """
    Lista os problemas (unresolved problems/alerts) atuais no Zabbix.
    
    Args:
        limit: Número máximo de problemas a retornar (padrão 20).
        severity_min: Severidade mínima (0=Não classificado, 1=Info, 2=Aviso, 3=Média, 4=Alta, 5=Desastre).
        
    Returns:
        Uma lista detalhada de problemas, ordenada dos mais recentes para os mais antigos.
    """
    return zabbix.get_problems(limit=limit, severity_min=severity_min)

@mcp.tool()
def get_zabbix_host_details(hostname: str) -> dict:
    """
    Obtém detalhes completos de um host específico no Zabbix.
    Inclui interfaces, itens (últimos valores coletados) e triggers.
    
    Args:
        hostname: O nome exato do host no Zabbix.
        
    Returns:
        Detalhes completos do host, ou um dicionário vazio se não encontrado.
    """
    return zabbix.get_host_details(hostname)

@mcp.tool()
def get_zabbix_triggers(hostids: list[str] = None, only_problems: bool = True) -> list:
    """
    Lista os triggers (regras de alerta) no Zabbix.
    
    Args:
        hostids: Lista opcional de IDs de hosts para filtrar.
        only_problems: Se verdadeiro (padrão), retorna apenas triggers que estão no estado de problema (value=1).
        
    Returns:
        Uma lista de triggers com estado, descrição, prioridade e data da última mudança.
    """
    return zabbix.get_triggers(hostids=hostids, only_problems=only_problems)


# ==========================================
# Ferramentas do Ravicor
# ==========================================

@mcp.tool()
def list_ravicor_device_groups() -> list:
    """
    Lista os grupos de dispositivos cadastrados no Ravicor (ex: MONITORES, DATA CENTER, DNS).
    
    Returns:
        Uma lista de grupos com seus respectivos IDs e nomes.
    """
    return ravicor.list_device_groups()

@mcp.tool()
def list_ravicor_devices(group_id: int = None) -> list:
    """
    Lista os dispositivos cadastrados no Ravicor.
    
    Args:
        group_id: ID opcional de um grupo para filtrar os dispositivos.
        
    Returns:
        Uma lista de dispositivos cadastrados.
    """
    return ravicor.list_devices(group_id=group_id)

@mcp.tool()
def list_ravicor_olts() -> list:
    """
    Lista as OLTs (Optical Line Terminals) cadastradas no Ravicor.
    
    Returns:
        Uma lista detalhada das OLTs.
    """
    return ravicor.list_olts()

@mcp.tool()
def get_ravicor_device(device_id: int) -> dict:
    """
    Obtém detalhes de um dispositivo específico no Ravicor pelo seu ID.
    
    Args:
        device_id: O ID numérico do dispositivo no Ravicor.
        
    Returns:
        Detalhes completos do dispositivo.
    """
    return ravicor.get_device(device_id)


if __name__ == "__main__":
    mcp.run()
