"""Módulo 5: Enriquecimento de IPs (Threat Intelligence) - SecuraPy.

Responsável por classificar IPs, gerenciar cache e consultar
a API pública do ipinfo.io para enriquecer alertas do SIEM.
"""
import sys

import requests

try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass


def eh_ip_privado(ip: str) -> bool:
    """Verifica se um endereço IPv4 pertence a uma rede privada (RFC 1918)
    ou loopback.
    Faixas privadas:
      - 10.0.0.0/8     (10.x.x.x)
      - 172.16.0.0/12  (172.16.x.x até 172.31.x.x)
      - 192.168.0.0/16 (192.168.x.x)
      - 127.0.0.0/8    (Loopback/Localhost)
    """
    if not isinstance(ip, str):
        return False
    partes = ip.strip().split(".")
    if len(partes) != 4:
        return False
    try:
        octetos = [int(p) for p in partes]
        for octeto in octetos:
            if not 0 <= octeto <= 255:
                return False
    except ValueError:
        return False
    if octetos[0] == 10:
        return True
    if octetos[0] == 172 and 16 <= octetos[1] <= 31:
        return True
    if octetos[0] == 192 and octetos[1] == 168:
        return True
    if octetos[0] == 127:
        return True
    return False
def consultar_ip(ip: str, cache: dict) -> dict:
    """Consulta o ipinfo.io para obter geolocalização e ASN/Organização.

    Aplica cache em memória e tratamento defensivo de erros.
    """
    ip_limpo = ip.strip() if isinstance(ip, str) else ""
    if ip_limpo in cache:
        return cache[ip_limpo]
    dados_padrao = {
        "ip": ip_limpo,
        "cidade": "Desconhecida",
        "regiao": "Desconhecida",
        "pais": "Desconhecido",
        "org": "Desconhecida",
        "hostname": "N/A",
        "tipo": "Publico",
    }
    if eh_ip_privado(ip_limpo):
        dados_privados = {
            "ip": ip_limpo,
            "cidade": "N/A",
            "regiao": "N/A",
            "pais": "N/A",
            "org": "Rede Interna",
            "hostname": "localhost",
            "tipo": "Privado",
        }
        cache[ip_limpo] = dados_privados
        return dados_privados
    partes = ip_limpo.split(".")
    if len(partes) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in partes):
        dados_invalidos = dados_padrao.copy()
        dados_invalidos["org"] = "IP Invalido"
        dados_invalidos["tipo"] = "Invalido"
        cache[ip_limpo] = dados_invalidos
        return dados_invalidos
    url = f"https://ipinfo.io/{ip_limpo}/json"
    try:
        resposta = requests.get(url, timeout=5)
        if resposta.status_code == 200:
            info = resposta.json()
            resultado = {
                "ip": ip_limpo,
                "cidade": info.get("city", "Desconhecida"),
                "regiao": info.get("region", "Desconhecida"),
                "pais": info.get("country", "Desconhecido"),
                "org": info.get("org", "Desconhecida"),
                "hostname": info.get("hostname", "N/A"),
                "tipo": "Publico",
            }
            cache[ip_limpo] = resultado
            return resultado
        elif resposta.status_code == 429:
            print(f"[!] Limite de requisições da API atingido (HTTP 429) para o IP {ip_limpo}.")
            dados_padrao["org"] = "Limite de API excedido"
            return dados_padrao
        elif resposta.status_code == 404:
            dados_padrao["org"] = "IP Nao Encontrado"
            cache[ip_limpo] = dados_padrao
            return dados_padrao
        else:
            print(f"[!] Erro na API: status code {resposta.status_code} para o IP {ip_limpo}.")
            return dados_padrao
    except requests.exceptions.Timeout:
        print(f"[!] Timeout: A API do ipinfo.io demorou mais de 5s para responder ({ip_limpo}).")
        dados_padrao["org"] = "Timeout na Consulta"
        return dados_padrao
    except requests.exceptions.ConnectionError:
        print(f"[!] Erro de Conexao: Falha ao conectar à internet ou host inacessível ({ip_limpo}).")
        dados_padrao["org"] = "Sem Conexao"
        return dados_padrao
    except Exception as e:
        print(f"[!] Erro inesperado ao consultar IP {ip_limpo}: {e}")
        return dados_padrao
def enriquecer_alertas(alertas: list, cache: dict) -> list:
    """Recebe uma lista de alertas gerados pelo SIEM, consulta as informações
    de geolocalização do campo 'ip_origem' e insere o enriquecimento.
    """
    alertas_enriquecidos = []
    for alerta in alertas:
        alerta_copia = alerta.copy()
        ip_origem = alerta_copia.get("ip_origem") or alerta_copia.get("ip")
        if ip_origem:
            dados_geoloc = consultar_ip(ip_origem, cache)
            alerta_copia["enriquecimento"] = dados_geoloc
        else:
            alerta_copia["enriquecimento"] = {
                "ip": "N/A",
                "org": "Sem IP",
                "tipo": "Indefinido",
            }
        alertas_enriquecidos.append(alerta_copia)
    return alertas_enriquecidos
def exibir_enriquecimento(dados_ip: dict) -> None:
    """Exibe os dados de enriquecimento de forma tabular e legível no console."""
    print("=" * 55)
    print(f"[*] RELATÓRIO DE THREAT INTELLIGENCE — IP: {dados_ip.get('ip')}")
    print("=" * 55)
    print(f"  Tipo de Rede : {dados_ip.get('tipo', 'N/A')}")
    print(f"  Organização  : {dados_ip.get('org', 'N/A')}")
    print(f"  Hostname     : {dados_ip.get('hostname', 'N/A')}")
    print(f"  Localização  : {dados_ip.get('cidade', 'N/A')}, {dados_ip.get('regiao', 'N/A')} - {dados_ip.get('pais', 'N/A')}")
    print("=" * 55)

# BATERIA DE TESTES LOCAIS (Executado apenas ao rodar este arquivo)
if __name__ == "__main__":
    print("\n--- INICIANDO TESTES DO MÓDULO 5 (enriquecimento.py) ---\n")
    cache_teste = {}
    # Cenário 1: IP Público conhecido (Google DNS)
    print("[TESTE 1] Consultando 8.8.8.8...")
    res1 = consultar_ip("8.8.8.8", cache_teste)
    exibir_enriquecimento(res1)
    # Cenário 2: IP Privado RFC 1918
    print("\n[TESTE 2] Consultando IP privado 192.168.1.10...")
    res2 = consultar_ip("192.168.1.10", cache_teste)
    exibir_enriquecimento(res2)
    # Cenário 3: Cache (deve responder sem nova requisição HTTP)
    print("\n[TESTE 3] Consultando 8.8.8.8 novamente (verificando Cache)...")
    res3 = consultar_ip("8.8.8.8", cache_teste)
    print(f"Está no cache? {'Sim' if '8.8.8.8' in cache_teste else 'Não'}")
    # Cenário 4: IP Inválido
    print("\n[TESTE 4] Consultando IP inválido 999.999.999.999...")
    res4 = consultar_ip("999.999.999.999", cache_teste)
    exibir_enriquecimento(res4)
    # Cenário 6: Enriquecimento em lote com alertas reais
    print("\n[TESTE 6] Enriquecendo lote de alertas mistos...")
    alertas_ficticios = [
        {"id": 1, "regra": "SSH Brute Force", "ip_origem": "1.1.1.1"},
        {"id": 2, "regra": "Port Scan Interno", "ip_origem": "10.0.0.50"},
    ]
    alertas_prontos = enriquecer_alertas(alertas_ficticios, cache_teste)
    for al in alertas_prontos:
        print(f"Alerta ID {al['id']} ({al['regra']}) -> Org: {al['enriquecimento']['org']}")
    print("\n[✔] Todos os cenários concluídos com sucesso!")