"""
[BÔNUS +0.20] Gerador automático de logs simulados - SecuraPy SIEM.

Gera arquivos auth.log, firewall.log e web_access.log com uma mistura de
trafego normal e padroes de ataque (brute force, port scan, path traversal,
XSS, reconhecimento), para testar o sistema com volumes/variacoes diferentes
dos logs de exemplo fixos usados na entrega original.

Por padrao escreve em uma pasta separada (logs_simulados/) para nao
sobrescrever os logs de referencia usados nos cenarios de teste do enunciado.
Use --destino logs para gerar direto na pasta oficial, se quiser.
"""
import argparse
import os
import random
from datetime import datetime, timedelta

IPS_INTERNOS = ["192.168.1.10", "192.168.1.20", "192.168.1.45", "10.0.0.5", "10.0.0.6"]
USUARIOS_NORMAIS = ["carlos", "ana", "bruno", "diana", "marcos", "julia"]
USUARIOS_PRIVILEGIADOS = ["admin", "root", "sa", "oracle", "administrator"]
IPS_MALICIOSOS = ["185.220.101.1", "91.240.118.172", "45.33.32.156", "23.94.5.100", "77.88.5.60"]
PORTAS_CRITICAS = [22, 23, 3389, 445, 3306, 5432, 1433]
PORTAS_COMUNS = [80, 443, 8080, 53]
URLS_NORMAIS = ["/index.html", "/api/data", "/api/users", "/robots.txt", "/login"]
URLS_ATAQUE = [
    "/../../etc/passwd",
    "/search?q=<script>alert(1)</script>",
    "/wp-admin",
    "/phpmyadmin",
    "/shell.php",
    "/.env",
]


def _ip_aleatorio_publico():
    """Gera um IPv4 publico aleatorio (fora das faixas privadas)."""
    while True:
        octetos = [random.randint(1, 254) for _ in range(4)]
        if octetos[0] not in (10, 127, 172, 192):
            return ".".join(str(o) for o in octetos)


def gerar_auth_log(n_normais=15, n_ataque_ips=2, falhas_por_ataque=8):
    """Gera linhas do auth.log: logins normais + rajadas de brute force."""
    linhas = []
    momento = datetime(2025, 3, 1, 9, 0, 0)

    for _ in range(n_normais):
        momento += timedelta(seconds=random.randint(2, 12))
        usuario = random.choice(USUARIOS_NORMAIS)
        ip = random.choice(IPS_INTERNOS)
        linhas.append(f"{momento:%Y-%m-%d %H:%M:%S} OK usuario={usuario} ip={ip}")

    ips_ataque = random.sample(IPS_MALICIOSOS, k=min(n_ataque_ips, len(IPS_MALICIOSOS)))
    for ip in ips_ataque:
        for _ in range(falhas_por_ataque):
            momento += timedelta(seconds=random.randint(1, 3))
            usuario = random.choice(USUARIOS_PRIVILEGIADOS)
            linhas.append(f"{momento:%Y-%m-%d %H:%M:%S} FAIL usuario={usuario} ip={ip}")

    return linhas


def gerar_firewall_log(n_normais=12, n_scanners=2, portas_por_scan=6):
    """Gera linhas do firewall.log: trafego liberado normal + port scans."""
    linhas = []
    momento = datetime(2025, 3, 1, 9, 5, 0)

    for _ in range(n_normais):
        momento += timedelta(seconds=random.randint(2, 10))
        ip = random.choice(IPS_INTERNOS)
        porta = random.choice(PORTAS_COMUNS)
        linhas.append(f"{momento:%Y-%m-%d %H:%M:%S} ALLOW proto=TCP src={ip} dst=10.0.0.1 dport={porta}")

    ips_scan = random.sample(IPS_MALICIOSOS, k=min(n_scanners, len(IPS_MALICIOSOS)))
    for ip in ips_scan:
        portas = random.sample(PORTAS_CRITICAS, k=min(portas_por_scan, len(PORTAS_CRITICAS)))
        for porta in portas:
            momento += timedelta(seconds=random.randint(1, 4))
            linhas.append(f"{momento:%Y-%m-%d %H:%M:%S} BLOCK proto=TCP src={ip} dst=10.0.0.1 dport={porta}")

    return linhas


def gerar_web_log(n_normais=10, n_ataques=6):
    """Gera linhas do web_access.log: acessos normais + tentativas de ataque."""
    linhas = []
    momento = datetime(2025, 3, 1, 9, 10, 0)

    for _ in range(n_normais):
        momento += timedelta(seconds=random.randint(2, 8))
        ip = random.choice(IPS_INTERNOS)
        url = random.choice(URLS_NORMAIS)
        linhas.append(f"{momento:%Y-%m-%d %H:%M:%S} GET url={url} ip={ip} status=200")

    for _ in range(n_ataques):
        momento += timedelta(seconds=random.randint(1, 5))
        ip = random.choice(IPS_MALICIOSOS + [_ip_aleatorio_publico()])
        url = random.choice(URLS_ATAQUE)
        linhas.append(f"{momento:%Y-%m-%d %H:%M:%S} GET url={url} ip={ip} status=400")

    return linhas


def salvar_log(linhas, caminho_arquivo):
    """Escreve as linhas geradas em um arquivo, criando a pasta se preciso."""
    pasta = os.path.dirname(caminho_arquivo)
    if pasta:
        os.makedirs(pasta, exist_ok=True)
    try:
        with open(caminho_arquivo, "w", encoding="utf-8") as arquivo:
            arquivo.write("\n".join(linhas) + "\n")
        print(f"[OK] {len(linhas)} linhas escritas em {caminho_arquivo}")
    except OSError as erro:
        print(f"[ERRO] Falha ao escrever {caminho_arquivo}: {erro}")


def gerar_logs_simulados(pasta_destino="logs_simulados", semente=None):
    """Gera os 3 arquivos de log simulados na pasta de destino informada."""
    if semente is not None:
        random.seed(semente)

    salvar_log(gerar_auth_log(), os.path.join(pasta_destino, "auth.log"))
    salvar_log(gerar_firewall_log(), os.path.join(pasta_destino, "firewall.log"))
    salvar_log(gerar_web_log(), os.path.join(pasta_destino, "web_access.log"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Gera logs simulados (trafego normal + ataques) para testar o SecuraPy SIEM."
    )
    parser.add_argument(
        "--destino", default="logs_simulados",
        help="Pasta onde os logs gerados serao salvos (padrao: logs_simulados)",
    )
    parser.add_argument("--semente", type=int, default=None, help="Semente do gerador aleatorio (opcional)")
    args = parser.parse_args()

    gerar_logs_simulados(pasta_destino=args.destino, semente=args.semente)
