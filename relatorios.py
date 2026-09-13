"""Modulo 6: Dashboard CLI e Relatorios - SecuraPy.

Interface do sistema com o operador: resumo geral, filtros, busca por IP,
top IPs mais ativos e exportacao de relatorio em JSON.
"""
import json
import os
from datetime import datetime


def exibir_menu():
    """Exibe o menu principal e retorna a opcao escolhida (validada como int)."""
    print("""
╔══════════════════════════════════════════╗
║         SecuraPy SIEM — Menu             ║
╠══════════════════════════════════════════╣
║  1. Carregar e processar logs            ║
║  2. Resumo geral                         ║
║  3. Filtrar eventos                      ║
║  4. Buscar IP                            ║
║  5. Top 10 IPs suspeitos                 ║
║  6. Ver alertas por severidade           ║
║  7. Enriquecer IPs suspeitos             ║
║  8. Exportar relatório JSON              ║
║  9. Iniciar servidor de alertas          ║
║  0. Sair                                 ║
╚══════════════════════════════════════════╝
""")
    escolha = input(">> Escolha uma opcao: ").strip()
    try:
        return int(escolha)
    except ValueError:
        print("[!] Opcao invalida. Digite um numero.")
        return -1


def resumo_geral(eventos, alertas):
    """Exibe contadores gerais: eventos por fonte, alertas por severidade."""
    if not eventos:
        print("[!] Nenhum evento carregado. Carregue os logs primeiro (opcao 1).")
        return

    contadores_fonte = {}
    for evento in eventos:
        fonte = evento.get("fonte", "desconhecida")
        contadores_fonte[fonte] = contadores_fonte.get(fonte, 0) + 1

    contadores_severidade = {}
    for alerta in alertas:
        severidade = alerta.get("severidade", "INFO")
        contadores_severidade[severidade] = contadores_severidade.get(severidade, 0) + 1

    partes_fonte = ", ".join(f"{qtd} de {fonte}" for fonte, qtd in contadores_fonte.items())
    print(f"\n{partes_fonte}. Total: {len(eventos)} eventos")

    print("\n--- Alertas por severidade ---")
    if not alertas:
        print("Nenhum alerta gerado.")
    else:
        ordem = ["CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO"]
        for severidade in ordem:
            if severidade in contadores_severidade:
                print(f"  {severidade:<8}: {contadores_severidade[severidade]}")
        print(f"  Total    : {len(alertas)}")


def filtrar_eventos(eventos, fonte=None, tipo=None, ip=None):
    """Retorna eventos filtrados pelos criterios. None = sem filtro."""
    resultado = eventos
    if fonte:
        resultado = [e for e in resultado if e.get("fonte") == fonte]
    if tipo:
        resultado = [e for e in resultado if e.get("tipo") == tipo]
    if ip:
        resultado = [e for e in resultado if e.get("ip") == ip]
    return resultado


def buscar_ip(ip, eventos, alertas, cache_enriquecimento):
    """Exibe relatorio completo de um IP: eventos, alertas e geolocalizacao."""
    from enriquecimento import consultar_ip, exibir_enriquecimento

    eventos_ip = [e for e in eventos if e.get("ip") == ip]
    alertas_ip = [a for a in alertas if a.get("ip") == ip]

    print(f"\n=== Relatorio do IP {ip} ===")
    print(f"Eventos encontrados: {len(eventos_ip)}")
    for evento in eventos_ip:
        print(f"  [{evento.get('timestamp')}] {evento.get('fonte')} - {evento.get('tipo')} - {evento.get('detalhes')}")

    print(f"\nAlertas relacionados: {len(alertas_ip)}")
    for alerta in alertas_ip:
        print(f"  [{alerta.get('severidade')}] {alerta.get('regra')} - {alerta.get('descricao')}")

    dados_geo = consultar_ip(ip, cache_enriquecimento)
    print()
    exibir_enriquecimento(dados_geo)

    return {"eventos": eventos_ip, "alertas": alertas_ip, "enriquecimento": dados_geo}


def top_ips(eventos, n=10):
    """Retorna os N IPs com mais eventos, com contagem e classificacao."""
    contagem = {}
    for evento in eventos:
        ip = evento.get("ip")
        if ip:
            contagem[ip] = contagem.get(ip, 0) + 1

    lista = [{"ip": ip, "eventos": qtd} for ip, qtd in contagem.items()]
    lista.sort(key=lambda item: item["eventos"], reverse=True)
    return lista[:n]


def exportar_relatorio_json(dados, caminho):
    """Salva relatorio completo em JSON formatado."""
    try:
        pasta = os.path.dirname(caminho)
        if pasta:
            os.makedirs(pasta, exist_ok=True)
        with open(caminho, "w", encoding="utf-8") as arquivo:
            json.dump(dados, arquivo, indent=2, ensure_ascii=False, default=str)
        print(f"[OK] Relatorio exportado para: {caminho}")
        return True
    except OSError as erro:
        print(f"[ERRO] Falha ao exportar relatorio: {erro}")
        return False


def exibir_tabela(dados, colunas):
    """Exibe uma lista de dicts como tabela formatada no terminal."""
    if not dados:
        print("(sem dados para exibir)")
        return

    largura = 18
    cabecalho = "".join(f"{coluna:<{largura}}" for coluna in colunas)
    print(cabecalho)
    print("-" * len(cabecalho))
    for linha in dados:
        print("".join(f"{str(linha.get(coluna, '')):<{largura}}" for coluna in colunas))


def gerar_nome_relatorio(pasta_saida="saida"):
    """Gera o nome do arquivo de relatorio com timestamp."""
    nome = datetime.now().strftime("relatorio_%Y%m%d_%H%M%S.json")
    return os.path.join(pasta_saida, nome)
