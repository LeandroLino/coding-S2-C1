"""SecuraPy SIEM - Ponto de entrada principal.

Menu interativo que orquestra os modulos: coletor, regras, detector,
enriquecimento, servidor de alertas e relatorios.
"""
import sys
import threading

# Garante que caracteres especiais (unicode) sejam exibidos corretamente
# mesmo em consoles Windows configurados com codepage legada (cp1252).
try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

from coletor import carregar_todos_os_logs, verificar_integridade_logs
from regras import carregar_regras, aplicar_regras, adicionar_regra
from detector import (
    detectar_brute_force,
    detectar_brute_force_temporal,
    detectar_port_scan,
    verificar_blacklist,
    gerar_resumo_ameacas,
)
from enriquecimento import enriquecer_alertas, consultar_ip
from relatorios import (
    resumo_geral,
    filtrar_eventos,
    buscar_ip,
    top_ips,
    exportar_relatorio_json,
    exibir_tabela,
    gerar_nome_relatorio,
)
from servidor_alertas import iniciar_servidor
from gerador_logs import gerar_logs_simulados

# Configuracoes
PASTA_LOGS = "logs"
ARQUIVO_REGRAS = "config/regras.json"
BLACKLIST = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}


def exibir_menu():
    """Exibe o menu principal e retorna a opcao escolhida (validada)."""
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
║ 10. Verificar integridade dos logs (SHA-256) ║
║ 11. Gerar logs de teste simulados        ║
║ 12. Criar regra customizada              ║
║  0. Sair                                 ║
╚══════════════════════════════════════════╝
""")
    escolha = input(">> Escolha uma opcao: ").strip()
    try:
        return int(escolha)
    except ValueError:
        print("[!] Opcao invalida.")
        return -1


def main():
    eventos = []
    alertas = []
    resumo_ameacas = []
    brute_force_temporal = {}
    cache_enriquecimento = {}
    logs_carregados = False

    while True:
        opcao = exibir_menu()

        if opcao == 1:
            eventos = carregar_todos_os_logs(PASTA_LOGS)
            regras = carregar_regras(ARQUIVO_REGRAS)
            alertas = aplicar_regras(eventos, regras)

            brute_force = detectar_brute_force(eventos)
            brute_force_temporal = detectar_brute_force_temporal(eventos)
            port_scan = detectar_port_scan(eventos)
            ips_blacklist, _ = verificar_blacklist(eventos, BLACKLIST)
            resumo_ameacas = gerar_resumo_ameacas(brute_force, port_scan, ips_blacklist)

            logs_carregados = True
            contadores = {}
            for evento in eventos:
                contadores[evento.get("fonte")] = contadores.get(evento.get("fonte"), 0) + 1
            partes = ", ".join(f"{qtd} de {fonte}" for fonte, qtd in contadores.items())
            print(f"\n{partes}. Total: {len(eventos)} eventos")
            print(f"Alertas gerados pelas regras: {len(alertas)}")
            print(f"IPs suspeitos no resumo de ameacas: {len(resumo_ameacas)}")
            if brute_force_temporal:
                print("\n--- Brute force com correlacao temporal (janela de 60s) ---")
                for ip, dados in brute_force_temporal.items():
                    print(f"  {ip}: {dados['tentativas_na_janela']} falhas em {dados['janela_segundos']}s ({dados['severidade']})")

        elif opcao == 2:
            if not logs_carregados:
                print("[!] Carregue os logs primeiro (opcao 1).")
                continue
            resumo_geral(eventos, alertas)

        elif opcao == 3:
            if not logs_carregados:
                print("[!] Carregue os logs primeiro (opcao 1).")
                continue
            fonte = input("Filtrar por fonte (auth/firewall/web ou Enter p/ ignorar): ").strip() or None
            tipo = input("Filtrar por tipo (FAIL/BLOCK/... ou Enter p/ ignorar): ").strip() or None
            ip = input("Filtrar por IP (ou Enter p/ ignorar): ").strip() or None
            resultado = filtrar_eventos(eventos, fonte=fonte, tipo=tipo, ip=ip)
            print(f"\n{len(resultado)} evento(s) encontrado(s):")
            for evento in resultado:
                print(f"  [{evento.get('timestamp')}] {evento.get('fonte')} - {evento.get('tipo')} - {evento.get('detalhes')}")

        elif opcao == 4:
            if not logs_carregados:
                print("[!] Carregue os logs primeiro (opcao 1).")
                continue
            ip = input("Digite o IP a buscar: ").strip()
            if ip:
                buscar_ip(ip, eventos, alertas, cache_enriquecimento)

        elif opcao == 5:
            if not logs_carregados:
                print("[!] Carregue os logs primeiro (opcao 1).")
                continue
            ranking = top_ips(eventos, n=10)
            ips_ameaca = {item["ip"] for item in resumo_ameacas}
            for item in ranking:
                marcador = " ⚠ AMEACA" if item["ip"] in ips_ameaca else ""
                item["ameaca"] = "SIM" if item["ip"] in ips_ameaca else "nao"
            exibir_tabela(ranking, ["ip", "eventos", "ameaca"])

        elif opcao == 6:
            if not logs_carregados:
                print("[!] Carregue os logs primeiro (opcao 1).")
                continue
            ordem = ["CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO"]
            for severidade in ordem:
                filtrados = [a for a in alertas if a.get("severidade") == severidade]
                if filtrados:
                    print(f"\n--- {severidade} ({len(filtrados)}) ---")
                    for alerta in filtrados:
                        print(f"  [{alerta.get('timestamp')}] {alerta.get('regra')} - {alerta.get('ip')} - {alerta.get('descricao')}")

        elif opcao == 7:
            if not logs_carregados:
                print("[!] Carregue os logs primeiro (opcao 1).")
                continue
            ips_unicos = sorted({item["ip"] for item in resumo_ameacas})
            if not ips_unicos:
                print("[!] Nenhum IP suspeito identificado ainda.")
                continue
            for ip in ips_unicos:
                dados = consultar_ip(ip, cache_enriquecimento)
                print(f"  {ip}: {dados.get('org')} - {dados.get('cidade')}/{dados.get('pais')}")
            alertas = enriquecer_alertas(alertas, cache_enriquecimento)
            print("[OK] IPs suspeitos enriquecidos e alertas atualizados.")

        elif opcao == 8:
            if not logs_carregados:
                print("[!] Carregue os logs primeiro (opcao 1).")
                continue
            dados_relatorio = {
                "total_eventos": len(eventos),
                "total_alertas": len(alertas),
                "eventos": eventos,
                "alertas": alertas,
                "resumo_ameacas": resumo_ameacas,
                "brute_force_correlacao_temporal": brute_force_temporal,
            }
            caminho = gerar_nome_relatorio("saida")
            exportar_relatorio_json(dados_relatorio, caminho)

        elif opcao == 9:
            porta = input("Porta do servidor (Enter para 9999): ").strip()
            porta = int(porta) if porta.isdigit() else 9999
            print(f"Iniciando servidor de alertas na porta {porta} (thread em segundo plano)...")
            thread_servidor = threading.Thread(target=iniciar_servidor, kwargs={"porta": porta}, daemon=True)
            thread_servidor.start()

        elif opcao == 10:
            resultado_integridade = verificar_integridade_logs(PASTA_LOGS)
            if not resultado_integridade:
                print("[!] Nenhum arquivo de log encontrado para verificar.")
                continue
            print("\n--- Integridade dos arquivos de log (SHA-256) ---")
            for nome_arquivo, info in resultado_integridade.items():
                print(f"  {nome_arquivo}: {info['status'].upper()} (hash: {info['hash_atual'][:12]}...)")

        elif opcao == 11:
            pasta_destino = input("Pasta de destino (Enter para 'logs_simulados'): ").strip() or "logs_simulados"
            gerar_logs_simulados(pasta_destino=pasta_destino)
            print(f"[OK] Logs simulados gerados em '{pasta_destino}/'. Aponte PASTA_LOGS para essa pasta para testa-los.")

        elif opcao == 12:
            print("\n--- Criar nova regra de deteccao ---")
            print("Condicoes suportadas: usuario_privilegiado, porta_critica, path_traversal, xss, reconhecimento")
            id_regra = input("ID da regra (ex: R006): ").strip()
            nome_regra = input("Nome: ").strip()
            descricao_regra = input("Descricao: ").strip()
            fonte_regra = input("Fonte (auth/firewall/web): ").strip()
            condicao_regra = input("Condicao: ").strip()

            nova_regra = {
                "id": id_regra,
                "nome": nome_regra,
                "descricao": descricao_regra,
                "fonte": fonte_regra,
                "condicao": condicao_regra,
                "severidade_base": 0,
                "ativa": True,
            }

            try:
                nova_regra["severidade_base"] = int(input("Severidade base (0-10): ").strip())
            except ValueError:
                print("[!] Valor invalido, usando severidade_base=5.")
                nova_regra["severidade_base"] = 5

            if condicao_regra == "usuario_privilegiado":
                valores = input("Usuarios alvo separados por virgula: ").strip()
                nova_regra["usuarios_alvo"] = [u.strip() for u in valores.split(",") if u.strip()]
            elif condicao_regra == "porta_critica":
                valores = input("Portas criticas separadas por virgula: ").strip()
                nova_regra["portas_criticas"] = [int(p) for p in valores.split(",") if p.strip().isdigit()]
            elif condicao_regra in ("path_traversal", "xss"):
                valores = input("Padroes a detectar na URL, separados por virgula: ").strip()
                nova_regra["padroes"] = [p.strip() for p in valores.split(",") if p.strip()]
            elif condicao_regra == "reconhecimento":
                valores = input("URLs suspeitas separadas por virgula: ").strip()
                nova_regra["urls_suspeitas"] = [u.strip() for u in valores.split(",") if u.strip()]
            else:
                print(f"[!] Condicao '{condicao_regra}' nao e reconhecida pelo motor de regras (regras.py).")

            if adicionar_regra(ARQUIVO_REGRAS, nova_regra):
                print(f"[OK] Regra {id_regra} adicionada em {ARQUIVO_REGRAS}. Recarregue os logs (opcao 1) para aplica-la.")

        elif opcao == 0:
            print("Encerrando SecuraPy. Ate logo!")
            break

        elif opcao != -1:
            print("[!] Opcao invalida.")


if __name__ == "__main__":
    main()
