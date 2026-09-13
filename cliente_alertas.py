"""Modulo 4: Cliente de Alertas em Tempo Real - SecuraPy.

Cliente TCP que se conecta ao servidor de alertas do SecuraPy, exibe
alertas recebidos em tempo real e permite enviar comandos (/status,
/historico, /sair).
"""
import socket
import threading

HOST_PADRAO = "127.0.0.1"
PORTA_PADRAO = 9999


def receber_alertas(cliente):
    """Thread que recebe e exibe alertas/mensagens do servidor."""
    while True:
        try:
            dados = cliente.recv(1024)
        except (ConnectionResetError, OSError):
            print("\n[!] Conexao com o servidor perdida.")
            break

        if not dados:
            print("\n[!] Servidor encerrou a conexao.")
            break

        mensagem = dados.decode("utf-8", errors="ignore").strip()
        for linha in mensagem.splitlines():
            print(linha)


def conectar_servidor(host=HOST_PADRAO, porta=PORTA_PADRAO):
    """Conecta ao servidor e fica recebendo alertas, permitindo enviar comandos."""
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        cliente.connect((host, porta))
    except (ConnectionRefusedError, OSError) as erro:
        print(f"[ERRO] Nao foi possivel conectar ao servidor {host}:{porta}: {erro}")
        return

    print(f"Conectado ao SecuraPy SIEM ({host}:{porta})")
    print("Comandos: /status, /historico, /sair")

    thread_recebimento = threading.Thread(target=receber_alertas, args=(cliente,), daemon=True)
    thread_recebimento.start()

    try:
        while True:
            comando = input()
            if not comando:
                continue
            try:
                cliente.sendall(comando.encode("utf-8"))
            except (BrokenPipeError, OSError):
                print("[!] Falha ao enviar comando: conexao perdida.")
                break
            if comando.strip() == "/sair":
                break
    except (KeyboardInterrupt, EOFError):
        print("\nEncerrando cliente...")
    finally:
        cliente.close()


if __name__ == "__main__":
    conectar_servidor()
