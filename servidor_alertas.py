"""Modulo 4: Servidor de Alertas em Tempo Real - SecuraPy.

Servidor TCP que aceita multiplos clientes simultaneos (threads), faz
broadcast de alertas gerados pelo SIEM e responde a comandos simples
enviados pelos consoles de monitoramento (clientes).
"""
import socket
import threading
from datetime import datetime

HOST_PADRAO = "0.0.0.0"
PORTA_PADRAO = 9999

clientes = {}          # {conexao: endereco}
historico_alertas = []  # lista dos alertas ja enviados na sessao
lock = threading.Lock()


def formatar_alerta(alerta_dict):
    """Converte dict de alerta em string formatada para exibicao.

    Formato: [TIMESTAMP] [SEVERIDADE] REGRA - IP - Descricao
    """
    timestamp = alerta_dict.get("timestamp", "N/A")
    severidade = alerta_dict.get("severidade", "INFO")
    regra = alerta_dict.get("regra", "Alerta")
    ip = alerta_dict.get("ip", "N/A")
    descricao = alerta_dict.get("descricao", "")
    return f"[{timestamp}] [{severidade}] {regra} - {ip} - {descricao}"


def _enviar_para_conexao(conexao, mensagem):
    """Envia uma mensagem para uma conexao especifica, tratando erros de rede."""
    try:
        conexao.sendall((mensagem + "\n").encode("utf-8"))
        return True
    except (ConnectionResetError, BrokenPipeError, OSError):
        return False


def broadcast_alerta(alerta):
    """Envia um alerta formatado para todos os clientes conectados."""
    mensagem = formatar_alerta(alerta)

    with lock:
        historico_alertas.append(alerta)
        if len(historico_alertas) > 200:
            del historico_alertas[0]
        clientes_desconectados = []
        for conexao in list(clientes.keys()):
            if not _enviar_para_conexao(conexao, mensagem):
                clientes_desconectados.append(conexao)

        for conexao in clientes_desconectados:
            _remover_cliente(conexao)

        total_clientes = len(clientes)

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Alerta enviado para {total_clientes} clientes: {mensagem}")


def _remover_cliente(conexao):
    """Remove um cliente do dicionario de conexoes ativas (assume lock ja adquirido)."""
    endereco = clientes.pop(conexao, None)
    try:
        conexao.close()
    except OSError:
        pass
    if endereco:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Cliente desconectado: {endereco[0]}:{endereco[1]}")


def _processar_comando(conexao, comando):
    """Processa comandos enviados pelo cliente (/status, /historico, /sair)."""
    comando = comando.strip()

    if comando == "/status":
        with lock:
            total_clientes = len(clientes)
            total_alertas = len(historico_alertas)
        _enviar_para_conexao(conexao, f"Clientes conectados: {total_clientes} | Alertas na sessao: {total_alertas}")
        return True

    if comando == "/historico":
        with lock:
            ultimos = historico_alertas[-10:]
        if not ultimos:
            _enviar_para_conexao(conexao, "Nenhum alerta registrado ainda.")
        else:
            for alerta in ultimos:
                _enviar_para_conexao(conexao, formatar_alerta(alerta))
        return True

    if comando == "/sair":
        _enviar_para_conexao(conexao, "Desconectando. Ate logo!")
        return False

    if comando:
        _enviar_para_conexao(conexao, f"Comando desconhecido: {comando}")
    return True


def tratar_cliente(conexao, endereco):
    """Gerencia comunicacao com um cliente individual (roda em thread)."""
    with lock:
        clientes[conexao] = endereco
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Cliente conectado: {endereco[0]}:{endereco[1]}")
    _enviar_para_conexao(conexao, "Bem-vindo ao SecuraPy SIEM! Comandos: /status, /historico, /sair")

    try:
        while True:
            try:
                dados = conexao.recv(1024)
            except (ConnectionResetError, ConnectionAbortedError, OSError):
                break

            if not dados:
                break

            comando = dados.decode("utf-8", errors="ignore")
            if not _processar_comando(conexao, comando):
                break
    finally:
        with lock:
            if conexao in clientes:
                _remover_cliente(conexao)


def iniciar_servidor(host=HOST_PADRAO, porta=PORTA_PADRAO):
    """Inicia o servidor TCP e fica aguardando conexoes."""
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        servidor.bind((host, porta))
        servidor.listen()
    except OSError as erro:
        print(f"[ERRO] Nao foi possivel iniciar o servidor em {host}:{porta}: {erro}")
        return

    print("=== Servidor de Alertas SecuraPy ===")
    print(f"Rodando em {host}:{porta}")
    print("Aguardando conexoes... (Ctrl+C para encerrar)")

    try:
        while True:
            conexao, endereco = servidor.accept()
            thread = threading.Thread(target=tratar_cliente, args=(conexao, endereco), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        print("\nEncerrando servidor...")
        with lock:
            for conexao in list(clientes.keys()):
                _enviar_para_conexao(conexao, "Servidor encerrando a conexao. Ate logo!")
                _remover_cliente(conexao)
    finally:
        servidor.close()


if __name__ == "__main__":
    iniciar_servidor()
