import json

# ==========================================
# BLOCO 1: CARREGAMENTO DO JSON
# ==========================================
def carregar_regras(caminho_config):
    """
    Lê o arquivo regras.json e retorna a lista de dicionários de regras.
    Trata exceções de arquivo não encontrado e JSON malformado.
    """
    try:
        with open(caminho_config, 'r', encoding='utf-8') as arquivo:
            dados = json.load(arquivo)
            if isinstance(dados, dict):
                return dados.get("regras", [])
            return []
    except FileNotFoundError:
        print(f"[ERRO] Arquivo de regras não encontrado em: {caminho_config}")
        return []
    except json.JSONDecodeError:
        print(f"[ERRO] Formato JSON inválido no arquivo: {caminho_config}")
        return []

# ==========================================
# BLOCO 2: CLASSIFICAÇÃO DE SEVERIDADE
# ==========================================
def classificar_severidade(pontuacao):
    """
    Classifica a pontuação numérica conforme regra oficial:
    >= 9: CRITICA, >= 7: ALTA, >= 5: MEDIA, >= 3: BAIXA, < 3: INFO
    """
    if pontuacao >= 9:
        return "CRITICA"
    elif pontuacao >= 7:
        return "ALTA"
    elif pontuacao >= 5:
        return "MEDIA"
    elif pontuacao >= 3:
        return "BAIXA"
    return "INFO"

# ==========================================
# BLOCO 3: AVALIAÇÃO INDIVIDUAL DE REGRA
# ==========================================
def avaliar_regra(regra, evento):
    """
    Avalia se um único evento viola uma regra específica baseada na chave "condicao".
    Retorna o dicionário do alerta se violar, ou None caso contrário.
    """
    if not regra.get("ativa", True):
        return None
        
    if evento.get("fonte") != regra.get("fonte"):
        return None

    condicao = regra.get("condicao")
    detalhes = str(evento.get("detalhes", ""))
    disparou = False

    # Condição 1: Usuário Privilegiado (Logins com root, admin, etc.)
    if condicao == "usuario_privilegiado":
        usuario = evento.get("usuario")
        if not usuario and "usuario=" in detalhes:
            usuario = detalhes.split("usuario=")[1].split()[0].strip()
        
        # Suporta tanto extração exata quanto busca em detalhes
        if usuario:
            disparou = usuario in regra.get("usuarios_alvo", [])
        else:
            disparou = any(f"usuario={u}" in detalhes for u in regra.get("usuarios_alvo", []))

    # Condição 2: Porta Crítica no Firewall
    elif condicao == "porta_critica":
        porta = evento.get("dport") or evento.get("porta")
        if porta is None and "dport=" in detalhes:
            try:
                porta = int(detalhes.split("dport=")[1].split()[0].strip(",;"))
            except (IndexError, ValueError):
                pass
        
        if porta is not None:
            disparou = porta in regra.get("portas_criticas", [])
        else:
            disparou = any(f"dport={p}" in detalhes for p in regra.get("portas_criticas", []))

    # Condições 3, 4 e 5: Web (Path Traversal, XSS, Reconhecimento)
    elif condicao in ("path_traversal", "xss"):
        url = evento.get("url") or detalhes
        disparou = any(padrao in url for padrao in regra.get("padroes", []))

    elif condicao == "reconhecimento":
        url = evento.get("url") or detalhes
        disparou = any(url_suspeita in url for url_suspeita in regra.get("urls_suspeitas", []))

    # Constrói o alerta caso a regra tenha disparado
    if disparou:
        pontos = regra.get("severidade_base", 0)
        return {
            "timestamp": evento.get("timestamp"),
            "regra": regra.get("nome"),
            "severidade": classificar_severidade(pontos),
            "ip": evento.get("ip"),
            "descricao": regra.get("descricao")
        }

    return None

# ==========================================
# BLOCO 4: APLICAÇÃO GERAL DAS REGRAS
# ==========================================
def aplicar_regras(eventos, regras):
    """
    Aplica todas as regras ativas sobre a lista de eventos.
    Retorna a lista de alertas gerados.
    """
    regras_ativas = [r for r in regras if r.get("ativa", True)]
    alertas = []
    for evento in eventos:
        for regra in regras_ativas:
            alerta = avaliar_regra(regra, evento)
            if alerta:
                alertas.append(alerta)
    return alertas