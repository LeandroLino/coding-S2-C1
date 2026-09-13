from datetime import datetime

# ==========================================
# BLOCO 1: DETECÇÃO DE BRUTE FORCE
# ==========================================
def detectar_brute_force(eventos, threshold=5):
    """
    Conta tentativas FAIL por IP nos eventos de auth.
    Retorna dict: {ip: {"tentativas": N, "usuarios": [...], "severidade": "..."}}
    """
    contagem_falhas = {}
    usuarios_alvo = {}

    for evento in eventos:
        if evento.get("fonte") == "auth" and evento.get("tipo") == "FAIL":
            ip = evento.get("ip")
            if not ip:
                continue

            detalhes = str(evento.get("detalhes", ""))
            usuario = evento.get("usuario")
            if not usuario and "usuario=" in detalhes:
                usuario = detalhes.split("usuario=")[1].split()[0].strip()

            contagem_falhas[ip] = contagem_falhas.get(ip, 0) + 1
            
            if ip not in usuarios_alvo:
                usuarios_alvo[ip] = set()
            if usuario:
                usuarios_alvo[ip].add(usuario)

    resultados = {}
    for ip, total in contagem_falhas.items():
        if total >= threshold:
            if total > 20:
                severidade = "CRITICA"
            elif total >= 10:
                severidade = "ALTA"
            elif total >= 5:
                severidade = "MEDIA"
            else:
                severidade = "BAIXA"

            resultados[ip] = {
                "tentativas": total,
                "usuarios": sorted(list(usuarios_alvo[ip])),
                "severidade": severidade
            }

    return resultados

# =======================================================
# [BÔNUS +0.30] DETECÇÃO DE BRUTE FORCE COM JANELA TEMPORAL
# =======================================================
def detectar_brute_force_temporal(eventos, threshold=5, janela_segundos=60):
    """
    Bônus: Detecta brute force considerando uma janela deslizante de tempo.
    Identifica se ocorreram >= threshold falhas em um intervalo de até 'janela_segundos'.
    """
    tentativas_por_ip = {}

    for evento in eventos:
        if evento.get("fonte") == "auth" and evento.get("tipo") == "FAIL":
            ip = evento.get("ip")
            ts_str = evento.get("timestamp")
            if not ip or not ts_str:
                continue

            try:
                ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue

            if ip not in tentativas_por_ip:
                tentativas_por_ip[ip] = []
            tentativas_por_ip[ip].append(ts)

    resultados_temporais = {}
    for ip, timestamps in tentativas_por_ip.items():
        timestamps.sort()
        max_no_intervalo = 0
        
        # Algoritmo de janela deslizante (sliding window)
        inicio = 0
        for fim in range(len(timestamps)):
            while (timestamps[fim] - timestamps[inicio]).total_seconds() > janela_segundos:
                inicio += 1
            contagem_janela = fim - inicio + 1
            if contagem_janela > max_no_intervalo:
                max_no_intervalo = contagem_janela

        if max_no_intervalo >= threshold:
            severidade = "CRITICA" if max_no_intervalo > 10 else "ALTA"
            resultados_temporais[ip] = {
                "tentativas_na_janela": max_no_intervalo,
                "janela_segundos": janela_segundos,
                "severidade": severidade
            }

    return resultados_temporais

# ==========================================
# BLOCO 2: DETECÇÃO DE PORT SCAN
# ==========================================
def detectar_port_scan(eventos, threshold=3):
    """
    Conta portas únicas (BLOCK) por IP nos eventos de firewall usando set.
    Retorna dict no formato:
    {ip: {"portas": set(...), "quantidade": N, "severidade": "..."}}
    """
    portas_por_ip = {}

    for evento in eventos:
        if evento.get("fonte") == "firewall" and evento.get("tipo") == "BLOCK":
            ip = evento.get("ip")
            if not ip:
                continue

            detalhes = str(evento.get("detalhes", ""))
            porta = evento.get("dport") or evento.get("porta")

            if porta is None and "dport=" in detalhes:
                try:
                    porta = int(detalhes.split("dport=")[1].split()[0].strip(",;"))
                except (IndexError, ValueError):
                    pass

            if porta is not None:
                if ip not in portas_por_ip:
                    portas_por_ip[ip] = set()
                portas_por_ip[ip].add(porta)

    resultados = {}
    for ip, portas in portas_por_ip.items():
        qtd = len(portas)
        if qtd >= threshold:
            severidade = "ALTA" if qtd >= 7 else "MEDIA"
            resultados[ip] = {
                "portas": portas,
                "quantidade": qtd,
                "severidade": severidade
            }

    return resultados

# ==========================================
# BLOCO 3: VERIFICAÇÃO DE BLACKLIST
# ==========================================
def verificar_blacklist(eventos, blacklist):
    """
    Cruza IPs dos eventos com a blacklist usando operações de set.
    Retorna (set_de_ips_maliciosos, dict_com_contagem_por_ip).
    """
    ips_eventos = {e.get("ip") for e in eventos if e.get("ip")}
    blacklist_set = set(blacklist)

    # Operação de interseção de conjuntos (conforme Aula 7.5)
    ips_encontrados = ips_eventos & blacklist_set

    # Contagem de aparições nos eventos para cada IP da blacklist
    contagem = {ip: 0 for ip in ips_encontrados}
    for e in eventos:
        ip = e.get("ip")
        if ip in ips_encontrados:
            contagem[ip] += 1

    return ips_encontrados, contagem

# ==========================================
# BLOCO 4: RESUMO CONSOLIDADO DE AMEAÇAS
# ==========================================
def gerar_resumo_ameacas(brute_force, port_scan, ips_blacklist):
    """
    Consolida todas as detecções em um resumo unificado.
    IPs em múltiplas detecções ganham severidade aumentada (CRITICA).
    Retorna lista de dicts ordenada por severidade.
    """
    if isinstance(ips_blacklist, tuple):
        ips_blacklist_set = set(ips_blacklist[0])
    elif isinstance(ips_blacklist, (set, list)):
        ips_blacklist_set = set(ips_blacklist)
    elif isinstance(ips_blacklist, dict):
        ips_blacklist_set = set(ips_blacklist.keys())
    else:
        ips_blacklist_set = set()

    todos_ips = set(brute_force.keys()) | set(port_scan.keys()) | ips_blacklist_set

    ordem_severidade = {"CRITICA": 4, "ALTA": 3, "MEDIA": 2, "BAIXA": 1, "INFO": 0}
    resumo_dict = {}

    for ip in todos_ips:
        motivos = []
        deteccoes_count = 0
        maior_sev = "INFO"

        if ip in brute_force:
            bf_data = brute_force[ip]
            motivos.append(f"Brute Force ({bf_data['tentativas']} falhas)")
            deteccoes_count += 1
            if ordem_severidade[bf_data["severidade"]] > ordem_severidade[maior_sev]:
                maior_sev = bf_data["severidade"]

        if ip in port_scan:
            ps_data = port_scan[ip]
            motivos.append(f"Port Scan ({ps_data['quantidade']} portas distintas)")
            deteccoes_count += 1
            if ordem_severidade[ps_data["severidade"]] > ordem_severidade[maior_sev]:
                maior_sev = ps_data["severidade"]

        if ip in ips_blacklist_set:
            motivos.append("IP presente na Blacklist")
            deteccoes_count += 1
            if ordem_severidade["ALTA"] > ordem_severidade[maior_sev]:
                maior_sev = "ALTA"

        # Múltiplas detecções: escala a severidade
        if deteccoes_count >= 3:
            maior_sev = "CRITICA"
        elif deteccoes_count == 2:
            if maior_sev in ("BAIXA", "INFO"):
                maior_sev = "MEDIA"
            elif maior_sev == "MEDIA":
                maior_sev = "ALTA"
            elif maior_sev == "ALTA":
                maior_sev = "CRITICA"

        resumo_dict[ip] = {
            "ip": ip,
            "motivos": motivos,
            "severidade": maior_sev,
            "total_deteccoes": deteccoes_count
        }

    lista_resumo = list(resumo_dict.values())
    lista_resumo.sort(key=lambda x: (ordem_severidade[x["severidade"]], x["total_deteccoes"]), reverse=True)

    return lista_resumo