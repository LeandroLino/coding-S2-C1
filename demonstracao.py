from detector import (
    detectar_brute_force,
    detectar_port_scan,
    verificar_blacklist,
    gerar_resumo_ameacas
)

# Dados de Teste
BLACKLIST = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}

# Simulação de eventos do log
eventos_auth = (
    [{"fonte": "auth", "tipo": "FAIL", "ip": "185.220.101.1", "detalhes": "usuario=admin"}] * 10 +
    [{"fonte": "auth", "tipo": "FAIL", "ip": "91.240.118.172", "detalhes": "usuario=root"}] * 5 +
    [{"fonte": "auth", "tipo": "FAIL", "ip": "45.33.32.156", "detalhes": "usuario=user"}] * 3
)

eventos_firewall = []
for porta in [22, 23, 80, 443, 3389, 8080, 21]:
    eventos_firewall.append({"fonte": "firewall", "tipo": "BLOCK", "ip": "185.220.101.1", "detalhes": f"dport={porta}"})
for porta in [80, 443, 22]:
    eventos_firewall.append({"fonte": "firewall", "tipo": "BLOCK", "ip": "91.240.118.172", "detalhes": f"dport={porta}"})

todos_eventos = eventos_auth + eventos_firewall

print("="*60)
print("PROVA DOS CENÁRIOS DE TESTE — MÓDULO 3")
print("="*60)

# Cenário 1
print("\n[Cenário 1] Processar auth.log (threshold=3 para mostrar BAIXA):")
bf_c1 = detectar_brute_force(eventos_auth, threshold=1)
for ip, dados in bf_c1.items():
    print(f"  IP {ip}: {dados['tentativas']} FAILs ({dados['severidade']})")

# Cenário 2
print("\n[Cenário 2] Processar firewall.log:")
ps_c2 = detectar_port_scan(eventos_firewall, threshold=3)
for ip, dados in ps_c2.items():
    print(f"  IP {ip}: {dados['quantidade']} portas distintas ({dados['severidade']})")

# Cenário 3
print("\n[Cenário 3] Cruzar IPs com blacklist:")
ips_enc, _ = verificar_blacklist(todos_eventos, BLACKLIST)
print(f"  Interseção encontrada: {ips_enc}")
print(f"  IP 23.94.5.100 está nos logs? {'23.94.5.100' in ips_enc}")

# Cenário 4
print("\n[Cenário 4] Resumo consolidado:")
resumo = gerar_resumo_ameacas(
    detectar_brute_force(eventos_auth, threshold=5),
    ps_c2,
    (ips_enc, {})
)
for item in resumo:
    print(f"  IP {item['ip']}: Aparece em {item['total_deteccoes']} detecção(ões) -> Severidade: {item['severidade']}")

# Cenário 5
print("\n[Cenário 5] Threshold de brute force alterado para 15:")
bf_c5 = detectar_brute_force(eventos_auth, threshold=15)
print(f"  IPs detectados: {list(bf_c5.keys())} (nenhum atingiu 15 FAILs)")