import unittest
from detector import detectar_brute_force, detectar_port_scan, verificar_blacklist, gerar_resumo_ameacas

class TestDetector(unittest.TestCase):

    def setUp(self):
        self.blacklist = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}

    def test_cenario_1_brute_force_threshold_padrao(self):
        """Cenário 1: Detectar 10 FAILs (ALTA) e 5 FAILs (MEDIA) com threshold=5"""
        eventos = (
            [{"fonte": "auth", "tipo": "FAIL", "ip": "185.220.101.1", "detalhes": "usuario=admin"}] * 10 +
            [{"fonte": "auth", "tipo": "FAIL", "ip": "91.240.118.172", "detalhes": "usuario=root"}] * 5
        )
        res = detectar_brute_force(eventos, threshold=5)
        self.assertEqual(res["185.220.101.1"]["severidade"], "ALTA")
        self.assertEqual(res["91.240.118.172"]["severidade"], "MEDIA")

    def test_cenario_2_port_scan(self):
        """Cenário 2: Detectar 7 portas distintas (ALTA) e 3 portas (MEDIA)"""
        eventos = []
        for porta in [22, 23, 80, 443, 3389, 8080, 21]:
            eventos.append({"fonte": "firewall", "tipo": "BLOCK", "ip": "185.220.101.1", "detalhes": f"dport={porta}"})
        for porta in [80, 443, 22]:
            eventos.append({"fonte": "firewall", "tipo": "BLOCK", "ip": "91.240.118.172", "detalhes": f"dport={porta}"})

        res = detectar_port_scan(eventos, threshold=3)
        self.assertEqual(res["185.220.101.1"]["quantidade"], 7)
        self.assertEqual(res["185.220.101.1"]["severidade"], "ALTA")
        self.assertEqual(res["91.240.118.172"]["quantidade"], 3)
        self.assertEqual(res["91.240.118.172"]["severidade"], "MEDIA")

    def test_cenario_3_intersecao_blacklist(self):
        """Cenário 3: Interseção de sets de IPs com a blacklist"""
        eventos = [
            {"ip": "185.220.101.1"},
            {"ip": "45.33.32.156"},
            {"ip": "91.240.118.172"}
        ]
        ips_enc, _ = verificar_blacklist(eventos, self.blacklist)
        self.assertEqual(ips_enc, {"185.220.101.1", "45.33.32.156", "91.240.118.172"})
        self.assertNotIn("23.94.5.100", ips_enc)

    def test_cenario_4_resumo_consolidado_multiplas_deteccoes(self):
        """Cenário 4: IP em 3 detecções -> Severidade CRITICA"""
        bf = {"185.220.101.1": {"tentativas": 10, "usuarios": ["admin"], "severidade": "ALTA"}}
        ps = {"185.220.101.1": {"portas": {22, 80}, "quantidade": 7, "severidade": "ALTA"}}
        bl = ({"185.220.101.1"}, {"185.220.101.1": 5})

        resumo = gerar_resumo_ameacas(bf, ps, bl)
        self.assertEqual(resumo[0]["ip"], "185.220.101.1")
        self.assertEqual(resumo[0]["severidade"], "CRITICA")

    def test_cenario_5_alterar_threshold_brute_force(self):
        """Cenário 5: Alterar threshold para 15 ignora IP com 10 FAILs"""
        eventos = [{"fonte": "auth", "tipo": "FAIL", "ip": "185.220.101.1", "detalhes": "usuario=admin"}] * 10
        res = detectar_brute_force(eventos, threshold=15)
        self.assertNotIn("185.220.101.1", res)

if __name__ == "__main__":
    unittest.main()