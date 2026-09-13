import unittest
import os
from regras import carregar_regras, aplicar_regras, classificar_severidade, avaliar_regra

class TestRegras(unittest.TestCase):

    def test_cenario_1_usuario_admin(self):
        """Cenário 1: Evento FAIL usuario=admin contra regra R001 -> MEDIA (6 pontos)"""
        regra_r001 = {
            "id": "R001", "nome": "Login com Usuario Privilegiado",
            "fonte": "auth", "condicao": "usuario_privilegiado",
            "usuarios_alvo": ["admin"], "severidade_base": 6, "ativa": True,
            "descricao": "Teste"
        }
        evento = {"fonte": "auth", "timestamp": "2026-05-01", "ip": "10.0.0.1", "detalhes": "usuario=admin"}
        alerta = avaliar_regra(regra_r001, evento)
        self.assertIsNotNone(alerta)
        self.assertEqual(alerta["severidade"], "MEDIA")

    def test_cenario_2_porta_critica(self):
        """Cenário 2: Evento BLOCK dport=22 contra regra R002 -> ALTA (7 pontos)"""
        regra_r002 = {
            "id": "R002", "nome": "Porta Critica",
            "fonte": "firewall", "condicao": "porta_critica",
            "portas_criticas": [22], "severidade_base": 7, "ativa": True,
            "descricao": "Teste"
        }
        evento = {"fonte": "firewall", "timestamp": "2026-05-01", "ip": "10.0.0.1", "detalhes": "dport=22"}
        alerta = avaliar_regra(regra_r002, evento)
        self.assertIsNotNone(alerta)
        self.assertEqual(alerta["severidade"], "ALTA")

    def test_cenario_3_path_traversal(self):
        """Cenário 3: Evento GET url=/../../etc/passwd contra R003 -> CRITICA (9 pontos)"""
        regra_r003 = {
            "id": "R003", "nome": "Path Traversal",
            "fonte": "web", "condicao": "path_traversal",
            "padroes": ["/etc/passwd"], "severidade_base": 9, "ativa": True,
            "descricao": "Teste"
        }
        evento = {"fonte": "web", "timestamp": "2026-05-01", "ip": "10.0.0.1", "detalhes": "GET url=/../../etc/passwd"}
        alerta = avaliar_regra(regra_r003, evento)
        self.assertIsNotNone(alerta)
        self.assertEqual(alerta["severidade"], "CRITICA")

    def test_cenario_4_evento_inofensivo(self):
        """Cenário 4: Evento normal -> Nenhum alerta"""
        regra_r005 = {
            "id": "R005", "fonte": "web", "condicao": "reconhecimento",
            "urls_suspeitas": ["/wp-admin"], "severidade_base": 5, "ativa": True
        }
        evento = {"fonte": "web", "detalhes": "GET url=/index.html"}
        alerta = avaliar_regra(regra_r005, evento)
        self.assertIsNone(alerta)

    def test_cenario_5_regra_desativada(self):
        """Cenário 5: Regra com 'ativa': false -> Ignorada"""
        regra_inativa = {
            "id": "R004", "fonte": "web", "condicao": "xss",
            "padroes": ["<script>"], "severidade_base": 8, "ativa": False
        }
        evento = {"fonte": "web", "detalhes": "<script>alert(1)</script>"}
        alerta = avaliar_regra(regra_inativa, evento)
        self.assertIsNone(alerta)

    def test_cenario_6_json_malformado(self):
        """Cenário 6: Arquivo inexistente ou corrompido -> Retorna lista vazia sem quebrar"""
        regras = carregar_regras("caminho/fantasma.json")
        self.assertEqual(regras, [])

if __name__ == "__main__":
    unittest.main()