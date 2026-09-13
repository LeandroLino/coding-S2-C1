# SecuraPy — SIEM Simplificado

Projeto final da disciplina **Coding for Security** — SIEM simplificado desenvolvido
para a CyberShield Ltda., capaz de coletar, analisar, correlacionar e alertar sobre
eventos de segurança em tempo real.

## Integrantes

| Nome | Módulo(s) responsável(is) |
|------|---------------------------|
| _(preencher)_ | Módulo 1 — Coletor de Logs |
| _(preencher)_ | Módulo 2 — Motor de Regras / Módulo 5 — Enriquecimento |
| _(preencher)_ | Módulo 3 — Detector de Anomalias |
| _(preencher)_ | Módulo 4 — Servidor/Cliente de Alertas / Módulo 6 — Dashboard e `main.py` |

## Descrição

O SecuraPy lê logs de autenticação, firewall e acesso web, normaliza os eventos,
aplica regras de detecção configuráveis (`config/regras.json`), identifica padrões
de ataque (brute force, port scan, blacklist), envia alertas em tempo real via
socket TCP, enriquece IPs suspeitos com dados de geolocalização (ipinfo.io) e
disponibiliza um dashboard interativo em linha de comando com filtros, busca por
IP e exportação de relatórios em JSON.

## Estrutura do projeto

```
├── main.py                 # Ponto de entrada e menu principal
├── coletor.py               # Módulo 1 — Leitura e parsing de logs
├── regras.py                 # Módulo 2 — Motor de regras de detecção
├── detector.py               # Módulo 3 — Detecção de anomalias e ataques
├── servidor_alertas.py       # Módulo 4 — Servidor TCP de alertas em tempo real
├── cliente_alertas.py        # Módulo 4 — Cliente TCP que recebe alertas
├── enriquecimento.py         # Módulo 5 — Consulta a APIs de threat intelligence
├── relatorios.py              # Módulo 6 — Dashboard CLI e geração de relatórios
├── logs/                     # Arquivos de log de teste (auth, firewall, web)
├── config/regras.json        # Configuração das regras de detecção
├── saida/                    # Relatórios JSON gerados pelo sistema
├── testes/                   # Testes unitários (unittest)
└── demonstracao.py           # Script de demonstração do Módulo 3
```

## Dependências

- Python 3.10+
- [`requests`](https://pypi.org/project/requests/) (usado pelo módulo de enriquecimento)

Instalação:

```bash
pip install requests
```

## Como executar

### Dashboard principal

```bash
python main.py
```

Fluxo sugerido: opção **1** (carregar logs) → **2** (resumo) → **5** (top IPs) →
**4** (buscar IP) → **7** (enriquecer) → **8** (exportar relatório).

### Servidor e cliente de alertas (rede)

Em terminais separados:

```bash
# Terminal 1
python servidor_alertas.py

# Terminal 2 e 3
python cliente_alertas.py
```

Comandos do cliente: `/status`, `/historico`, `/sair`.
Alternativamente, a opção **9** do menu principal inicia o servidor em segundo plano.

### Testes unitários

```bash
$env:PYTHONPATH = "."       # PowerShell
python testes/teste_detector.py
python testes/teste_regras.py
```

## Tratamento de erros

- Arquivos de log inexistentes ou vazios não travam o programa (mensagens amigáveis).
- Linhas malformadas em qualquer log são ignoradas com aviso e não interrompem o processamento.
- `config/regras.json` ausente ou com JSON inválido é tratado, retornando lista vazia de regras.
- Entradas inválidas no menu (`main.py`) não derrubam o programa.
- Erros de rede (timeout, indisponibilidade, IP inválido, HTTP 429) são tratados no módulo de enriquecimento.
- Desconexões de clientes no servidor de alertas são detectadas e tratadas sem derrubar o servidor.
