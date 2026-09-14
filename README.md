# SecuraPy — SIEM Simplificado

Projeto final da disciplina **Coding for Security** — SIEM simplificado desenvolvido
para a CyberShield Ltda., capaz de coletar, analisar, correlacionar e alertar sobre
eventos de segurança em tempo real.

## Integrantes

| Nome | Módulo(s) responsável(is) |
|------|---------------------------|
| Samuel — RM 571054 | Módulo 1 — Coletor de Logs (`coletor.py`) + arquivos de log para teste |
| Gabriel Barros — RM 569367 | Módulo 2 — Motor de Regras (`regras.py`) + Módulo 3 — Detector de Anomalias (`detector.py`) + `config/regras.json` |
| Leandro — RM 570697 | Módulo 4 — Comunicação em rede: Servidor de Alertas (`servidor_alertas.py`) + Cliente de Alertas (`cliente_alertas.py`) |
| Vinicius | Módulo 5 — Enriquecimento de IPs (`enriquecimento.py`) + integração com os demais módulos |
| Lucas | Módulo 6 — Dashboard/Relatórios (`relatorios.py`) + `main.py` |

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
├── coletor.py               # Módulo 1 — Leitura e parsing de logs (+ hash de integridade)
├── regras.py                 # Módulo 2 — Motor de regras de detecção (+ regras customizadas)
├── detector.py               # Módulo 3 — Detecção de anomalias e ataques (+ correlação temporal)
├── servidor_alertas.py       # Módulo 4 — Servidor TCP de alertas em tempo real
├── cliente_alertas.py        # Módulo 4 — Cliente TCP que recebe alertas
├── enriquecimento.py         # Módulo 5 — Consulta a APIs de threat intelligence
├── relatorios.py              # Módulo 6 — Dashboard CLI e geração de relatórios
├── gerador_logs.py            # Bônus — gerador de logs simulados (normal + ataques)
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

## Funcionalidades bônus implementadas

- **Correlação temporal de brute force** (`detector.detectar_brute_force_temporal`):
  além da contagem total de falhas por IP, usa uma janela deslizante (padrão
  60s) para identificar rajadas de login falho em curto intervalo de tempo.
  Exibida automaticamente ao carregar os logs (opção 1) e incluída no
  relatório JSON exportado (opção 8).
- **Hash de integridade dos logs** (`coletor.calcular_hash_arquivo` /
  `verificar_integridade_logs`): calcula o SHA-256 de cada arquivo em `logs/`
  e compara com a execução anterior (salva em `config/hashes_logs.json`),
  reportando `novo`, `alterado` ou `inalterado`. Menu → opção **10**.
- **Geração automática de logs simulados** (`gerador_logs.py`): script
  standalone que gera trafego normal + ataques (brute force, port scan, XSS,
  path traversal, reconhecimento) em uma pasta separada (`logs_simulados/`
  por padrão, para não sobrescrever os logs de referência). Pode ser rodado
  via `python gerador_logs.py --destino logs_simulados --semente 42` ou pelo
  menu → opção **11**.
- **Regras customizadas pelo menu** (`regras.adicionar_regra`): o operador
  pode criar uma nova regra de detecção (mesmas condições do motor:
  `usuario_privilegiado`, `porta_critica`, `path_traversal`, `xss`,
  `reconhecimento`) sem editar `config/regras.json` manualmente. Menu →
  opção **12**; recarregue os logs (opção 1) para aplicá-la.

## Como executar

### Dashboard principal

```bash
python main.py
```

Fluxo sugerido: opção **1** (carregar logs) → **2** (resumo) → **5** (top IPs) →
**4** (buscar IP) → **7** (enriquecer) → **8** (exportar relatório). Opções **10**,
**11** e **12** são as funcionalidades bônus (integridade, geração de logs e
regras customizadas — veja a seção acima).

### Demonstração do Módulo 3 (Detector)

```bash
python demonstracao.py
```

Roda os 5 cenários de teste do detector (brute force, port scan, blacklist,
resumo consolidado e mudança de threshold) com dados fictícios, sem depender
dos arquivos em `logs/`.

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
- Arquivo de hashes ausente/corrompido (`config/hashes_logs.json`) é tratado como
  "sem histórico anterior" (todo log aparece como `novo`), sem travar o programa.
- Tentativa de adicionar uma regra customizada com ID duplicado é rejeitada com
  mensagem de erro, sem corromper `config/regras.json`.
