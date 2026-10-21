# Analisador de Logs de Segurança (SOC)

Ferramenta de triagem de autenticações SSH e HTTP, desenvolvida exclusivamente com a biblioteca padrão do Python. **Todos os dados de exemplo são fictícios** (IPs de documentação RFC 5737).

## Detecções

- **Força bruta (MITRE ATT&CK T1110):** falhas por IP, com limiar e janela deslizante opcionais.
- **Login aceito após falhas:** marca `COMPROMETIMENTO?` quando há sucesso SSH após falhas anteriores **do mesmo IP**. É um sinal de investigação, não prova de comprometimento. Pode ser relacionado à análise de contas válidas (T1078), mas o evento isolado não confirma essa técnica.
- **Possível password spraying (T1110.003):** `PASSWORD SPRAYING?` quando o IP acumula falhas para pelo menos `--users-threshold` usuários distintos (padrão: 5).
- **HTTP:** contabiliza respostas 401/403 para qualquer método HTTP (GET, POST, HEAD, PATCH, OPTIONS etc.).

Prioridade de classificação: `COMPROMETIMENTO?` > `PASSWORD SPRAYING?` > `SUSPEITO` > `ok`. A correlação é por IP, portanto NAT e proxies podem causar falsos positivos. Os usuários distintos são contados apenas nas falhas com identidade identificada.

## Uso

```bash
python log_analyzer.py sample.log --year 2026
python log_analyzer.py sample.log --window 10 --threshold 5 --year 2026
python log_analyzer.py sample.log --format json --year 2026
python log_analyzer.py sample.log --format csv --year 2026 > ranking.csv
python log_analyzer.py sample.log --csv ranking.csv --html relatorio.html --year 2026
python log_analyzer.py primeiro.log segundo.log --whitelist whitelist.txt
cat sample.log | python log_analyzer.py - --year 2026
python -m unittest -v
```

| Opção | Descrição | Padrão |
| --- | --- | --- |
| `ARQUIVO [ARQUIVO ...]` | Um ou vários arquivos; `-` lê entrada padrão | Obrigatório |
| `--top N` | IPs exibidos | 10 |
| `--threshold N` | Falhas para `SUSPEITO` | 5 |
| `--users-threshold N` | Usuários distintos para `PASSWORD SPRAYING?` | 5 |
| `--window MIN` | Pico de falhas em janela deslizante por IP | Sem janela |
| `--year ANO` | Ano de logs syslog tradicionais | Ano corrente |
| `--format {table,json,csv}` | Formato da saída padrão | table |
| `--csv ARQUIVO` | Exportação CSV adicional (compatibilidade) | Desativado |
| `--whitelist ARQUIVO` | Ignora IPs e redes CIDR listados no arquivo | Desativado |
| `--no-color` | Desativa cores ANSI | Automático |
| `--html ARQUIVO` | HTML estático autocontido, com tabela ordenável | Desativado |

O arquivo de whitelist aceita um IP ou CIDR por linha, além de linhas vazias e comentários iniciados por `#`:

```text
# Rede interna de exemplo
192.0.2.0/24
2001:db8::1
```

## Exemplo de saída real do script

Executado com `python log_analyzer.py sample.log --year 2026` usando o arquivo fictício do repositório:

```text
RELATÓRIO DE SEGURANÇA — TOP 10 IPs
Limiar: 5 falhas
Timestamps inválidos ignorados: 0
Eventos ignorados pela whitelist: 0
POS  IP                                      FALHAS   USUÁRIOS  STATUS
1    192.0.2.10                              5        3         SUSPEITO (29.4%)
2    203.0.113.15                            4        1         ok (23.5%)
3    198.51.100.4                            3        0         ok (17.6%)
4    198.51.100.77                           2        1         COMPROMETIMENTO? (11.8%)
5    192.0.2.55                              2        2         ok (11.8%)
6    198.51.100.9                            1        1         ok (5.9%)
```

**Código de saída:** `2` (há achados). A detecção de `198.51.100.77` envolve duas falhas para `user1` e um sucesso para `maria`; por serem usuários diferentes, não é evidência de que uma conta específica foi comprometida.

## Códigos de saída

- `0`: processamento concluído sem IP sinalizado.
- `2`: ao menos um IP com `COMPROMETIMENTO?`, `PASSWORD SPRAYING?` ou `SUSPEITO`, **mesmo fora do Top N**.
- `1`: erro ao ler arquivo, whitelist ou gerar saída.

Em pipelines, `2` significa **alerta**, não falha técnica. Se necessário, trate-o explicitamente. Em `--format csv`, o resumo de linhas inválidas vai para stderr, mantendo stdout como CSV válido; em JSON, ele aparece em `resumo`.

## Timestamps e limites

- SSH aceita syslog tradicional (`Oct 08 10:15:01`) e ISO 8601 com fuso (`2026-10-08T10:15:01-03:00` ou `Z`).
- O syslog tradicional não informa ano nem fuso: `--year` define o ano e **UTC é uma convenção de demonstração**. Logs HTTP usam o offset presente no evento.
- Linhas de autenticação reconhecidas com timestamp inválido são descartadas e **contadas**. Linhas não relevantes não entram nessa contagem.
- Sem janela, `falhas` representa total por IP; com janela, representa o pico por IP. O percentual continua baseado no total geral de falhas válidas.
- O HTML usa CSS e JavaScript **embutidos** (sem recursos externos) para permitir ordenação por clique ou teclado.
- Não enviar logs de produção, dados pessoais ou segredos a repositórios públicos.

## Testes e integração contínua

```bash
python -m unittest -v
```

O GitHub Actions executa os testes em **Python 3.9, 3.11 e 3.12**. Os testes cobrem parsing, timestamps, whitelist, correlação, CLI, códigos de saída, cores, JSON, CSV e HTML.

## Projetos relacionados

- [Sentinel SOC](https://github.com/thlozz/sentinel-soc)
- [Política de Segurança da Informação](https://github.com/thlozz/psi-clinica-viver-bem)
- [Matriz de Riscos GRC](https://github.com/thlozz/matriz-riscos-grc)
