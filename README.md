# Analisador de Logs de Segurança (`log_analyzer.py`)

Script em Python que automatiza a triagem de possíveis ataques de **força bruta** (MITRE ATT&CK **T1110 – Brute Force**) em logs de **SSH** e de **servidores web**. Todos os dados de exemplo são fictícios.

## O que ele faz
- Detecta tentativas de login falhas:
  - **SSH:** linhas `Failed password` (inclui usuários inexistentes).
  - **Web:** respostas HTTP `401` (não autenticado) e `403` (acesso negado).
- Extrai e valida o IP de origem (IPv4 e IPv6).
- Gera um ranking dos **IPs com mais falhas**, com o percentual do total.
- Marca como **SUSPEITO** os IPs acima de um limiar configurável.
- Exporta o resultado em **CSV** (opcional).

## Como usar
```bash
python log_analyzer.py sample.log
python log_analyzer.py sample.log --top 5 --threshold 3 --csv resultado.csv
```

| Argumento | Descrição | Padrão |
| :--- | :--- | :---: |
| `log_file` | Caminho do arquivo de log | obrigatório |
| `--top` | Quantidade de IPs no ranking | 10 |
| `--threshold` | Falhas mínimas para marcar como SUSPEITO | 5 |
| `--csv` | Exporta o ranking para CSV | desativado |

## Exemplo de saída (`sample.log`)
```text

========================================================================
           RELATÓRIO DE SEGURANÇA: TOP 10 IPs COM LOGIN FALHO           
========================================================================
Total de falhas detectadas: 17
Limiar para SUSPEITO: 5 falhas ou mais

POS   | ENDEREÇO IP          | FALHAS   | % DO TOTAL | STATUS
------------------------------------------------------------------------
1     | 192.0.2.10           | 5        |     29.41% | SUSPEITO
2     | 203.0.113.15         | 4        |     23.53% | ok
3     | 198.51.100.4         | 3        |     17.65% | ok
4     | 198.51.100.77        | 2        |     11.76% | ok
5     | 192.0.2.55           | 2        |     11.76% | ok
6     | 198.51.100.9         | 1        |      5.88% | ok
========================================================================
```

## Decisões e limitações
- **Sem dupla contagem:** o `sshd` registra `Invalid user` **e** `Failed password` para a mesma tentativa. O script conta apenas `Failed password`.
- **Status 403** pode ser acesso negado a uma página, e não necessariamente falha de login. Em produção, vale filtrar por rotas de login.
- **Limiar fixo:** o valor padrão (5 falhas) é ilustrativo. Em um SOC real, o limiar deve considerar janela de tempo (ex.: 5 falhas em 1 minuto), o que é uma melhoria futura.
- **Formatos suportados:** `auth.log`/`secure` do OpenSSH e logs web no formato *common/combined* (Apache/Nginx).
- IPs privados e de documentação (RFC 5737) são usados apenas para teste.

## Relação com GRC
A mitigação desse tipo de ataque está prevista na Política de Segurança (seção 5.3, bloqueio de conta após 5 tentativas) e no risco **R-04** (credenciais fracas) da Matriz de Riscos do projeto.

## Próximos passos
- Janela de tempo na detecção (taxa de falhas por minuto).
- Teste com um *dataset* público de `auth.log`.
- Integração com alertas (e-mail ou webhook).
