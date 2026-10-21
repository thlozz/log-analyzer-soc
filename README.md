# Analisador de Logs de Segurança

Ferramenta Python sem dependências externas para triagem de autenticações SSH e respostas HTTP 401/403. Dados de demonstração fictícios.

## Recursos
- Interpretação de falhas e sucessos SSH (`Failed password`, `Accepted password`, `Accepted publickey`).
- Detecção de **sucesso SSH após falhas anteriores do mesmo IP**: `COMPROMETIMENTO?` indica investigação necessária, **não comprometimento confirmado**.
- Análise de HTTP 401/403 com qualquer método HTTP (incluindo HEAD, PATCH e OPTIONS).
- Contagem de usuários distintos por IP, útil como sinal auxiliar para password spraying.
- `--window` calcula o **pico de falhas por IP em uma janela deslizante**, sem dupla contagem de eventos; `--year` define o ano dos timestamps syslog.
- Exportação CSV, validação de IP e testes unitários.

## Uso
```bash
python log_analyzer.py sample.log
python log_analyzer.py sample.log --top 10 --threshold 5 --window 10 --year 2026
python log_analyzer.py sample.log --csv resultado.csv
python -m unittest discover -s tests -v
```

| Parâmetro | Descrição | Padrão |
| --- | --- | --- |
| `--top` | Quantidade de IPs exibidos | 10 |
| `--threshold` | Pico de falhas para status SUSPEITO | 5 |
| `--window` | Janela deslizante em minutos | Sem janela |
| `--year` | Ano para timestamps SSH sem ano | Ano corrente |
| `--csv` | Caminho do CSV exportado | Desativado |

## Notas de detecção
- No `sample.log`, o IP `198.51.100.77` apresenta duas falhas e depois um sucesso SSH, **para usuários diferentes**. O sinal é registrado por IP e precisa de investigação; não é prova de invasão de conta.
- Sem `--window`, as falhas são acumuladas em todo o arquivo. Com janela, a coluna de falhas representa o **máximo em uma janela**, não o total histórico; o percentual é calculado sobre o total de falhas.
- Os timestamps de syslog são interpretados em UTC por convenção de demonstração; logs web usam o fuso declarado.
- Respostas HTTP 403 podem ser autorização negada em páginas que não são de login. Dados sem usuário identificado não contribuem para a contagem de usuários distintos.
- A detecção de sucesso após falhas é correlacionada por **IP**, não por identidade, e pode produzir falsos positivos em redes NAT.
- Em caso de janela configurada, a correlação de sucesso considera falhas do mesmo IP dentro da janela.
- Não utilizar dados sensíveis ou logs reais de clientes neste projeto público.

## Projetos relacionados
- [Sentinel SOC](https://github.com/thlozz/sentinel-soc)
- [Política de Segurança da Informação](https://github.com/thlozz/psi-clinica-viver-bem)
- [Matriz de Riscos GRC](https://github.com/thlozz/matriz-riscos-grc)
