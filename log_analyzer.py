#!/usr/bin/env python3
"""
Mini Analisador de Logs de Segurança (SOC / GRC)

Lê um arquivo de log (SSH ou servidor web) e mostra os IPs com mais
tentativas de login falhas. IPs acima de um limiar são marcados como
SUSPEITO (possível força bruta, MITRE ATT&CK T1110 - Brute Force).

Uso:
    python log_analyzer.py sample.log
    python log_analyzer.py sample.log --top 5 --threshold 3 --csv resultado.csv
"""

import argparse
import csv
import ipaddress
import re
import sys
from collections import Counter

# Log SSH (auth.log / secure): cada tentativa falha gera UMA linha "Failed password".
# Não contamos "Invalid user", pois o sshd registra essa mensagem além do
# "Failed password" para a mesma tentativa (contaria em dobro).
SSH_FAILED_REGEX = re.compile(
    r"Failed password for (?:invalid user )?\S+ from (?P<ip>[0-9a-fA-F.:]+)"
)

# Log de servidor web (formato Apache/Nginx "common/combined"):
# IP ident usuario [data] "METODO caminho HTTP/x" STATUS tamanho
# Status 401 (não autenticado) ou 403 (acesso negado).
WEB_FAILED_REGEX = re.compile(
    r'^(?P<ip>[0-9a-fA-F.:]+)\s+\S+\s+\S+\s+\[.*?\]\s+'
    r'"(?:GET|POST|PUT|DELETE)\s+.*?\s+HTTP/[\d.]+"\s+(?P<status>401|403)\s'
)


def is_valid_ip(value: str) -> bool:
    """Confirma que o texto capturado é mesmo um IPv4/IPv6 válido."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def analyze_log(file_path: str) -> Counter:
    """Lê o log linha a linha e conta as falhas de autenticação por IP."""
    counter = Counter()
    with open(file_path, "r", encoding="utf-8", errors="ignore") as log_file:
        for line in log_file:
            match = WEB_FAILED_REGEX.search(line) or SSH_FAILED_REGEX.search(line)
            if match and is_valid_ip(match.group("ip")):
                counter[match.group("ip")] += 1
    return counter


def build_rows(counter: Counter, top_n: int, threshold: int) -> list:
    """Monta as linhas do ranking: (posição, ip, falhas, percentual, status)."""
    total = sum(counter.values())
    rows = []
    for rank, (ip, count) in enumerate(counter.most_common(top_n), start=1):
        percent = (count / total) * 100 if total else 0.0
        status = "SUSPEITO" if count >= threshold else "ok"
        rows.append((rank, ip, count, percent, status))
    return rows


def display_report(counter: Counter, rows: list, top_n: int, threshold: int) -> None:
    """Imprime o relatório no terminal."""
    total = sum(counter.values())
    width = 72
    print("\n" + "=" * width)
    print(f"RELATÓRIO DE SEGURANÇA: TOP {top_n} IPs COM LOGIN FALHO".center(width))
    print("=" * width)
    print(f"Total de falhas detectadas: {total}")
    print(f"Limiar para SUSPEITO: {threshold} falhas ou mais\n")

    if not rows:
        print("Nenhuma tentativa de login falha foi encontrada no log.")
        print("=" * width)
        return

    print(f"{'POS':<5} | {'ENDEREÇO IP':<20} | {'FALHAS':<8} | {'% DO TOTAL':<10} | STATUS")
    print("-" * width)
    for rank, ip, count, percent, status in rows:
        print(f"{rank:<5} | {ip:<20} | {count:<8} | {percent:>9.2f}% | {status}")
    print("=" * width + "\n")


def export_csv(rows: list, path: str) -> None:
    """Exporta o ranking para CSV."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["posicao", "ip", "falhas", "percentual", "status"])
        for rank, ip, count, percent, status in rows:
            writer.writerow([rank, ip, count, f"{percent:.2f}", status])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Identifica IPs com muitas tentativas de login falhas (SSH ou web)."
    )
    parser.add_argument("log_file", help="caminho do arquivo de log")
    parser.add_argument("--top", type=int, default=10, help="quantidade de IPs no ranking (padrão: 10)")
    parser.add_argument("--threshold", type=int, default=5,
                        help="falhas mínimas para marcar como SUSPEITO (padrão: 5)")
    parser.add_argument("--csv", metavar="ARQUIVO", help="exporta o ranking para um arquivo CSV")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        counter = analyze_log(args.log_file)
    except FileNotFoundError:
        print(f"[ERRO] O arquivo '{args.log_file}' não foi encontrado.", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"[ERRO] Falha ao ler o arquivo: {e}", file=sys.stderr)
        return 1

    rows = build_rows(counter, args.top, args.threshold)
    display_report(counter, rows, args.top, args.threshold)

    if args.csv:
        export_csv(rows, args.csv)
        print(f"Ranking exportado para '{args.csv}'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
