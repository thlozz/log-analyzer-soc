#!/usr/bin/env python3
"""Security log analyzer: SSH and Apache/Nginx authentication signals."""
import argparse
import csv
import ipaddress
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

SSH_RE = re.compile(r"(?P<action>Failed password|Accepted (?:password|publickey)) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
SYSLOG_DATE = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<clock>\d\d:\d\d:\d\d)")
WEB_RE = re.compile(r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<date>[^]]+)\]\s+"(?P<method>[A-Z]+)\s+[^"]+\s+HTTP/[\d.]+"\s+(?P<status>\d{3})\s')
WEB_DATE_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def parse_line(line, year):
    ssh = SSH_RE.search(line)
    if ssh and is_valid_ip(ssh.group("ip")):
        stamp = SYSLOG_DATE.match(line)
        when = None
        if stamp:
            try:
                when = datetime.strptime(f"{year} {stamp.group('mon')} {stamp.group('day')} {stamp.group('clock')}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        return (when, ssh.group("ip"), ssh.group("user"), "failure" if ssh.group("action").startswith("Failed") else "success")
    web = WEB_RE.match(line)
    if web and is_valid_ip(web.group("ip")):
        status = int(web.group("status"))
        if status not in (401, 403):
            return None
        try:
            when = datetime.strptime(web.group("date"), WEB_DATE_FORMAT).astimezone(timezone.utc)
        except ValueError:
            when = None
        return (when, web.group("ip"), web.group("user") if web.group("user") != "-" else None, "failure")
    return None


def read_events(file_path, year=None):
    year = year or datetime.now().year
    events = []
    with open(file_path, encoding="utf-8", errors="replace") as stream:
        for line in stream:
            event = parse_line(line, year)
            if event:
                events.append(event)
    return events


def analyze_events(events, threshold=5, window=None):
    failures = Counter()
    users = defaultdict(set)
    histories = defaultdict(list)
    success_after_failures = set()
    for timestamp, ip, username, status in sorted(events, key=lambda e: (e[0] is None, e[0] or datetime.max.replace(tzinfo=timezone.utc))):
        if username:
            users[ip].add(username)
        if status == "failure":
            failures[ip] += 1
            histories[ip].append(timestamp)
        elif status == "success":
            prior = histories[ip]
            if timestamp is not None and window is not None:
                prior = [t for t in prior if t is not None and 0 <= (timestamp - t).total_seconds() <= window * 60]
            elif timestamp is not None:
                prior = [t for t in prior if t is not None and t <= timestamp]
            if prior:
                success_after_failures.add(ip)
    counts = {}
    for ip, total in failures.items():
        if window is None:
            counts[ip] = total
            continue
        times = sorted(t for t in histories[ip] if t is not None)
        left = 0
        maximum = 0
        for right, moment in enumerate(times):
            while (moment - times[left]).total_seconds() > window * 60:
                left += 1
            maximum = max(maximum, right - left + 1)
        counts[ip] = maximum
    return Counter(counts), users, success_after_failures, sum(failures.values())


def analyze_log(file_path):
    """Backward-compatible count of all authentication failures by IP."""
    events = read_events(file_path)
    return Counter(ip for _, ip, _, status in events if status == "failure")


def build_rows(counter, top_n, threshold, users=None, compromised=None, total=None):
    total = sum(counter.values()) if total is None else total
    users = users or {}
    compromised = compromised or set()
    rows = []
    for rank, (ip, count) in enumerate(counter.most_common(top_n), 1):
        status = "COMPROMETIMENTO?" if ip in compromised else ("SUSPEITO" if count >= threshold else "ok")
        rows.append((rank, ip, count, 100 * count / total if total else 0, status, len(users.get(ip, set()))))
    return rows


def display_report(counter, rows, top_n, threshold, window=None):
    print(f"\nRELATÓRIO DE SEGURANÇA — TOP {top_n} IPs")
    print(f"Limiar: {threshold} falhas" + (f" em {window} min (pico por IP)" if window else ""))
    print(f"{'POS':<4} {'IP':<39} {'FALHAS':<8} {'USUÁRIOS':<9} STATUS")
    for rank, ip, count, pct, status, unique_users in rows:
        print(f"{rank:<4} {ip:<39} {count:<8} {unique_users:<9} {status} ({pct:.1f}%)")
    if not rows:
        print("Nenhuma falha encontrada.")


def export_csv(rows, path):
    with open(path, "w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["posicao", "ip", "falhas", "percentual", "status", "usuarios_distintos"])
        for rank, ip, count, percent, status, users in rows:
            writer.writerow([rank, ip, count, f"{percent:.2f}", status, users])


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Analisa tentativas de autenticação SSH e HTTP.")
    parser.add_argument("log_file")
    parser.add_argument("--top", type=int, default=10)
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--window", type=int, help="Janela em minutos para pico de falhas por IP")
    parser.add_argument("--year", type=int, help="Ano atribuído aos timestamps syslog sem ano")
    parser.add_argument("--csv", metavar="ARQUIVO")
    args = parser.parse_args(argv)
    if args.top < 1 or args.threshold < 1 or (args.window is not None and args.window < 1):
        parser.error("--top, --threshold e --window devem ser positivos")
    return args


def main():
    args = parse_args()
    try:
        events = read_events(args.log_file, args.year)
        counter, users, compromised, total = analyze_events(events, args.threshold, args.window)
        rows = build_rows(counter, args.top, args.threshold, users, compromised, total)
        display_report(counter, rows, args.top, args.threshold, args.window)
        if args.csv:
            export_csv(rows, args.csv)
        return 0
    except OSError as exc:
        print(f"Erro ao processar arquivo: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
