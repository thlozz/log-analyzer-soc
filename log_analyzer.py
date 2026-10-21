#!/usr/bin/env python3
"""Analisador de logs SSH e HTTP sem dependências externas."""
import argparse
import csv
import html
import ipaddress
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

SSH = re.compile(r"(?P<action>Failed password|Accepted (?:password|publickey)) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
SYSLOG = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<clock>\d\d:\d\d:\d\d)")
ISO = re.compile(r"^(?P<stamp>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d))(?=\s)")
WEB = re.compile(r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<date>[^]]+)\]\s+"(?P<method>[A-Z]+)\s+[^"]+\s+HTTP/[\d.]+"\s+(?P<status>\d{3})\s')
COLS = ["posicao", "ip", "falhas", "percentual", "status", "usuarios_distintos"]

def is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def parse_line(line, year):
    """Evento reconhecido com timestamp inválido gera ValueError."""
    ssh = SSH.search(line)
    if ssh and is_valid_ip(ssh.group("ip")):
        iso, stamp = ISO.match(line), SYSLOG.match(line)
        try:
            if iso:
                when = datetime.fromisoformat(iso.group("stamp").replace("Z", "+00:00")).astimezone(timezone.utc)
            elif stamp:
                date = "{} {} {} {}".format(year, stamp.group("mon"), stamp.group("day"), stamp.group("clock"))
                when = datetime.strptime(date, "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
            else:
                raise ValueError("data ausente")
        except ValueError as exc:
            raise ValueError("timestamp SSH inválido") from exc
        return when, ssh.group("ip"), ssh.group("user"), "failure" if ssh.group("action").startswith("Failed") else "success"
    web = WEB.match(line)
    if web and is_valid_ip(web.group("ip")):
        if int(web.group("status")) not in (401, 403):
            return None
        try:
            when = datetime.strptime(web.group("date"), "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
        except ValueError as exc:
            raise ValueError("timestamp HTTP inválido") from exc
        return when, web.group("ip"), web.group("user") if web.group("user") != "-" else None, "failure"
    return None

def load_whitelist(path):
    networks = []
    with open(path, encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            item = line.split("#", 1)[0].strip()
            if item:
                try:
                    networks.append(ipaddress.ip_network(item, strict=False))
                except ValueError as exc:
                    raise ValueError("Whitelist linha {}: {}".format(number, item)) from exc
    return networks

def read_events(paths, year=None, whitelist=None, stdin=None, return_stats=False):
    year = datetime.now().year if year is None else year
    paths = [paths] if isinstance(paths, (str, Path)) else list(paths)
    whitelist, stdin = whitelist or [], sys.stdin if stdin is None else stdin
    events, invalid, excluded = [], 0, 0
    for path in paths:
        stream = stdin if path == "-" else open(path, encoding="utf-8", errors="replace")
        try:
            for line in stream:
                try:
                    event = parse_line(line, year)
                except ValueError:
                    invalid += 1
                    continue
                if event is None:
                    continue
                if any(ipaddress.ip_address(event[1]) in net for net in whitelist):
                    excluded += 1
                    continue
                events.append(event)
        finally:
            if path != "-":
                stream.close()
    stats = {"timestamps_invalidos": invalid, "eventos_whitelist": excluded}
    return (events, stats) if return_stats else events

def analyze_events(events, threshold=5, window=None):
    failures, users, history, accepted = Counter(), defaultdict(set), defaultdict(list), set()
    for when, ip, username, status in sorted(events, key=lambda e: e[0]):
        if status == "failure":
            failures[ip] += 1
            history[ip].append(when)
            if username:
                users[ip].add(username)
        elif status == "success":
            prior = history[ip]
            if window is not None:
                prior = [t for t in prior if 0 <= (when-t).total_seconds() <= window*60]
            if prior:
                accepted.add(ip)
    counts = Counter()
    for ip, total in failures.items():
        if window is None:
            counts[ip] = total
        else:
            times, left, maximum = history[ip], 0, 0
            for right, moment in enumerate(times):
                while (moment-times[left]).total_seconds() > window*60:
                    left += 1
                maximum = max(maximum, right-left+1)
            counts[ip] = maximum
    return counts, users, accepted, sum(failures.values())

def analyze_log(file_path):
    """Compatibilidade: conta todas as falhas por IP."""
    return Counter(ip for _, ip, _, status in read_events(file_path) if status == "failure")

def build_rows(counter, top_n, threshold, users=None, compromised=None, total=None, users_threshold=5):
    total = sum(counter.values()) if total is None else total
    users, compromised = users or {}, compromised or set()
    rows = []
    for rank, (ip, count) in enumerate(counter.most_common(top_n), 1):
        distinct = len(users.get(ip, set()))
        if ip in compromised:
            status = "COMPROMETIMENTO?"
        elif distinct >= users_threshold:
            status = "PASSWORD SPRAYING?"
        elif count >= threshold:
            status = "SUSPEITO"
        else:
            status = "ok"
        rows.append((rank, ip, count, 100*count/total if total else 0, status, distinct))
    return rows

def report_dict(rows, stats, total, window):
    return {"resumo": {"falhas_totais": total, "ips_exibidos": len(rows), "janela_minutos": window,
                       "timestamps_invalidos": stats["timestamps_invalidos"],
                       "eventos_whitelist": stats["eventos_whitelist"]},
            "resultados": [dict(zip(COLS, (rank, ip, count, round(pct, 2), status, users)))
                           for rank, ip, count, pct, status, users in rows]}

def display_report(counter, rows, top_n, threshold, window=None, stats=None, color=False):
    stats = stats or {"timestamps_invalidos": 0, "eventos_whitelist": 0}
    print("\nRELATÓRIO DE SEGURANÇA — TOP {} IPs".format(top_n))
    print("Limiar: {} falhas{}".format(threshold, " em {} min (pico por IP)".format(window) if window else ""))
    print("Timestamps inválidos ignorados: {}".format(stats["timestamps_invalidos"]))
    print("Eventos ignorados pela whitelist: {}".format(stats["eventos_whitelist"]))
    print("{:<4} {:<39} {:<8} {:<9} STATUS".format("POS", "IP", "FALHAS", "USUÁRIOS"))
    for rank, ip, count, pct, status, distinct in rows:
        shown = status
        if color:
            code = "31" if status == "COMPROMETIMENTO?" else "33" if status in ("SUSPEITO", "PASSWORD SPRAYING?") else None
            if code:
                shown = "\033[{}m{}\033[0m".format(code, status)
        print("{:<4} {:<39} {:<8} {:<9} {} ({:.1f}%)".format(rank, ip, count, distinct, shown, pct))
    if not rows:
        print("Nenhuma falha encontrada.")

def write_csv(stream, rows):
    writer = csv.writer(stream)
    writer.writerow(COLS)
    for rank, ip, count, pct, status, users in rows:
        writer.writerow([rank, ip, count, "{:.2f}".format(pct), status, users])

def export_csv(rows, path):
    with open(path, "w", newline="", encoding="utf-8") as stream:
        write_csv(stream, rows)

def export_html(rows, stats, total, path):
    """Relatório autocontido, com ordenação por JavaScript embutido."""
    labels = ["Posição", "IP", "Falhas", "% do total", "Status", "Usuários distintos"]
    style = "body{font:15px system-ui,sans-serif;background:#0d121a;color:#e7ebf1;margin:32px}table{border-collapse:collapse;width:100%}th,td{padding:10px;border-bottom:1px solid #303b49;text-align:left}th{background:#172232;cursor:pointer}th:focus{outline:2px solid #8ac5ff}.bad{color:#ff7186}.warn{color:#ffd16d}"
    parts = ['<!doctype html><html lang="pt-BR"><meta charset="utf-8"><title>Relatório SOC</title><style>{}</style><body>'.format(style),
             '<h1>Relatório de segurança — dados de demonstração</h1>',
             '<p>Falhas totais: {} | IPs exibidos: {} | Timestamps inválidos: {} | Eventos whitelist: {}</p>'.format(total,len(rows),stats["timestamps_invalidos"],stats["eventos_whitelist"]),
             '<p>Clique no cabeçalho para ordenar.</p>',
             '<table id="resultados"><thead><tr>' + ''.join('<th scope="col" tabindex="0" data-col="{}">{}</th>'.format(i,label) for i,label in enumerate(labels)) + '</tr></thead><tbody>']
    for rank, ip, count, pct, status, distinct in rows:
        cls = ' class="bad"' if status == "COMPROMETIMENTO?" else ' class="warn"' if status != "ok" else ""
        cells = [rank,ip,count,"{:.2f}".format(pct),status,distinct]
        parts.append("<tr>" + "".join("<td{}>{}</td>".format(cls if i==4 else "",html.escape(str(v))) for i,v in enumerate(cells)) + "</tr>")
    parts.append("</tbody></table>")
    parts.append("""<script>
    const tabela=document.querySelector('#resultados');
    let anterior=-1,crescente=true;
    function ordenar(coluna){
      crescente=anterior===coluna?!crescente:true; anterior=coluna;
      const linhas=Array.from(tabela.tBodies[0].rows);
      linhas.sort((a,b)=>{
        const av=a.cells[coluna].textContent.trim(),bv=b.cells[coluna].textContent.trim();
        const numeric=[0,2,3,5].includes(coluna);
        const resultado=numeric?Number(av)-Number(bv):av.localeCompare(bv,'pt-BR');
        return crescente?resultado:-resultado;
      });
      linhas.forEach(linha=>tabela.tBodies[0].appendChild(linha));
    }
    tabela.querySelectorAll('th').forEach(c=>{
      const i=Number(c.dataset.col);
      c.addEventListener('click',()=>ordenar(i));
      c.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();ordenar(i);}});
    });
    </script></body></html>""")
    Path(path).write_text("\n".join(parts), encoding="utf-8")

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Analisa autenticações SSH e HTTP.")
    parser.add_argument("log_files", nargs="+", metavar="ARQUIVO", help="Um ou mais arquivos; '-' lê stdin")
    parser.add_argument("--top", type=int, default=10)
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--users-threshold", type=int, default=5)
    parser.add_argument("--window", type=int)
    parser.add_argument("--year", type=int)
    parser.add_argument("--format", choices=("table","json","csv"), default="table")
    parser.add_argument("--csv", metavar="ARQUIVO", help="Exportação CSV adicional")
    parser.add_argument("--whitelist", metavar="ARQUIVO", help="IPs/CIDRs ignorados")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--html", metavar="RELATORIO.html")
    args = parser.parse_args(argv)
    if args.top<1 or args.threshold<1 or args.users_threshold<1 or (args.window is not None and args.window<1):
        parser.error("Parâmetros de limiar e janela devem ser positivos")
    return args

def main(argv=None):
    args = parse_args(argv)
    try:
        whitelist = load_whitelist(args.whitelist) if args.whitelist else []
        events, stats = read_events(args.log_files, args.year, whitelist, return_stats=True)
        counter, users, compromised, total = analyze_events(events, args.threshold, args.window)
        all_rows = build_rows(counter, len(counter), args.threshold, users, compromised, total, args.users_threshold)
        rows = all_rows[:args.top]
        if args.format == "json":
            print(json.dumps(report_dict(rows, stats, total, args.window), ensure_ascii=False, indent=2))
        elif args.format == "csv":
            write_csv(sys.stdout, rows)
            print("Timestamps inválidos ignorados: {}; eventos whitelist: {}".format(stats["timestamps_invalidos"],stats["eventos_whitelist"]),file=sys.stderr)
        else:
            display_report(counter, rows, args.top, args.threshold, args.window, stats, color=not args.no_color and sys.stdout.isatty())
        if args.csv:
            export_csv(rows, args.csv)
        if args.html:
            export_html(rows, stats, total, args.html)
        return 2 if any(r[4] != "ok" for r in all_rows) else 0
    except (OSError, ValueError) as exc:
        print("Erro ao processar logs: {}".format(exc),file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
