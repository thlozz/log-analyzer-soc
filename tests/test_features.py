"""Testes das funcionalidades de qualidade, CLI e relatórios (dados fictícios)."""
import contextlib
import io
import json
import tempfile
import unittest
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from log_analyzer import (analyze_events, build_rows, display_report, export_html,
                          load_whitelist, main, parse_line, read_events)

FAIL = "Oct 08 10:16:00 host sshd[1]: Failed password for user1 from 198.51.100.77 port 22 ssh2"
SUCCESS = "Oct 08 10:19:40 host sshd[1]: Accepted password for maria from 198.51.100.77 port 22 ssh2"
T = datetime(2026, 10, 8, 13, tzinfo=timezone.utc)


class Funcionalidades(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def arquivo(self, texto, nome="teste.log"):
        path = Path(self.temp.name) / nome
        path.write_text(texto, encoding="utf-8")
        return str(path)

    def test_iso_offset(self):
        linha = "2026-10-08T10:15:01-03:00 host sshd: Failed password for root from 192.0.2.1 port 22 ssh2"
        self.assertEqual(parse_line(linha, 2025)[0], datetime(2026,10,8,13,15,1,tzinfo=timezone.utc))

    def test_iso_z(self):
        linha = "2026-10-08T13:15:01Z host sshd: Accepted publickey for root from 192.0.2.1 port 22 ssh2"
        self.assertEqual(parse_line(linha, 2026)[3], "success")

    def test_iso_invalido(self):
        linha = "2026-13-08T10:15:01-03:00 host sshd: Failed password for root from 192.0.2.1 port 22 ssh2"
        with self.assertRaises(ValueError):
            parse_line(linha, 2026)

    def test_syslog_invalido(self):
        linha = "Oct 99 10:15:01 host sshd: Failed password for root from 192.0.2.1 port 22 ssh2"
        with self.assertRaises(ValueError):
            parse_line(linha, 2026)

    def test_contador_invalidos(self):
        arquivo = self.arquivo(FAIL+"\nOct 99 10:15:01 host sshd: Failed password for root from 192.0.2.1 port 22 ssh2\n")
        eventos, stats = read_events([arquivo],2026,return_stats=True)
        self.assertEqual((len(eventos),stats["timestamps_invalidos"]),(1,1))

    def test_varios_arquivos(self):
        a=self.arquivo(FAIL+"\n","a.log")
        b=self.arquivo(SUCCESS+"\n","b.log")
        self.assertEqual(len(read_events([a,b],2026)),2)

    def test_stdin(self):
        self.assertEqual(len(read_events(["-"],2026,stdin=io.StringIO(FAIL+"\n"))),1)

    def test_whitelist_cidr(self):
        wl=self.arquivo("# rede de teste\n198.51.100.0/24\n2001:db8::1\n","lista.txt")
        redes=load_whitelist(wl)
        self.assertEqual(len(redes),2)
        eventos,stats=read_events(["-"],2026,redes,io.StringIO(FAIL+"\n"),True)
        self.assertEqual((len(eventos),stats["eventos_whitelist"]),(0,1))

    def test_whitelist_invalida(self):
        with self.assertRaises(ValueError):
            load_whitelist(self.arquivo("invalido\n","lista.txt"))

    def test_spraying(self):
        linhas=build_rows(Counter({"192.0.2.1":3}),10,5,users={"192.0.2.1":{"a","b","c"}},users_threshold=3)
        self.assertEqual(linhas[0][4],"PASSWORD SPRAYING?")

    def test_prioridade_comprometimento(self):
        linhas=build_rows(Counter({"192.0.2.1":3}),10,5,users={"192.0.2.1":{"a","b","c"}},compromised={"192.0.2.1"},users_threshold=3)
        self.assertEqual(linhas[0][4],"COMPROMETIMENTO?")

    def test_usuario_distinto_so_falhas(self):
        eventos=[(T,"192.0.2.1","a","failure"),(T,"192.0.2.1","b","failure"),(T,"192.0.2.1","c","success")]
        self.assertEqual(len(analyze_events(eventos)[1]["192.0.2.1"]),2)

    def test_json(self):
        arquivo=self.arquivo(FAIL+"\n")
        saida=io.StringIO()
        with contextlib.redirect_stdout(saida):
            codigo=main([arquivo,"--format","json"])
        self.assertEqual(codigo,0)
        self.assertEqual(json.loads(saida.getvalue())["resumo"]["falhas_totais"],1)

    def test_csv_stdout(self):
        arquivo=self.arquivo(FAIL+"\n")
        saida=io.StringIO()
        with contextlib.redirect_stdout(saida),contextlib.redirect_stderr(io.StringIO()):
            codigo=main([arquivo,"--format","csv"])
        self.assertEqual(codigo,0)
        self.assertTrue(saida.getvalue().startswith("posicao,ip"))

    def test_exit_suspeito(self):
        arquivo=self.arquivo(FAIL+"\n")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([arquivo,"--threshold","1"]),2)

    def test_exit_comprometimento(self):
        arquivo=self.arquivo(FAIL+"\n"+SUCCESS+"\n")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([arquivo]),2)

    def test_exit_considera_todos_ips(self):
        arquivo=self.arquivo(FAIL+"\n"+SUCCESS+"\n"+"Oct 08 10:16:00 host sshd: Failed password for a from 192.0.2.10 port 22 ssh2\n"*3)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([arquivo,"--top","1"]),2)

    def test_exit_erro(self):
        arquivo=self.arquivo(FAIL+"\n")
        lista=self.arquivo("IP-INVALIDO","lista.txt")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([arquivo,"--whitelist",lista]),1)

    def test_ansi_ativado(self):
        saida=io.StringIO()
        with contextlib.redirect_stdout(saida):
            display_report(Counter(),[(1,"192.0.2.1",5,100,"COMPROMETIMENTO?",1)],10,5,color=True)
        self.assertIn("\033[31m",saida.getvalue())

    def test_ansi_desativado(self):
        saida=io.StringIO()
        with contextlib.redirect_stdout(saida):
            display_report(Counter(),[(1,"192.0.2.1",5,100,"SUSPEITO",1)],10,5,color=False)
        self.assertNotIn("\033[",saida.getvalue())

    def test_html_autocontido(self):
        destino=Path(self.temp.name)/"relatorio.html"
        export_html([(1,"192.0.2.1",5,100,"SUSPEITO",1)],{"timestamps_invalidos":0,"eventos_whitelist":0},5,str(destino))
        texto=destino.read_text(encoding="utf-8")
        self.assertIn("addEventListener",texto)
        self.assertIn("SUSPEITO",texto)
        self.assertNotIn('src="http',texto)

    def test_html_escape(self):
        destino=Path(self.temp.name)/"relatorio.html"
        export_html([(1,"192.0.2.1",5,100,"<script>alert(1)</script>",1)],{"timestamps_invalidos":0,"eventos_whitelist":0},5,str(destino))
        self.assertIn("&lt;script&gt;",destino.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
