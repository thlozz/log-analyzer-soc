import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timezone, timedelta

from log_analyzer import (
    analyze_events, analyze_log, build_rows, is_valid_ip, parse_args,
    parse_line, read_events, export_csv,
)

T = datetime(2026, 10, 8, 13, 0, tzinfo=timezone.utc)
SSH_FAIL = "Oct 08 10:16:00 server sshd[1]: Failed password for user1 from 198.51.100.77 port 22 ssh2"
SSH_SUCCESS = "Oct 08 10:19:40 server sshd[1]: Accepted password for maria from 198.51.100.77 port 22 ssh2"
WEB = '198.51.100.4 - - [08/Oct/2026:10:20:01 -0300] "{method} /login HTTP/1.1" {status} 128'


class AnalyzerTests(unittest.TestCase):
    def test_ipv4(self): self.assertTrue(is_valid_ip("192.0.2.10"))
    def test_ipv6(self): self.assertTrue(is_valid_ip("2001:db8::1"))
    def test_invalid_ip(self): self.assertFalse(is_valid_ip("999.1.1.1"))
    def test_ssh_failure(self): self.assertEqual(parse_line(SSH_FAIL, 2026)[3], "failure")
    def test_ssh_success(self): self.assertEqual(parse_line(SSH_SUCCESS, 2026)[3], "success")
    def test_ssh_username(self): self.assertEqual(parse_line(SSH_FAIL, 2026)[2], "user1")
    def test_syslog_year(self): self.assertEqual(parse_line(SSH_FAIL, 2025)[0].year, 2025)
    def test_invalid_user_not_counted(self): self.assertIsNone(parse_line("Oct 08 10:00:00 host sshd: Invalid user admin from 192.0.2.1", 2026))
    def test_web_get(self): self.assertEqual(parse_line(WEB.format(method="GET",status=401),2026)[3],"failure")
    def test_web_head(self): self.assertEqual(parse_line(WEB.format(method="HEAD",status=401),2026)[3],"failure")
    def test_web_patch(self): self.assertEqual(parse_line(WEB.format(method="PATCH",status=403),2026)[3],"failure")
    def test_web_options(self): self.assertEqual(parse_line(WEB.format(method="OPTIONS",status=401),2026)[3],"failure")
    def test_web_200_ignored(self): self.assertIsNone(parse_line(WEB.format(method="POST",status=200),2026))
    def test_success_after_failure(self):
        events=[(T,"192.0.2.1","alice","failure"),(T+timedelta(minutes=1),"192.0.2.1","alice","success")]
        self.assertIn("192.0.2.1",analyze_events(events)[2])
    def test_success_without_failure(self):
        self.assertFalse(analyze_events([(T,"192.0.2.1","alice","success")])[2])
    def test_window_peak(self):
        events=[(T,"192.0.2.1","alice","failure"),(T+timedelta(minutes=20),"192.0.2.1","alice","failure")]
        self.assertEqual(analyze_events(events,window=5)[0]["192.0.2.1"],1)
    def test_total_failures(self):
        events=[(T,"192.0.2.1","alice","failure"),(T,"192.0.2.1","alice","success")]
        self.assertEqual(analyze_events(events)[3],1)
    def test_unique_users(self):
        events=[(T,"192.0.2.1","alice","failure"),(T,"192.0.2.1","bob","failure")]
        self.assertEqual(len(analyze_events(events)[1]["192.0.2.1"]),2)
    def test_status_priority(self):
        rows=build_rows(__import__("collections").Counter({"192.0.2.1":2}),10,5,compromised={"192.0.2.1"})
        self.assertEqual(rows[0][4],"COMPROMETIMENTO?")
    def test_csv_export(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"out.csv"
            export_csv([(1,"192.0.2.1",2,100.0,"SUSPEITO",1)],str(path))
            self.assertIn("usuarios_distintos",path.read_text())
    def test_sample(self):
        path=Path(__file__).resolve().parents[1]/"sample.log"
        self.assertEqual(sum(analyze_log(str(path)).values()),17)
    def test_cli_args(self):
        args=parse_args(["sample.log","--window","10","--year","2026"])
        self.assertEqual((args.window,args.year),(10,2026))


if __name__ == "__main__":
    unittest.main()
