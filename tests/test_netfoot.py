#!/usr/bin/env python3

# run only one test:
# python -m unittest test_netfoot.Netfoot_log_unittest.test_infos_lookup

import sys
import unittest
from collections import defaultdict
from pathlib import Path
import shutil
import time
import copy

sys.path.append('..')
import netfoot

OUTPUT_DIR = Path(__file__).resolve().parent / 'tmp'
print("OUTPUT_DIR = %s" % OUTPUT_DIR)
if OUTPUT_DIR.exists():
    shutil.rmtree(OUTPUT_DIR)
OUTPUT_DIR.mkdir()

TARGETS = {
    'masscan_result_1': {
        '1.2.3.4': "slip",
    },
    'masscan_result_2': {
        '1.2.3.4': "slip",
        '1.2.3.5': "sock",
    },
    'nmap_result_1': {
        '1.2.3.4': "slip",
    },
}
EXPECTED_DIRTREE = {
    'masscan_result_1': {
        "nfdir": {
            "host_1.2.3.4": ("outdir", "from_moncul/host_1.2.3.4_20171225_0000"),
            "from_moncul": ("outdir", "from_moncul"),
        },
        "outdir": {
            "host_1.2.3.4": {
                "ip": "1.2.3.4",
                "from_moncul_20171225_0000": ("outdir", "from_moncul/host_1.2.3.4_20171225_0000"),
                "from_moncul_lastseen": ("outdir", "from_moncul/host_1.2.3.4_lastseen"),
                "from_moncul": ("outdir", "from_moncul/host_1.2.3.4"),
            },
            "from_moncul": {
                "perspective": "moncul",
                "host_1.2.3.4" : {
                    "host": ('outdir', 'host_1.2.3.4'),
                    "comment": ("outdir", "from_moncul/host_1.2.3.4_20171225_0000/comment"),
                    'icmp': {'0': {'answer_time': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/icmp/0/answer_time'), 'reason': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/icmp/0/reason'), 'reason_ttl': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/icmp/0/reason_ttl'), 'state': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/icmp/0/state')}},
                },
                "host_1.2.3.4_20171225_0000": {
                    "host": ("outdir", "host_1.2.3.4"),
                    "comment": "slip",
                    "icmp": defaultdict(dict, { "0": { "state": "open", "reason": "none", "reason_ttl": "108", "answer_time": time.strftime("%Y%m%d_%H%M%S", time.localtime(1597451433)) } }),
                    "netfoot": ("nfdir", ),
                },
                "host_1.2.3.4_lastseen": ("outdir", "from_moncul/host_1.2.3.4_20171225_0000"),
            }
        }
    },
    'masscan_result_2': {
        "nfdir": {
            "host_1.2.3.4": ("outdir", "from_moncul/host_1.2.3.4_20171225_0200"),
            "host_1.2.3.5": ("outdir", "from_moncul/host_1.2.3.5_20171225_0200"),
            "from_moncul": ("outdir", "from_moncul"),
        },
        "outdir": {
            "host_1.2.3.4": {
                "ip": "1.2.3.4",
                "from_moncul_20171225_0200": ("outdir", "from_moncul/host_1.2.3.4_20171225_0200"),
                "from_moncul_lastseen": ("outdir", "from_moncul/host_1.2.3.4_lastseen"),
                "from_moncul": ("outdir", "from_moncul/host_1.2.3.4"),
            },
            "host_1.2.3.5": {
                "ip": "1.2.3.5",
                "from_moncul_20171225_0200": ("outdir", "from_moncul/host_1.2.3.5_20171225_0200"),
                "from_moncul_lastseen": ("outdir", "from_moncul/host_1.2.3.5_lastseen"),
                "from_moncul": ("outdir", "from_moncul/host_1.2.3.5"),
            },
            "from_moncul": {
                "perspective": "moncul",
                "host_1.2.3.4" : {
                    "host": ('outdir', 'host_1.2.3.4'),
                    "comment": ("outdir", "from_moncul/host_1.2.3.4_20171225_0200/comment"),
                    'icmp': {'0': {'answer_time': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0200/icmp/0/answer_time'), 'reason': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0200/icmp/0/reason'), 'reason_ttl': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0200/icmp/0/reason_ttl'), 'state': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0200/icmp/0/state')}},
                },
                "host_1.2.3.5" : {
                    "host": ('outdir', 'host_1.2.3.5'),
                    "comment": ("outdir", "from_moncul/host_1.2.3.5_20171225_0200/comment"),
                    'icmp': {'0': {'answer_time': ('outdir', 'from_moncul/host_1.2.3.5_20171225_0200/icmp/0/answer_time'), 'reason': ('outdir', 'from_moncul/host_1.2.3.5_20171225_0200/icmp/0/reason'), 'reason_ttl': ('outdir', 'from_moncul/host_1.2.3.5_20171225_0200/icmp/0/reason_ttl'), 'state': ('outdir', 'from_moncul/host_1.2.3.5_20171225_0200/icmp/0/state')}},
                    'tcp': { '80': {'answer_time': ('outdir', 'from_moncul/host_1.2.3.5_20171225_0200/tcp/80/answer_time'), 'banner_answer_time': ('outdir', 'from_moncul/host_1.2.3.5_20171225_0200/tcp/80/banner_answer_time'), 'banner_html': ('outdir', 'from_moncul/host_1.2.3.5_20171225_0200/tcp/80/banner_html'), 'banner_title': ('outdir', 'from_moncul/host_1.2.3.5_20171225_0200/tcp/80/banner_title'), 'reason': ('outdir', 'from_moncul/host_1.2.3.5_20171225_0200/tcp/80/reason'), 'reason_ttl': ('outdir', 'from_moncul/host_1.2.3.5_20171225_0200/tcp/80/reason_ttl'), 'state': ('outdir', 'from_moncul/host_1.2.3.5_20171225_0200/tcp/80/state')},
                             '8080': {'answer_time': ('outdir', 'from_moncul/host_1.2.3.5_20171225_0200/tcp/8080/answer_time'), 'reason': ('outdir', 'from_moncul/host_1.2.3.5_20171225_0200/tcp/8080/reason'), 'reason_ttl': ('outdir', 'from_moncul/host_1.2.3.5_20171225_0200/tcp/8080/reason_ttl'), 'state': ('outdir', 'from_moncul/host_1.2.3.5_20171225_0200/tcp/8080/state') } }
                },
                "host_1.2.3.4_20171225_0200": {
                    "host": ("outdir", "host_1.2.3.4"),
                    "comment": "slip",
                    "icmp": defaultdict(dict, { "0": { "state": "open", "reason": "none", "reason_ttl": "108", "answer_time": time.strftime("%Y%m%d_%H%M%S", time.localtime(1597451433)) } }),
                    "netfoot": ("nfdir", ),
                },
                "host_1.2.3.5_20171225_0200": {
                    "host": ("outdir", "host_1.2.3.5"),
                    "comment": "sock",
                    "icmp": defaultdict(dict, { "0": { "state": "open", "reason": "none", "reason_ttl": "108", "answer_time": time.strftime("%Y%m%d_%H%M%S", time.localtime(1597451433)) } }),
                    "tcp": defaultdict(dict, {
                        "80": { "state": "open", "reason": "syn-ack", "reason_ttl": "44", "answer_time": time.strftime("%Y%m%d_%H%M%S", time.localtime(1597451502)), "banner_answer_time": time.strftime("%Y%m%d_%H%M%S", time.localtime(1597451532)), "banner_title": "Speedtest", "banner_html": '\\x3c!DOCTYPE html PUBLIC \\x22-//W3C//DTD XHTML 1.0 Transitional//EN\\x22 \\x22' },
                        "8080": { "state": "open", "reason": "syn-ack", "reason_ttl": "44", "answer_time": time.strftime("%Y%m%d_%H%M%S", time.localtime(1597451502)) },
                    }),
                    "netfoot": ("nfdir", ),
                },
                "host_1.2.3.4_lastseen": ("outdir", "from_moncul/host_1.2.3.4_20171225_0200"),
                "host_1.2.3.5_lastseen": ("outdir", "from_moncul/host_1.2.3.5_20171225_0200"),
            }
        }
    },
    'nmap_result_1': {
        "nfdir": {
            "host_1.2.3.4": ("outdir", "from_moncul/host_1.2.3.4_20171225_0000"),
            "from_moncul": ("outdir", "from_moncul"),
        },
        "outdir": {
            "host_1.2.3.4": {
                "ip": "1.2.3.4",
                "from_moncul_20171225_0000": ("outdir", "from_moncul/host_1.2.3.4_20171225_0000"),
                "from_moncul_lastseen": ("outdir", "from_moncul/host_1.2.3.4_lastseen"),
                "from_moncul": ("outdir", "from_moncul/host_1.2.3.4"),
            },
            "from_moncul": {
                "perspective": "moncul",
                'host_1.2.3.4': {
                    'comment': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/comment'),
                    'host': ('outdir', 'host_1.2.3.4'),
                    'state_up_reason': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/state_up_reason'),
                    'tcp': {'18793': {'reason': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/18793/reason'), 'reason_ttl': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/18793/reason_ttl'), 'state': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/18793/state')}, '2121': {'banner': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/2121/banner'), 'ftp-brute': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/2121/ftp-brute'), 'ftp-syst': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/2121/ftp-syst'), 'product_ftp': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/2121/product_ftp'), 'reason': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/2121/reason'), 'reason_ttl': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/2121/reason_ttl'), 'state': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/2121/state'), 'unusual-port': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/2121/unusual-port')}, '2122': {'banner': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/2122/banner'), 'ftp-brute': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/2122/ftp-brute'), 'ftp-syst': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/2122/ftp-syst'), 'product_ftp': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/2122/product_ftp'), 'reason': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/2122/reason'), 'reason_ttl': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/2122/reason_ttl'), 'state': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/2122/state'), 'unusual-port': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/2122/unusual-port')}, '2123': {'banner': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/2123/banner'), 'ftp-anon': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/2123/ftp-anon'), 'ftp-brute': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/2123/ftp-brute'), 'ftp-syst': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/2123/ftp-syst'), 'product_ftp': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/2123/product_ftp'), 'reason': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/2123/reason'), 'reason_ttl': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/2123/reason_ttl'), 'state': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/2123/state'), 'unusual-port': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/2123/unusual-port')}, '22': {'banner': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/22/banner'), 'product_ssh': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/22/product_ssh'), 'reason': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/22/reason'), 'reason_ttl': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/22/reason_ttl'), 'ssh-brute': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/22/ssh-brute'), 'ssh-hostkey': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/22/ssh-hostkey'), 'ssh2-enum-algos': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/22/ssh2-enum-algos'), 'state': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/22/state'), 'vulners': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/tcp/22/vulners')}},
                    'traceroute_tcp3389': ('outdir', 'from_moncul/host_1.2.3.4_20171225_0000/traceroute_tcp3389')
                },
                "host_1.2.3.4_20171225_0000": {
                    "host": ("outdir", "host_1.2.3.4"),
                    "comment": "slip",
                    "netfoot": ("nfdir", ),
                    'state_up_reason': 'echo-reply',
                    "tcp": defaultdict(dict, {
                        "18793": { "state": "open", "reason": "syn-ack", "reason_ttl": "63", },
                        "2121": { "state": "open", "reason": "syn-ack", "reason_ttl": "63", "banner": "220 pyftpdlib 1.5.6 ready.", "ftp-brute": "\n  Accounts: No valid accounts found\n  Statistics: Performed 1037 guesses in 303 seconds, average tps: 3.3", "ftp-syst": "\n  STAT: \nFTP server status:\n Connected to: 1.2.3.4:2121\n Waiting for username.\n TYPE: ASCII; STRUcture: File; MODE: Stream\n Data connection closed.\nEnd of status.", "product_ftp": "pyftpdlib 1.5.6", "unusual-port": "ftp unexpected on port tcp/2121" },
                        "2122": { "state": "open", "reason": "syn-ack", "reason_ttl": "63", "banner": "220 pyftpdlib 1.5.6 ready.", "ftp-brute": "\n  Accounts: No valid accounts found\n  Statistics: Performed 0 guesses in 1 seconds, average tps: 0.0\n  ERROR: The service seems to have failed or is heavily firewalled...", "ftp-syst": "\n  STAT: \nFTP server status:\n Connected to: 1.2.3.4:2122\n Waiting for username.\n TYPE: ASCII; STRUcture: File; MODE: Stream\n Data connection closed.\nEnd of status.", "product_ftp": "pyftpdlib 1.5.6", "unusual-port": "ftp unexpected on port tcp/2122" },
                        "2123": { "state": "open", "reason": "syn-ack", "reason_ttl": "63", "banner": "220 pyftpdlib 1.5.6 ready.", "ftp-anon": "Anonymous FTP login allowed (FTP code 230)\ndrwxr-xr-x  24 s        s          110592 Sep 04 09:34 Music", "ftp-brute": "\n  Accounts: No valid accounts found\n  Statistics: Performed 862 guesses in 303 seconds, average tps: 2.8", "ftp-syst": "\n  STAT: \nFTP server status:\n Connected to: 1.2.3.4:2123\n Waiting for username.\n TYPE: ASCII; STRUcture: File; MODE: Stream\n Data connection closed.\nEnd of status.", "product_ftp": "pyftpdlib 1.5.6", "unusual-port": "ftp unexpected on port tcp/2123" },
                        "22": { "state": "open", "reason": "syn-ack", "reason_ttl": "63", "banner": "SSH-2.0-OpenSSH_8.4", "product_ssh": "OpenSSH 8.4 protocol 2.0", "ssh-brute": "Password authentication not allowed", "ssh-hostkey": "\n  2048 c0:46:0c:a0:97:36:42:51:49:17:94:9e:07:57:68:3f (RSA)\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGvH3MdcbtW5ef5PjXNDYrhPbprSQDviTdXQ0T/Z4tGGXJIt3DQUmxWa1JD2isbwR7Rz5StFvg5YzdOoZAeX+meuPqcbOcQgnOFjIl+1UnSsFzMUxqNhQlU1Y+7aq0ixvjMe8wNXHlkLUChUIoLz1YXu5Iv7s2hGOl5HOe8AXORxw35xXBTFVYTnX39RudAnvHTnyjE0dYPjmpRKrSCYBOBFF2cMHBFaqPJym15rG4TrFwNuzNtM7WFO0eMyyS401dpPKyKudSM0T6pXvskM2JDdW4leTQNPUvKuCr1O0hUcj6/vfwaOGl6Ly44VIqTURBBj6oGU15o/8qPvsw1I4p\n  256 0d:cd:f1:3e:29:19:83:03:3e:f1:3a:19:78:9d:35:cb (ECDSA)\necdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEAsKhLEe7WHzdDlT1kxuB5tzcLtEKsKlN0hlBgC9bZVBefeIBde9O7sVHR9sI0Q2q92DWimbEs10XnSiK95G50=\n  256 e5:17:90:2b:7b:36:0e:c1:df:fa:ba:66:87:52:cb:ef (ED25519)\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK1a72AxiRw1nCYKmmgElAxH9YSYrIqgI6tPdftC/At/", "ssh2-enum-algos": "\n  kex_algorithms: (9)\n      curve25519-sha256\n      curve25519-sha256@libssh.org\n      ecdh-sha2-nistp256\n      ecdh-sha2-nistp384\n      ecdh-sha2-nistp521\n      diffie-hellman-group-exchange-sha256\n      diffie-hellman-group16-sha512\n      diffie-hellman-group18-sha512\n      diffie-hellman-group14-sha256\n  server_host_key_algorithms: (5)\n      rsa-sha2-512\n      rsa-sha2-256\n      ssh-rsa\n      ecdsa-sha2-nistp256\n      ssh-ed25519\n  encryption_algorithms: (6)\n      chacha20-poly1305@openssh.com\n      aes128-ctr\n      aes192-ctr\n      aes256-ctr\n      aes128-gcm@openssh.com\n      aes256-gcm@openssh.com\n  mac_algorithms: (10)\n      umac-64-etm@openssh.com\n      umac-128-etm@openssh.com\n      hmac-sha2-256-etm@openssh.com\n      hmac-sha2-512-etm@openssh.com\n      hmac-sha1-etm@openssh.com\n      umac-64@openssh.com\n      umac-128@openssh.com\n      hmac-sha2-256\n      hmac-sha2-512\n      hmac-sha1\n  compression_algorithms: (2)\n      none\n      zlib@openssh.com", "vulners": "\n  cpe:/a:openbsd:openssh:8.4: \n    \tCVE-2008-3844\t9.3\thttps://vulners.com/cve/CVE-2008-3844\n    \tCVE-2007-2768\t4.3\thttps://vulners.com/cve/CVE-2007-2768\n    \tCVE-2014-9278\t4.0\thttps://vulners.com/cve/CVE-2014-9278"},
                    }),
                    "traceroute_tcp3389": "1\t0.34\t2.2.2.2\n2\t0.62\t1.2.3.4\n",
                },
                "host_1.2.3.4_lastseen": ("outdir", "from_moncul/host_1.2.3.4_20171225_0000"),
            }
        }
    },
}

class Netfoot_args_dummy(object):
    def __init__(self):
        self.output_dir = str(OUTPUT_DIR)
        self.iface = "lo"
        self.rate = 50
        self.ffrom = "moncul"
        self.no_dirtree = False

class Proc_masscan_unittest(unittest.TestCase):
    def test_process_output_1(self):
        self.maxDiff = None
        xmlresultsname = "masscan_result_1"
        xmlresultsfile = Path(__file__).parent / ("%s.xml" % xmlresultsname)
        # prepare dummy netfoot
        args = Netfoot_args_dummy()
        now = "20171225_0000"
        nfname = "netfoot_%s_Proc_masscan_unittest_1" % now
        nfdir = Path(args.output_dir).resolve() / nfname
        nfdir.mkdir()
        log = netfoot.Netfoot_log(args, nfdir, nfname, "127.0.0.1", "1.1.1.1")
        shutil.copy(xmlresultsfile, nfdir)
        targets = netfoot.Targets(log, load_obj=TARGETS[xmlresultsname])
        # instantiate class
        exe = netfoot.Proc_masscan(log, '/dev/null', xmlresultsname, args.ffrom, now, targets)
        tree = exe.process_output()
        # cleanup
        log.close()
        # test class
        self.assertEqual(EXPECTED_DIRTREE[xmlresultsname], tree)

    def test_process_output_2(self):
        self.maxDiff = None
        xmlresultsname = "masscan_result_2"
        xmlresultsfile = Path(__file__).parent / ("%s.xml" % xmlresultsname)
        # prepare dummy netfoot
        args = Netfoot_args_dummy()
        now = "20171225_0200"
        nfname = "netfoot_%s_Proc_masscan_unittest_2" % now
        nfdir = Path(args.output_dir).resolve() / nfname
        nfdir.mkdir()
        log = netfoot.Netfoot_log(args, nfdir, nfname, "127.0.0.1", "1.1.1.1")
        shutil.copy(xmlresultsfile, nfdir)
        targets = netfoot.Targets(log, load_obj=TARGETS[xmlresultsname])
        # instantiate class
        exe = netfoot.Proc_masscan(log, '/dev/null', xmlresultsname, args.ffrom, now, targets)
        tree = exe.process_output()
        # cleanup
        log.close()
        # test class
        self.assertEqual(EXPECTED_DIRTREE[xmlresultsname], tree)

class Netfoot_dirtree_unittest(unittest.TestCase):
    def test_update_masscan_1(self):
        # prepare dummy netfoot
        args = Netfoot_args_dummy()
        odir = Path(args.output_dir).resolve()
        now = "20171225_0000"
        nfname = "netfoot_%s_Netfoot_dirtree_unittest_1" % now
        nfdir = odir / nfname
        nfdir.mkdir()
        # instantiate class
        log = netfoot.Netfoot_log(args, nfdir, nfname, "127.0.0.1", "1.1.1.1")
        dt = netfoot.Netfoot_dirtree(args, log, nfdir, nfname)
        dt.update(copy.copy(EXPECTED_DIRTREE['masscan_result_1']))
        # cleanup
        dt.close()
        log.close()
        # check directories and files
        # netfoot_<name>/
        self.assertTrue(nfdir.is_dir())
        self.assertTrue((nfdir / 'host_1.2.3.4').is_symlink())
        self.assertEqual(odir / 'from_moncul' / ('host_1.2.3.4_'+now), (nfdir / 'host_1.2.3.4').resolve())
        self.assertTrue((nfdir / 'from_moncul').is_symlink())
        # from_<from>/
        self.assertTrue((odir / 'from_moncul').is_dir())
        hdir = odir / 'from_moncul' / ('host_1.2.3.4_'+now)
        self.assertTrue((odir / 'from_moncul' / 'host_1.2.3.4_lastseen').is_symlink())
        self.assertTrue((odir / 'from_moncul' / 'host_1.2.3.4_lastseen').resolve(), hdir) 
        # from_<from>/host_<ip>_<date>/
        self.assertTrue(hdir.is_dir())
        self.assertTrue((hdir / 'host').is_symlink())
        self.assertEqual(odir / 'host_1.2.3.4', (hdir / 'host').resolve())
        self.assertTrue((hdir / 'comment').is_file())
        self.assertEqual("slip", (hdir / 'comment').read_text())
        self.assertTrue((hdir / 'icmp').is_dir())
        self.assertTrue((hdir / 'icmp' / '0').is_dir())
        self.assertTrue((hdir / 'icmp' / '0' / 'reason').is_file())
        self.assertEqual("none", (hdir / 'icmp' / '0' / 'reason').read_text())
        self.assertTrue((hdir / 'icmp' / '0' / 'reason_ttl').is_file())
        self.assertEqual("108", (hdir / 'icmp' / '0' / 'reason_ttl').read_text())
        self.assertTrue((hdir / 'icmp' / '0' / 'answer_time').is_file())
        self.assertEqual(time.strftime("%Y%m%d_%H%M%S", time.localtime(1597451433)), (hdir / 'icmp' / '0' / 'answer_time').read_text())
        self.assertTrue((hdir / 'netfoot').is_symlink())
        self.assertEqual(nfdir, (hdir / 'netfoot').resolve())
        # host_<ip>/
        self.assertTrue((odir / 'host_1.2.3.4').is_dir())
        self.assertEqual("1.2.3.4", (odir / 'host_1.2.3.4' / 'ip').read_text())

    def test_update_masscan_2(self):
        # prepare dummy netfoot
        args = Netfoot_args_dummy()
        odir = Path(args.output_dir).resolve()
        now = "20171225_0200"
        nfname = "netfoot_%s_Netfoot_dirtree_unittest_2" % now
        nfdir = odir / nfname
        nfdir.mkdir()
        # instantiate class
        log = netfoot.Netfoot_log(args, nfdir, nfname, "127.0.0.1", "1.1.1.1")
        dt = netfoot.Netfoot_dirtree(args, log, nfdir, nfname)
        dt.update(copy.copy(EXPECTED_DIRTREE['masscan_result_2']))
        # cleanup
        dt.close()
        log.close()
        # check directories and files
        # XXX missing checks for host 1.2.3.5
        # netfoot_<name>/
        self.assertTrue(nfdir.is_dir())
        self.assertTrue((nfdir / 'host_1.2.3.4').is_symlink())
        self.assertTrue((nfdir / 'host_1.2.3.5').is_symlink())
        self.assertEqual(odir / 'from_moncul' / ('host_1.2.3.4_'+now), (nfdir / 'host_1.2.3.4').resolve())
        self.assertEqual(odir / 'from_moncul' / ('host_1.2.3.5_'+now), (nfdir / 'host_1.2.3.5').resolve())
        self.assertTrue((nfdir / 'from_moncul').is_symlink())
        # from_<from>/
        self.assertTrue((odir / 'from_moncul').is_dir())
        hdir4 = odir / 'from_moncul' / ('host_1.2.3.4_'+now)
        hdir5 = odir / 'from_moncul' / ('host_1.2.3.5_'+now)
        self.assertTrue((odir / 'from_moncul' / 'host_1.2.3.4_lastseen').is_symlink())
        self.assertTrue((odir / 'from_moncul' / 'host_1.2.3.4_lastseen').resolve(), hdir4) 
        self.assertTrue((odir / 'from_moncul' / 'host_1.2.3.5_lastseen').is_symlink())
        self.assertTrue((odir / 'from_moncul' / 'host_1.2.3.5_lastseen').resolve(), hdir5) 
        # from_<from>/host_<ip>_<date>/
        self.assertTrue(hdir4.is_dir())
        self.assertTrue(hdir5.is_dir())
        self.assertTrue((hdir4 / 'host').is_symlink())
        self.assertTrue((hdir5 / 'host').is_symlink())
        self.assertEqual(odir / 'host_1.2.3.4', (hdir4 / 'host').resolve())
        self.assertEqual(odir / 'host_1.2.3.5', (hdir5 / 'host').resolve())
        self.assertTrue((hdir4 / 'comment').is_file())
        self.assertTrue((hdir5 / 'comment').is_file())
        self.assertEqual("slip", (hdir4 / 'comment').read_text())
        self.assertEqual("sock", (hdir5 / 'comment').read_text())
        self.assertTrue((hdir4 / 'icmp').is_dir())
        self.assertTrue((hdir5 / 'icmp').is_dir())
        self.assertTrue((hdir4 / 'icmp' / '0').is_dir())
        self.assertTrue((hdir5 / 'icmp' / '0').is_dir())
        self.assertTrue((hdir4 / 'icmp' / '0' / 'reason').is_file())
        self.assertTrue((hdir5 / 'icmp' / '0' / 'reason').is_file())
        self.assertEqual("none", (hdir4 / 'icmp' / '0' / 'reason').read_text())
        self.assertEqual("none", (hdir5 / 'icmp' / '0' / 'reason').read_text())
        self.assertTrue((hdir4 / 'icmp' / '0' / 'reason_ttl').is_file())
        self.assertTrue((hdir5 / 'icmp' / '0' / 'reason_ttl').is_file())
        self.assertEqual("108", (hdir4 / 'icmp' / '0' / 'reason_ttl').read_text())
        self.assertEqual("108", (hdir5 / 'icmp' / '0' / 'reason_ttl').read_text())
        self.assertTrue((hdir4 / 'icmp' / '0' / 'answer_time').is_file())
        self.assertTrue((hdir5 / 'icmp' / '0' / 'answer_time').is_file())
        self.assertEqual(time.strftime("%Y%m%d_%H%M%S", time.localtime(1597451433)), (hdir4 / 'icmp' / '0' / 'answer_time').read_text())
        self.assertEqual(time.strftime("%Y%m%d_%H%M%S", time.localtime(1597451433)), (hdir5 / 'icmp' / '0' / 'answer_time').read_text())
        self.assertTrue((hdir4 / 'netfoot').is_symlink())
        self.assertTrue((hdir5 / 'netfoot').is_symlink())
        self.assertEqual(nfdir, (hdir4 / 'netfoot').resolve())
        self.assertEqual(nfdir, (hdir5 / 'netfoot').resolve())
        # host_<ip>/
        self.assertTrue((odir / 'host_1.2.3.4').is_dir())
        self.assertTrue((odir / 'host_1.2.3.5').is_dir())
        self.assertEqual("1.2.3.4", (odir / 'host_1.2.3.4' / 'ip').read_text())
        self.assertEqual("1.2.3.5", (odir / 'host_1.2.3.5' / 'ip').read_text())


    @unittest.skip("TODO")
    def test_update_masscan_1_and_2(self):
        pass

    @unittest.skip("TODO")
    def test_update_traceroute(self):
        pass

class Proc_nmap_unittest(unittest.TestCase):
    def test_process_output_1(self):
        self.maxDiff = None
        xmlresultsname = "nmap_result_1"
        xmlresultsfile = Path(__file__).parent / ("%s.xml" % xmlresultsname)
        # prepare dummy netfoot
        args = Netfoot_args_dummy()
        now = "20171225_0000"
        nfname = "netfoot_%s_Proc_nmap_unittest_1" % now
        nfdir = Path(args.output_dir).resolve() / nfname
        nfdir.mkdir()
        log = netfoot.Netfoot_log(args, nfdir, nfname, "127.0.0.1", "1.1.1.1")
        shutil.copy(xmlresultsfile, nfdir)
        targets = netfoot.Targets(log, load_obj=TARGETS[xmlresultsname])
        # instantiate class
        exe = netfoot.Proc_nmap(log, '/dev/null', xmlresultsname, args.ffrom, now, targets)
        tree = exe.process_output()
        # cleanup
        log.close()
        # test class
        self.assertEqual(EXPECTED_DIRTREE[xmlresultsname], tree)

if __name__ == "__main__":
    unittest.main()
