#!/usr/bin/env python3

# netfoot - quick active network footprinting, output to file hierarchy
# Copyright (c) 2017, 2020 Laurent Ghigonis <ooookiwi@gmail.com>

import os
import re
import sys
import time
import socket
import shutil
import argparse
import subprocess
import collections
from pathlib import Path
from xml.etree import ElementTree
from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address, IPv4Network, IPv6Network

VERSION = '1.0'
EPILOG="""Use '-c help' to list commands executed by netfoot
Use '-i help' for extensive help on importing scans
Use '-o help' to preview the directory structure created by netfoot.
"""

HELP_OUTPUT = """Directory structure created by netfoot:

Created per-scan:
netfoot_<date>_<from>_<iface>[_pub<pubip>][_lan<lanip>]/
netfoot_<date>_<from>_<iface>[_pub<pubip>][_lan<lanip>]/netfoot_<date>_<from>[_pub<pubip>][_lan<lanip].log # main log containing a copy of terminal output
netfoot_<date>_<from>_<iface>[_pub<pubip>][_lan<lanip>]/cmd_(OK|FAILED)_<cmd>.txt   # output of command
netfoot_<date>_<from>_<iface>[_pub<pubip>][_lan<lanip>]/config_date_start.txt       # scan start date
netfoot_<date>_<from>_<iface>[_pub<pubip>][_lan<lanip>]/config_perspective.txt      # scan perspective name
netfoot_<date>_<from>_<iface>[_pub<pubip>][_lan<lanip>]/config_targets.txt          # list of targets passed as arguments for the scan
netfoot_<date>_<from>_<iface>[_pub<pubip>][_lan<lanip>]/lan_ip.txt                  # LAN IP
netfoot_<date>_<from>_<iface>[_pub<pubip>][_lan<lanip>]/pub_ip.txt                  # Public IP
netfoot_<date>_<from>_<iface>[_pub<pubip>][_lan<lanip>]/host_<ip>/                  # -> symlink to discovered from_<from>/host_<ip>_<date>/
netfoot_<date>_<from>_<iface>[_pub<pubip>][_lan<lanip>]/from_<from>/                # -> symlink to from_<from>/

Shared accross multiple scans:
netfoot_lastscan/                                                                   # -> symlink to last netfoot_*/
host_<ip>/
host_<ip>/ip                                            # ip address
host_<ip>/from_<from>_<date>/                           # -> symlink to from_<from>/host_<ip>_<date>/
host_<ip>/from_<from>_lastseen/                         # -> symlink to from_<from>/host_<ip>_lastseen/
from_<from>/
from_<from>/perspective                                 # perspective name
from_<from>/host_<ip>_<date>/host                       # -> symlink to host_<ip>/
from_<from>/host_<ip>_<date>/comment                    # host user comment
from_<from>/host_<ip>_<date>/traceroute_<proto><port>   # traceroute <proto+port> "<hopn> <delay1> <ip1>\\n..."
from_<from>/host_<ip>_<date>/<proto>/
from_<from>/host_<ip>_<date>/<proto>/<port>/
from_<from>/host_<ip>_<date>/<proto>/<port>/state       # open
from_<from>/host_<ip>_<date>/<proto>/<port>/reason      # answer type from target
from_<from>/host_<ip>_<date>/<proto>/<port>/reason_ttl  # TTL in answer from target
from_<from>/host_<ip>_<date>/<proto>/<port>/banner      # banner returned from this port, if any
from_<from>/host_<ip>_<date>/<proto>/<port>/answer_time # time of answer
from_<from>/host_<ip>_<date>/netfoot                    # -> symlink to logs of this scan
from_<from>/host_<ip>_lastseen/                         # -> symlink to last from_<from>/host_<ip>_<date>/
from_<from>/host_<ip>/
from_<from>/host_<ip>/host                              # -> symlink to host_<ip>/
from_<from>/host_<ip>/comment                           # -> symlink to last created from_<from>/host_<ip>_<date>/comment
from_<from>/host_<ip>/<proto>/<port>/*                  # -> symlinks to last created from_<from>/host_<ip>_<date>/<proto>/<port>/*"""

TODO = """
from_<from>/host_<ip>_<date>/in_traceroute_<proto/port>_<ip2>   # <ip> found during traceroute <proto/port> towards <ip2>

net_<network>+<mask>/
net_<network>+<mask>/range              # network/mask
net_<network>+<mask>/whois              # whois record
net_<network>+<mask>/whoismin           # whois record simplified
net_<network>+<mask>/org                # organisation from whois record
net_<network>+<mask>/as_<asnum>/        # -> symlink to as_<asnum>/
net_<network>+<mask>/host_<ip>/         # -> symlink to host_<ip>/

as_<asnum>/
as_<asnum>/asnum                        # AS number
as_<asnum>/asname                       # AS name
as_<asnum>/net_<network>+<mask>/        # -> symlink to net_<network>+<mask>/
"""

def dict_merge(dct, merge_dct):
    """ Recursive dict merge. Inspired by :meth:``dict.update()``, instead of
    updating only top-level keys, dict_merge recurses down into dicts nested
    to an arbitrary depth, updating keys. The ``merge_dct`` is merged into
    ``dct``.
    :param dct: dict onto which the merge is executed
    :param merge_dct: dct merged into dct
    :return: None
    """
    for k, v in merge_dct.items():
        if (k in dct and isinstance(dct[k], dict)
                and isinstance(merge_dct[k], collections.Mapping)):
            dict_merge(dct[k], merge_dct[k])
        else:
            dct[k] = merge_dct[k]

class Netfoot_error(Exception):
    pass

class Netfoot(object):
    def __init__(self, args):
        if args.rate == 100:
            args.rate_nmap = 3
        elif args.rate < 100:
            args.rate_nmap = 2
        else:
            args.rate_nmap = 4
        self.args = args
        self.date_start = time.strftime("%Y%m%d_%H%M%S")
        self.lan_ip, self.pub_ip, ipstr = self._get_lanpub_ips()
        # initialise output
        if not Path(args.output_dir).exists():
            raise Netfoot_error("specified output directory does not exist : %s" % args.output_dir)
        if not Path(args.output_dir).is_dir():
            raise Netfoot_error("specified output directory is not a directory : %s" % args.output_dir)
        self.netfoot_name = 'netfoot_%s_%s_%s_%s' % (self.date_start, self.args.ffrom, args.iface, ipstr)
        self.netfoot_dir = Path(self.args.output_dir).resolve() / self.netfoot_name
        self.netfoot_dir.mkdir()
        self.log = Netfoot_log(args, self.netfoot_dir, self.netfoot_name, self.date_start, self.args.ffrom, self.lan_ip, self.pub_ip)
        if not args.no_dirtree:
            self.dirtree = Netfoot_dirtree(args, self.log, self.netfoot_dir, self.netfoot_name)
        else:
            self.dirtree = None
        # check that command programs are present on the system
        for cmdtype in CMDS.keys():
            for cmd in CMDS[cmdtype]:
                if not shutil.which(cmd[CMD_BINARY]):
                    self.log.warn("binary '%s' for command '%s' not found on the system ! this command will be skipped." % (cmd[CMD_BINARY], cmd[CMD_NAME]))
                    CMDS[cmdtype].remove(cmd)

    def run(self):
        if self.args.targets_file:
            self.targets = Targets(self.log, load_path=self.args.targets_file)
            cmds_groups = CMDS_ALWAYS + CMDS_DEFAULT_TARGET
        elif self.args.targets:
            self.targets = Targets(self.log, load_str=self.args.targets)
            cmds_groups = CMDS_ALWAYS + CMDS_DEFAULT_TARGET
        else:
            self.targets = Targets(self.log)
            self.log.info("No targets specified, starting LAN discovery")
            cmds_groups = CMDS_ALWAYS + CMDS_DEFAULT_LANDISCOVERY
        cmds = list()
        if self.args.commands:
            for group in CMDS_ALWAYS + self.args.commands.split(','):
                cmds.extend(CMDS[group])
        else:
            for group in cmds_groups:
                cmds.extend(CMDS[group])
        self.log.info("Commands to be executed:\n%s" % '\n'.join([ "* %s: %s %s %s" % (c[CMD_NAME], c[CMD_BINARY], c[CMD_ARGUMENTS] if len(c) > CMD_ARGUMENTS else "", "(t=%s)" % c[CMD_TARGET_MODE] if len(c) > CMD_TARGET_MODE and c[CMD_TARGET_MODE] is not None else "") for c in cmds]))
        for cmd in cmds:
            if len(cmd) > CMD_TARGET_MODE and cmd[CMD_TARGET_MODE] is not None:
                if cmd[CMD_TARGET_MODE] == 'single_target':
                    for target in self.targets.targets:
                        self._run_cmd_target(cmd, target)
                else:
                    self._run_cmd_target(cmd, 'config_targets.txt')
            else:
                self._run_cmd_target(cmd)

    def end(self):
        if self.dirtree:
            self.dirtree.close()
        self.log.close()

    def fatal(self, msg):
        print("FATAL: %s" % msg)
        sys.exit(1)

    def _run_cmd_target(self, cmd, target=None):
        # run command with logging
        logfile, outfilename, code = self.log.execlog(cmd, target)
        if code != 0:
            self.log.warn("command %s returned code %d. see output file %s" % (cmd[CMD_NAME], code, logfile))
        # process command output
        if len(cmd) > CMD_OUTPUT_PROCESSINGCLASS and self.dirtree:
            tree = cmd[CMD_OUTPUT_PROCESSINGCLASS](self.log, logfile, outfilename, self.args.ffrom, self.date_start, self.targets).process_output()
            if tree:
                self.dirtree.update(tree)
                self.log.info("created %d files, updated %d files in output directory tree" % (tree['stats']['files_created'], tree['stats']['files_updated']))
                self.log.dirtree_stats['files_created'] += tree['stats']['files_created']
                self.log.dirtree_stats['files_updated'] += tree['stats']['files_updated']
            else:
                self.log.info("no output data found, not populating directory tree output")

    def _get_lanpub_ips(self):
        try:
            cmd = 'ip -o a s dev %s |awk \'{print $4}\' |cut -d"/" -f1 |head -n1' % self.args.iface
            print("getting LAN IP : %s" % cmd)
            lan_ip = subprocess.check_output(cmd, shell=True).decode('utf8').strip()
            if lan_ip is None or len(lan_ip) == 0:
                raise Exception("returned LAN IP is empty")
            ipstr = "lan%s" % lan_ip
        except Exception as e:
            self.fatal("cannot get LAN IP on interface %s : %s" % (self.args.iface, e))
        if not args.no_internet:
            cmd = 'dig -b %s +short myip.opendns.com @resolver1.opendns.com' % lan_ip
            print("getting Public IP : %s" % cmd)
            try:
                pub_ip = subprocess.check_output(cmd, shell=True).decode('utf8').strip()
                if pub_ip is None or len(lan_ip) == 0:
                    raise Exception("returned public IP is empty")
            except Exception as e:
                self.fatal("cannot get public IP on interface %s, try to disable internet tests with -N :\n%s" % (self.args.iface, e))
            ipstr = "pub%s_" % pub_ip + ipstr
        else:
            pub_ip = None
        print("%s" % ipstr)
        return lan_ip, pub_ip, ipstr

class Netfoot_import(object):
    def __init__(self, args):
        self.args = args
        if not Path(args.import_dir).exists():
            raise Netfoot_error("specified import directory does not exist : %s" % args.import_dir)
        if not Path(args.import_dir).is_dir():
            raise Netfoot_error("specified import directory is not a directory : %s" % args.import_dir)
        self.netfoot_dir = Path(self.args.import_dir).resolve()
        if not (self.netfoot_dir / "config_date_start.txt").is_file():
            raise Netfoot_error("file missing in import directory: config_date_start.txt")
        self.date_start = (self.netfoot_dir / "config_date_start.txt").read_text()
        self.now = time.strftime("%Y%m%d_%H%M%S")
        self.netfoot_name = "%s_import_%s" % (Path(self.args.import_dir).name, self.now)
        if not (self.netfoot_dir / "config_perspective.txt").is_file():
            raise Netfoot_error("file missing in import directory: config_perspective.txt")
        self.ffrom = (self.netfoot_dir / "config_perspective.txt").read_text()
        self.log = Netfoot_log(args, self.netfoot_dir, self.netfoot_name)
        if not (self.netfoot_dir / "config_targets.txt").is_file():
            raise Netfoot_error("file missing in import directory: config_targets.txt")
        targets_file = self.netfoot_dir / "config_targets.txt"
        self.targets = Targets(self.log, load_path=targets_file)
        self.dirtree = Netfoot_dirtree(args, self.log, self.netfoot_dir, self.netfoot_name)

    def run(self):
        for cls in CMDS_OUTPUT_PROCESSINGCLASSES:
            self.log.info("[+] processing output using %s" % str(cls))
            if 'OUTPUT_FILES_PATTERNS' in dir(cls):
                for pattern in cls.OUTPUT_FILES_PATTERNS:
                    for outfile in self.netfoot_dir.glob(pattern[OUTPUT_FILES_PATTERNS_GLOB]):
                        outfilename = outfile.name[:-len(pattern[OUTPUT_FILES_PATTERNS_EXTENSION])]
                        self.log.info("%s" % outfile)
                        tree = cls(self.log, None, outfilename, self.ffrom, self.date_start, self.targets).process_output()
                        if tree:
                            self.dirtree.update(tree)
                            self.log.info("created %d files, updated %d files in output directory tree" % (tree['stats']['files_created'], tree['stats']['files_updated']))
                            self.log.dirtree_stats['files_created'] += tree['stats']['files_created']
                            self.log.dirtree_stats['files_updated'] += tree['stats']['files_updated']
                        else:
                            self.log.info("no output data found, not creating directory tree output")

    def end(self):
        self.dirtree.close()
        self.log.close()

class Netfoot_log(object):
    def __init__(self, args, netfoot_dir, netfoot_name, date_start=None, perspective=None, lan_ip=None, pub_ip=None):
        self.args = args
        self.lan_ip = lan_ip
        self.pub_ip = pub_ip
        self.warnings = list()
        self.netfoot_dir = netfoot_dir
        self.netfoot_name = netfoot_name
        self.logpath = self.netfoot_dir / ("%s.log" % netfoot_name)
        self.logfile = self.logpath.open('w')
        if perspective:
            self.createfile("config_perspective.txt", perspective)
        if date_start:
            self.createfile("config_date_start.txt", date_start)
        if lan_ip:
            self.createfile("lan_ip.txt", lan_ip)
        if pub_ip:
            self.createfile("pub_ip.txt", pub_ip)
        self.dirtree_stats = { 'files_created': 0, 'files_updated': 0 }
        self.bar()
        self.info("[*] %s START\n\n%s\n" % (time.strftime("%Y%m%d_%H%M%S"), self._banner()))

    def close(self):
        self.bar()
        self.info("[*] %s DONE\n\n%s" % (time.strftime("%Y%m%d_%H%M%S"), self._banner()))
        if len(self.warnings) > 0:
            self.warn("\nTotal of %d warnings during execution:\n%s" % (len(self.warnings), '\n'.join(self.warnings)))
        self.logfile.close()

    def raw(self, msg, extrafile=None):
        sys.stdout.write(msg)
        sys.stdout.flush()
        self.logfile.write(msg)
        self.logfile.flush()
        if extrafile:
            extrafile.write(msg)
            extrafile.flush()

    def info(self, msg):
        print(msg)
        self.logfile.write(msg + '\n')
        self.logfile.flush()

    def warn(self, msg):
        msg = "WARNING: %s" % msg
        print(msg)
        self.warnings.append(msg)
        self.logfile.write(msg + '\n')
        self.logfile.flush()

    def bar(self):
        self.info("\n%s" % ('='*80))

    def execlog(self, cmd, target=None):
        # prepare logs
        self.bar()
        outfilename = self.format_cmd(cmd, target, cleanpath=True)
        exe = self.format_cmd(cmd, target, outfilename)
        outlog = self.netfoot_dir / ('cmd_RUNNING_%s.log' % self.format_cmd(cmd, target, cleanpath=True))
        outlog_ok = self.netfoot_dir / ('cmd_OK_%s.log' % self.format_cmd(cmd, target, cleanpath=True))
        outlog_fail = self.netfoot_dir / ('cmd_FAIL_%s.log' % self.format_cmd(cmd, target, cleanpath=True))
        with outlog.open('w') as outlogfile:
            header = "# %s %s : %s\n\n" % (time.strftime("%Y%m%d_%H%M%S"), cmd[CMD_NAME], exe)
            self.raw(header, outlogfile)
            # run pre-command
            if len(cmd) > CMD_PRE:
                preexe = self.format_exe(cmd[CMD_PRE])
                self.info("running pre-command %s" % preexe)
                if subprocess.call(preexe, shell=True) != 0:
                    self.warn("command %s pre-command exited with non-zero code" % (cmd[CMD_NAME]))
            # run the command
            p = subprocess.Popen(exe, shell=True, cwd=self.netfoot_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1)
            self.child_pid = p.pid
            time_start = time.time()
            for line in iter(p.stdout.readline, b''):
                self.raw(line.decode('utf8'), outlogfile)
            p.wait()
            time_end = time.time()
            self.raw("# [%d] (%.02fs)\n" % (p.returncode, time_end-time_start), outlogfile)
        if p.returncode == 0:
            outlog.rename(outlog_ok)
            outlog = outlog_ok
        else:
            outlog.rename(outlog_fail)
            outlog = outlog_fail
        self.child_pid = None
        # run post-command
        if len(cmd) > CMD_POST:
            postexe = self.format_exe(cmd[CMD_POST])
            self.info("running post-command %s" % postexe)
            if subprocess.call(postexe, shell=True) != 0:
                self.warn("command %s pre-command exited with non-zero code" % (cmd[CMD_NAME]))
        return (outlog, outfilename, p.returncode)

    def format_cmd(self, cmd, target, outfilename=None, cleanpath=False):
        exe = cmd[CMD_BINARY]
        if len(cmd) > CMD_ARGUMENTS:
            exe = "%s %s" % (exe, cmd[CMD_ARGUMENTS])
        exe = self.format_exe(exe, target, outfilename)
        if type(target) is IPv4Network:
            if target.prefixlen != 32:
                targetstr_ip = str(list(target.hosts())[0])
            else:
                targetstr_ip = str(target.network_address)
        elif type(target) is IPv4Address:
            targetstr_ip = str(target)
        else:
            targetstr_ip = 'None'
        exe = exe.replace('%T', targetstr_ip)
        if cleanpath:
            while len(exe) > 240:
                # shorten the longest argument of the command
                exelist = exe.split(' ')
                idxlongarg = exelist.index(max(exelist, key=len))
                longarg = exelist.pop(idxlongarg)
                longarg = longarg[:int(len(longarg)/10)] + '...' + longarg[-int(len(longarg)/10):]
                exelist.insert(idxlongarg, longarg)
                exe = ' '.join(exelist)
        if cleanpath:
            exe = exe.replace('/', '+').replace('=', '').replace(' ', '_').replace('_-', '-').replace('_.', '_').replace('\"', "_")
        return exe

    def format_exe(self, exe, target=None, outfilename=None):
        exe = exe.replace('%i', self.args.iface)
        exe = exe.replace('%l', self.lan_ip)
        exe = exe.replace('%o', outfilename if outfilename else '')
        exe = exe.replace('%r', "%d" % self.args.rate)
        exe = exe.replace('%R', "%d" % self.args.rate_nmap)
        if target:
            exe = exe.replace('%t', str(target))
        return exe 

    def createfile(self, filename, content):
        (self.netfoot_dir / filename).write_text(content)

    def _banner(self):
        if self.args.no_dirtree:
            dirtree_stats = " (disabled by -D)"
        else:
            stats_created, stats_updated = None, None
            if self.dirtree_stats['files_created'] > 0:
                stats_created = 'created %d files' % self.dirtree_stats['files_created']
            if self.dirtree_stats['files_updated'] > 0:
                stats_updated = 'updated %d files' % self.dirtree_stats['files_updated']
            if stats_created or stats_updated:
                dirtree_stats = " (%s)" % ','.join(filter(None, [stats_created, stats_updated]))
            else:
                dirtree_stats = ""
        return """Command-line          : %s
Directory tree output : %s%s
Directory scan logs   : %s
Full log file         : %s""" % (' '.join(sys.argv), self.args.output_dir, dirtree_stats, self.netfoot_dir, self.logpath)

class Netfoot_dirtree(object):
    def __init__(self, args, log, netfoot_dir, netfoot_name):
        self.args = args
        self.log = log
        self.dir = { "nfdir": netfoot_dir, "outdir": Path(args.output_dir).resolve() }
        self.netfoot_name = netfoot_name

    def update(self, tree):
        stats = { 'files_created': 0, 'files_updated': 0 }
        self._update_recurse(self.dir["nfdir"], tree["nfdir"], stats)
        self._update_recurse(self.dir["outdir"], tree["outdir"], stats)
        tree['stats'] = stats
        return

    def close(self):
        self._symlink(self.dir["outdir"] / 'netfoot_lastscan', self.dir["nfdir"])

    def _update_recurse(self, cwd, tree, stats):
        for entry, subtree in tree.items():
            path = cwd / entry
            if type(subtree) is tuple: # symlink
                dest = self.dir[subtree[0]]
                if len(subtree) == 2:
                    dest = dest / subtree[1]
                self._symlink(path, dest)
            elif type(subtree) is str: # file
                if path.is_file():
                    path.unlink()
                    stats['files_updated'] += 1
                else:
                    stats['files_created'] += 1
                self.log.createfile(path, subtree)
            elif type(subtree) in [dict, collections.defaultdict]: # directory
                if not path.is_dir():
                    path.mkdir()
                self._update_recurse(path, subtree, stats)
            else:
                self.log.warn("found unexpected type %s in directory tree, skipping: %s - %s" % (type(subtree), path, subtree))

    def _symlink(self, path, to, replace=True):
        """ create relative symbolic links """
        if path.is_symlink() and replace:
            path.unlink()
        relative = Path(os.path.relpath(to, path.parent))
        path.symlink_to(relative)

class Targets(object):
    def __init__(self, log, load_path=None, load_obj=None, load_str=None):
        self.log = log
        if load_path:
            obj = self._import_path(load_path)
            self.source_txt = "file"
            self.source = load_path
        elif load_obj:
            obj = load_obj
            self.source_txt = "dict"
            self.source = load_obj
        elif load_str:
            obj = self._import_str(load_str)
            self.source_txt = "dict"
            self.source = load_obj
        else:
            obj = dict()
            self.source_txt = "none"
            self.source = None
        self._load(obj)
        self.log.info("loading targets done, %d targets" % len(self.targets))
        self.log.createfile("config_targets.txt", '# netfoot targets generated from %s\n%s' % (self.source_txt, self.to_str()))
        self.log.info("%s" % self.to_str())

    def to_str(self):
        s = ""
        for target, comment in self.targets.items():
            if comment:
                s += "%s # %s\n" % (target, comment)
            else:
                s += "%s\n" % target
        return s

    def lookup(self, ipaddr):
        if ipaddr in self.targets:
            return {'ip': ipaddr, 'comment': self.targets[ipaddr]}
        else:
            for t, comment in self.targets.items():
                if type(t) is IPv4Network and ipaddr in t:
                    return {'network': t, 'comment': 'in %s%s' % (t, "" if comment == None else " %s" % comment)}
        return None
                
    def _load(self, obj):
        self.targets = dict()
        for target in obj:
            if target.find('/') == -1:
                targetaddr = ip_address(target)
            else:
                targetaddr = ip_network(target)
            self.targets[targetaddr] = obj[target]

    def _import_path(self, path):
        targets = dict()
        self.log.info("loading targets from '%s'..." % path)
        with open(path, 'r') if path != '-' else sys.stdin as f:
            for nline, line in enumerate(f.readlines()):
                try:
                    t = re.search('^([0-9a-zA-Z\.\/]+)[ #]*(.*)', line)
                    if t:
                        target, comment = t.groups()
                        if target in targets:
                            self.log.warn("target %s (%s) on line %d already in targets as %s" % (target, comment, nline, targets[target]))
                        else:
                            targets[target] = comment
                    elif line == '\n' or line.startswith("#"):
                        continue
                    else:
                        raise Exception("invalid line format")
                except (netaddr.core.AddrFormatError, Exception) as e:
                    self.log.warn("invalid target entry line %d, skipping '%s' : %s" % (nline+1, line, e))
                    continue
        return targets

    def _import_str(self, s):
        targets = dict()
        for t in s:
            targets[t] = None
        return targets

# position of elements in OUTPUT_FILES_PATTERNS of Proc class childs
OUTPUT_FILES_PATTERNS_GLOB = 0
OUTPUT_FILES_PATTERNS_EXTENSION = 1

class Proc(object):
    def __init__(self, log, logfile, outfilename, ffrom, now, targets):
        self.log = log
        self.logfile = logfile
        self.ffrom = ffrom
        self.now = now
        self.targets = targets
        self.tree = {
            'nfdir': { "from_%s" % ffrom: ("outdir", "from_%s" % ffrom) },
            'outdir': { "from_%s" % ffrom: { "perspective": ffrom } },
        }

    def create_base_host(self, ip):
        tree = self.tree
        ffrom = self.ffrom
        now = self.now
        tree["nfdir"]["host_%s" % ip] = ("outdir", "from_%s/host_%s_%s" % (ffrom, ip, now))
        tree["outdir"]["host_%s" % ip] = {"ip": ip}
        tree["outdir"]["host_%s" % ip]["from_%s_%s" % (ffrom, now)] = ("outdir", "from_%s/host_%s_%s" % (ffrom, ip, now))
        tree["outdir"]["host_%s" % ip]["from_%s_lastseen" % ffrom] = ("outdir", "from_%s/host_%s_lastseen" % (ffrom, ip))
        tree["outdir"]["host_%s" % ip]["from_%s" % ffrom] = ("outdir", "from_%s/host_%s" % (ffrom, ip))
        dict_merge(tree["outdir"]["from_%s" % ffrom], {
            "host_%s_%s" % (ip, now): {
                "host": ("outdir", "host_%s" % ip),
                "netfoot": ("nfdir", ),
            },
            "host_%s_lastseen" % ip: ("outdir", "from_%s/host_%s_%s" % (ffrom, ip, now)),
            "host_%s" % ip: {
                "host": ("outdir", "host_%s" % ip),
            },
        })
        target = self.targets.lookup(ip_address(ip))
        if target and target['comment']:
            tree["outdir"]["from_%s" % ffrom]["host_%s_%s" % (ip, now)]["comment"] = target['comment']
            tree["outdir"]["from_%s" % ffrom]["host_%s" % ip]["comment"] = ("outdir", "from_%s/host_%s_%s/comment" % (ffrom, ip, now))
        return target

    def symlink_dir_content(self, target, targetpath, source, ignorelist=[]):
        """ iterate over items in 'target' tree and creates symlink to them from 'source'
        NOTE: 'target' and 'source' must be at same directory depth not to break symlinks copy """
        for entry, subtree in target.items():
            if entry in ignorelist:
                continue
            if type(subtree) is str: # file
                source[entry] = ("outdir", "%s/%s" % (targetpath, entry))
            elif type(subtree) is tuple: # symlink
                source[entry] = subtree
            elif type(subtree) in [dict, collections.defaultdict]: # directory
                if entry not in source:
                    source[entry] = dict()
                self.symlink_dir_content(subtree, "%s/%s" % (targetpath, entry), source[entry], ignorelist)
            else:
                self.log.warn("found unexpected type %s while processing target %s tree, skipping: %s" % (type(subtree), targetpath, subtree))

class Proc_masscan(Proc):
    OUTPUT_FILES_PATTERNS = [ ('masscan-*.xml', '.xml') ]

    def __init__(self, log, logfile, outfilename, ffrom, now, targets):
        super().__init__(log, logfile, outfilename, ffrom, now, targets)
        xmlfile = self.log.netfoot_dir / ("%s.xml" % outfilename)
        if not xmlfile.exists():
            self.log.warn("could not find masscan output file to process, directory structure will not get updated : %s" % xmlfile)
            self.xml = None
        if xmlfile.stat().st_size == 0:
            self.log.info("masscan output file is empty")
            self.xml = None
        else:
            self.xml = ElementTree.parse(xmlfile)

    def process_output(self):
        if not self.xml:
            return None
        root = self.xml.getroot()
        for host in root.findall('.//host'):
            ip = host.find('address').get('addr')
            target = self.create_base_host(ip)
            ports = collections.defaultdict(lambda: collections.defaultdict(dict))
            for port in host.find('ports').findall('.//port'):
                p = {
                    'state': port.find('state').get('state'),
                    'reason_ttl': port.find('state').get('reason_ttl'),
                }
                reason = port.find('state').get('reason')
                if reason != 'response': # 'reason' from banner grabbing, should not delete the initial port-scan reason
                    p['reason'] = reason
                    p['answer_time'] = time.strftime("%Y%m%d_%H%M%S", time.localtime(int(host.get('endtime'))))
                else:
                    p['banner_answer_time'] = time.strftime("%Y%m%d_%H%M%S", time.localtime(int(host.get('endtime'))))
                if port.find('service') is not None:
                    name = port.find('service').get('name')
                    banner = port.find('service').get('banner')
                    p['banner_%s' % name] = banner
                dict_merge(ports[port.get('protocol')][port.get('portid')], p)
            dict_merge(self.tree["outdir"]["from_%s" % self.ffrom]["host_%s_%s" % (ip, self.now)], ports)
            self.symlink_dir_content(self.tree["outdir"]["from_%s" % self.ffrom]["host_%s_%s" % (ip, self.now)],
                    "from_%s/host_%s_%s" % (self.ffrom, ip, self.now),
                    self.tree["outdir"]["from_%s" % self.ffrom]["host_%s" % ip],
                    ["netfoot"])
        return self.tree

class Proc_nmap(Proc):
    OUTPUT_FILES_PATTERNS = [ ('nmap-*.xml', '.xml') ]

    def __init__(self, log, logfile, outfilename, ffrom, now, targets):
        super().__init__(log, logfile, outfilename, ffrom, now, targets)
        xmlfile = self.log.netfoot_dir / ("%s.xml" % outfilename)
        if not xmlfile.exists():
            self.log.warn("could not find nmap output file to process, directory structure will not get updated : %s" % xmlfile)
            self.xml = None
        else:
            self.xml = ElementTree.parse(xmlfile)

    def process_output(self):
        if not self.xml:
            return None
        root = self.xml.getroot()
        for host in root.findall('.//host'):
            if host.find('status').get('state') == 'down':
                continue
            ip = host.find('address').get('addr')
            target = self.create_base_host(ip)
            self.tree["outdir"]["from_%s" % self.ffrom]["host_%s_%s" % (ip, self.now)]["state_up_reason"] = host.find('status').get('reason')
            ports = collections.defaultdict(lambda: collections.defaultdict(dict))
            if host.find('ports'):
                for port in host.find('ports').findall('.//port'):
                    if port.find('state').get('state') == "filtered" and port.find('state').get('reason') == "no-response":
                        continue
                    p = {
                        'state': port.find('state').get('state'),
                        'reason_ttl': port.find('state').get('reason_ttl'),
                    }
                    p['reason'] = port.find('state').get('reason')
                    if port.find('service') is not None:
                        name = port.find('service').get('name')
                        product = port.find('service').get('product')
                        version = port.find('service').get('version')
                        extrainfo = port.find('service').get('extrainfo')
                        p['product_%s' % name] = ' '.join(filter(None, [product, version, extrainfo]))
                    for script in port.findall('script'):
                        p[script.get('id')] = script.get('output')
                    dict_merge(ports[port.get('protocol')][port.get('portid')], p)
            if host.find('trace'):
                trace = ""
                tracemethod = ''.join(filter(None, [host.find('trace').get('proto'), host.find('trace').get('port')]))
                tracename = "traceroute_%s" % tracemethod if len(tracemethod) > 0 else "traceroute"
                for hop in host.findall('trace/hop'):
                    trace += "%s\t%s\t%s\n" % (hop.get('ttl'), hop.get('rtt'), hop.get('ipaddr'))
                self.tree["outdir"]["from_%s" % self.ffrom]["host_%s_%s" % (ip, self.now)][tracename] = trace
            dict_merge(self.tree["outdir"]["from_%s" % self.ffrom]["host_%s_%s" % (ip, self.now)], ports)
            self.symlink_dir_content(self.tree["outdir"]["from_%s" % self.ffrom]["host_%s_%s" % (ip, self.now)],
                    "from_%s/host_%s_%s" % (self.ffrom, ip, self.now),
                    self.tree["outdir"]["from_%s" % self.ffrom]["host_%s" % ip],
                    ["netfoot"])
        return self.tree

"""Commands arguments format:
%i : interface name
%l : LAN IP
%o : output file name, generated from binary and arguments
%r : rate, number of packets per second
%R : rate, in nmap timing scale
%t : target
%T : target converted to IP
"""
CMD_NAME = 0                   # cmd name
CMD_BINARY = 1                 # binary name
CMD_ARGUMENTS = 2              # binary arguments
CMD_TARGET_MODE = 3            # all_targets_file, single_target
CMD_OUTPUT_PROCESSINGCLASS = 4 # class to process the scan output, see Proc_*
CMD_PRE = 5                    # command to execute before binary
CMD_POST = 6                   # command to execute after binary
MASSCAN_ARGUMENTS = '--interactive --rate=%r -e %i --adapter-port 61389 --banners --capture html -p21,22,23,25,53,80,88,110,111,143,443,445,554,1098,3306,3389,5900,6000,6881,8080,8081,8443,10000,27017 --ports U:53,U:67,U:111,U:123,U:161,U:500,U:2123,U:5060 --ping -oX %o.xml'
MASSCAN_ARGUMENTS_ALLPORTS = '--interactive --rate=%r -e %i --adapter-port 61389 --banners --capture html -p0-65535 --ports U:53,U:67,U:111,U:123,U:161,U:500,U:2123,U:5060 --ping -oX %o.xml'
MASSCAN_PRE = 'iptables -A INPUT -p tcp -i %i --dport 61389 -j DROP'
MASSCAN_POST = 'iptables -D INPUT -p tcp -i %i --dport 61389 -j DROP'
CMDS = {
    # XXX 'background': [
    #    ['Network capture', 'tcpdump', '-n -w capture_tcpdump_%i.pcap -i %i'],
    #],
    'localinfos' : [
        # internally we also get pub_ip (url ifconfig.me) and lan_ip (ip -o a s dev <iface> |awk '{print $4}' |cut -d'/' -f1)
        ['IP addresses', 'ip', 'addr show'],
        ['IP routes', 'ip', 'route show'],
        ['DNS servers', 'grep', '-q systemd /etc/resolv.conf && systemd-resolve --status || cat /etc/resolv.conf'],
        ['Wifi settings', 'iwconfig'],
    ],
    'landiscovery' : [
        ['Traceroute google', 'traceroute', '-n 8.8.8.8', None],
        ['UPNP connections', 'upnpc', '-m %i -s ||true'],
        ['UPNP redirects', 'upnpc', '-m %i -l ||true'],
        ['LAN portscan', 'masscan', MASSCAN_ARGUMENTS+' %l/24', 'all_targets_file', Proc_masscan, MASSCAN_PRE, MASSCAN_POST],
        ['Speedtest', 'speedtest'],
    ],
    'portscan' : [
        ['Portscan', 'masscan', MASSCAN_ARGUMENTS+' -iL %t', 'all_targets_file', Proc_masscan, MASSCAN_PRE, MASSCAN_POST],
    ],
    'portscan_allports' : [
        ['Portscan all ports', 'masscan', MASSCAN_ARGUMENTS_ALLPORTS+' -iL %t', 'all_targets_file', Proc_masscan, MASSCAN_PRE, MASSCAN_POST],
    ],
    'portscan_nmap_aggressive' : [
        ['Portscan nmap aggressive', 'nmap', '-sV -sS -O --traceroute -e %i -T %R -v100 --script="safe or brute" -p 0-65535 -PE -PS22,443 -PA80 -PP -oA %o -iL %t', 'all_targets_file', Proc_nmap],
    ],
    'scan_hostinfos' : [
        ['Traceroute', 'traceroute', '-n %T', 'single_target'],
        ['SNMP walk', 'snmpwalk', '-v 2c -c public %T system ||true', 'single_target'],
    ],
}
CMDS_ALWAYS = ['localinfos']
CMDS_USER = sorted(CMDS.keys() - CMDS_ALWAYS)
CMDS_DEFAULT_LANDISCOVERY = ["landiscovery"]
CMDS_DEFAULT_TARGET = ["portscan", "scan_hostinfos"]
CMDS_OUTPUT_PROCESSINGCLASSES = [ Proc_masscan, Proc_nmap ]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='netfoot %s\nquick active network footprinting' % VERSION, epilog=EPILOG, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-c', dest='commands', help='use specific commands group(s), or \'help\' to list commands')
    parser.add_argument('-f', dest='ffrom', default=socket.gethostname(), help='name of the scan perspective, defaults to hostname')
    parser.add_argument('-i', dest='import_dir', help='import scan directory and create output directory tree. usefull to import previous scans done with -D')
    parser.add_argument('-o', dest='output_dir', default=Path().cwd(), help='output directory tree, or \'help\' to preview output layout. defaults current directory')
    parser.add_argument('-t', dest='targets_file', help='use targets from file or - for stdin, one ip/range per line')
    parser.add_argument('-r', dest='rate', default=100, type=int, help='packet rate for scans, defaults to 100')
    parser.add_argument('-D', dest='no_dirtree', action='store_true', default=False, help='disable directory tree output')
    # XXX parser.add_argument('-E', dest='no_exec', action='store_true', default=False, help='list what would be executed or imported, but don\'t perform any actions')
    parser.add_argument('-N', dest='no_internet', action='store_true', default=False, help='disable internet tests')
    parser.add_argument('iface', help='network interface to use', nargs='?')
    parser.add_argument('targets', metavar='target', nargs='*', help='target IPs and IP ranges, leave empty for LAN discovery')
    args = parser.parse_args()
    
    if args.output_dir == "help":
        print(HELP_OUTPUT)
        sys.exit(0)
    if args.commands == "help":
        print("Commands always executed : %s" % ','.join(CMDS_ALWAYS))
        print("Default commands if only interface is specified : %s" % ','.join(CMDS_DEFAULT_LANDISCOVERY))
        print("Default commands if targets are specified : %s" % ','.join(CMDS_DEFAULT_TARGET))
        print("Commands list:")
        for name, cmds in CMDS.items():
            print("++ %s" % name)
            for c in cmds:
                print("| %s: %s %s %s" % (c[CMD_NAME], c[CMD_BINARY], c[CMD_ARGUMENTS] if len(c) > CMD_ARGUMENTS else "", "(t=%s)" % c[CMD_TARGET_MODE] if len(c) > CMD_TARGET_MODE and c[CMD_TARGET_MODE] is not None else ""))
        sys.exit(0)
    if args.import_dir == "help":
        print("""Import previously created scans logs directory and create output directory tree (see netfoot -o help).
Scan logs must be inside a directory previously created by netfoot or manual scans following with a specific naming.
Scan logs directory name created by netfoot (or netfoot -D):
* netfoot_<date>_<time>_<perspective>_<interface>_pub<public_ip>_lan<lan_ip>/
Required file naming in import directory:
* 'config_date_start.txt' must exist and contain a date in the format %Y%m%d_%H%M%S
* 'config_perspective.txt' must exist and contain the name of the scan perspective, like netfoot -f argument
* 'config_targets.txt' must exist and contain one targets per line, like nmap -iL format
* optional: nmap scan output (nmap -oX) must be named like '{nmap_file_patterns}'
* optional: masscan scan output (masscan -oX) must be named like '{masscan_file_patterns}'""".format(
            nmap_file_patterns=','.join([p[OUTPUT_FILES_PATTERNS_GLOB] for p in Proc_nmap.OUTPUT_FILES_PATTERNS]),
            masscan_file_patterns=','.join([p[OUTPUT_FILES_PATTERNS_GLOB] for p in Proc_masscan.OUTPUT_FILES_PATTERNS])))
        sys.exit(0)
    if args.import_dir:
        try: netfoot_import = Netfoot_import(args)
        except Netfoot_error as e:
            print("error: could not initialize netfoot_import, %s" % e)
            sys.exit(1)
        netfoot_import.run()
        netfoot_import.end()
        sys.exit(0)
    if not args.iface:
        parser.print_help()
        print("error: you must at least specify an interface")
        sys.exit(1)
    if args.targets and args.targets_file:
        parser.print_help()
        print("error: you cannot specify targets on command-line and targets file at the same time")
        sys.exit(1)
    if args.commands and args.commands not in CMDS_USER:
        parser.print_help()
        print("error: command groups must be one of %s" % CMDS_USER)
        sys.exit(1)
    if os.geteuid() != 0:
        print("you must be root")
        sys.exit(1)

    try: netfoot = Netfoot(args)
    except Netfoot_error as e:
        print("error: could not initialize netfoot, %s" % e)
        sys.exit(1)
    netfoot.run()
    netfoot.end()
