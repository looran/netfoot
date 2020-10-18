#!/bin/sh

set -e

PROG="$(basename $0)"
LOCAL_DIR="$(pwd)"
LOCALBIN_DIR="$(dirname $0)"
REMOTE_DIR="${REMOTE_DIR:-/tmp/netfoot}"
PROCESS_NAMES="netfoot|netrun|masscan|patator"

usageexit() {
    cat <<-_EOF
usage: $PROG <host> (deploy|run|check|tail|fetch-results|fetch-tools|kill|shred) ...
actions:
    <host> deploy                    : copy netfoot tools to remote host
    <host> run netfoot|netcred <options> : run program on remote host (stdin will not work).
                                           for netfoot, -D option is added automatically
    <host> check                     : check status of execution on remote host
    <host> tail netfoot              : tail log of tool, to get real-time results
    <host> fetch-results             : fetch results from remote host to netfoot_remote_<host>/
    <host> fetch-tools               : fetch netfoot tools from remote host
    <host> kill                      : stop execution of tools on remote host
    <host> shred                     : delete tools and results from remote host
    help-examples                    : provide additional example usages
environment variables:
    REMOTE_DIR: base directory for tools and results on remote host
_EOF
    exit 1
}

helpexamplesexit() {
    cat <<-_EOF
example scans with netfoot and netcred from remote host 192.168.1.1:
    $PROG 192.168.1.1 deploy

    $PROG 192.168.1.1 run netfoot -f as1300 -t /tmp/targets_lab.txt eth0
    $PROG 192.168.1.1 check
    $PROG 192.168.1.1 tail netfoot
    $PROG 192.168.1.1 fetch-results

    $PROG 192.168.1.1 run netcred -v brute ssh <remote_scandir>
    $PROG 192.168.1.1 check
    $PROG 192.168.1.1 fetch-results

    $PROG 192.168.1.1 shred
_EOF
    exit 0
}

trace() {
    echo "# $*" 1>&2
    "$@"
}

confirm() {
    msg="$1"
    echo -e "CONFIRM: $msg\nexecute ? [enter/ctrl-c]"
    read a
}

log() {
    msg="$1"
    echo $msg
    msg="$(date "+%Y%m%d_%H%M%S") $msg"
    echo $msg >> $logfile
}

ensureroot() {
		whoami=$(trace ssh "$host" "whoami")
		[ X"$whoami" != X"root" ] && echo "error: must be root on remote host $host" && exit 1 ||true
}

do_check() {
    trace ssh "$host" "egrep -H 'START|DONE' $REMOTE_DIR/scans/netfoot_*/netfoot_*.log"
    trace ssh "$host" "ps -ef |grep -v \"$PROCESS_NAMES\" |egrep \"$PROCESS_NAMES\"" && log "scan in progress" || log "idle"
}

[ $# -eq 1 -a "$1" = "help-examples" ] && helpexamplesexit
[ $# -lt 2 ] && usageexit
now=$(date "+%Y%m%d_%H%M%S")
host="$1"
action="$2"
host_machine="$(echo $host |sed 's/.*@\(.*\)/\1/')" # remove user login if any
outdir="$(realpath $LOCAL_DIR/netfoot_remote_$host_machine)"
mkdir -p "$outdir"
logfile="$outdir/netfoot_remote_$host_machine.log"
echo "logging to $logfile"
shift; shift
case $action in
deploy)
    log "deploy"
    trace ssh "$host" "mkdir -p $REMOTE_DIR; mkdir -p $REMOTE_DIR/scans"
    trace ssh "$host" "[ -e $REMOTE_DIR/netfoot ] && cp $REMOTE_DIR/netfoot $REMOTE_DIR/netfoot.bak.$now ||true"
    trace ssh "$host" "[ -e $REMOTE_DIR/netcred ] && cp $REMOTE_DIR/netcred $REMOTE_DIR/netcred.bak.$now ||true"
    [ -e $LOCALBIN_DIR/netfoot.py ] && bin_netfoot="$LOCALBIN_DIR/netfoot.py" || bin_netfoot="$LOCALBIN_DIR/netfoot" 
    [ -e $LOCALBIN_DIR/netcred.sh ] && bin_netcred="$LOCALBIN_DIR/netcred.sh" || bin_netcred="$LOCALBIN_DIR/netcred" 
    trace scp $LOCALBIN_DIR/$bin_netfoot "$host":"$REMOTE_DIR/netfoot"
    trace scp $LOCALBIN_DIR/$bin_netcred "$host":"$REMOTE_DIR/netcred"
    trace ssh "$host" "uname -ap" > "$outdir/uname"
    trace ssh "$host" "ifconfig" > "$outdir/ifconfig"
    ;;
run)
    [ $# -lt 2 ] && usageexit
    prog="$1"
    shift
	opts="$@"
	case $prog in
	netfoot)
		opts="-D $opts"
		ensureroot
		;;
	netcred) ;;
	*) usageexit ;;
	esac
    log "action run $prog $opts"
    trace ssh "$host" "cd $REMOTE_DIR/scans; /bin/sh -c \"../$prog $opts &\" >& /dev/null; sleep 0.2"
	trace sleep 2
	do_check
    ;;
check)
    log "action check"
	do_check
    ;;
tail)
    [ $# -lt 1 ] && usageexit
    prog="$1"
    case $prog in
    netfoot)
        log "action tail netfoot"
        trace ssh "$host" "logfile=\"\$(ls $REMOTE_DIR/scans/\$(ls $REMOTE_DIR/scans/ |grep 'netfoot_' |grep -v last |tail -n1)/netfoot*.log)\" && echo \"tail -f \$logfile\" && tail -f \$logfile"
        ;;
    *)
        usageexit
    esac
    ;;
fetch-results)
    log "action fetch-results"
    trace rsync -avP "$host":"$REMOTE_DIR/scans" $outdir/
    log "DONE, results stored in $outdir"
    echo "hint: use 'netfoot -i' to import scans"
    ;;
fetch-tools)
    log "action fetch-tools"
    trace scp "$host":"$REMOTE_DIR/netfoot" $outdir/netfoot.py
    trace scp "$host":"$REMOTE_DIR/netcred" $outdir/netcred.sh
    log "DONE, tools fetched to $outdir"
    ;;
kill)
	ensureroot
    confirm "going to kill running netfoot tools on $host ($PROCESS_NAMES)"
    log "action kill"
    trace ssh "$host" "pkill -x \"$PROCESS_NAMES\""
    ;;
shred)
	ensureroot
    confirm "going to shred directory $REMOTE_DIR on $host (tools and results)"
    log "action shred"
    trace ssh "$host" "find $REMOTE_DIR -type f -exec shred -v -n1 -u {} \; && rm -rf $REMOTE_DIR" && log "DONE, removal OK" || log "error: removal FAILED"
    ;;
*)
    usageexit
    ;;
esac
