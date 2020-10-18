#!/bin/sh

# netcred - look for credentials on the network or offline
# Copyright (c) 2017, 2020 Laurent Ghigonis <ooookiwi@gmail.com>

set -e

PROG="$(basename $0)"
THREADS=${THREADS:-2}
CREDENTIALS_DEFAULTS="root:root
root:root123
root:root1234
root:r00t
root:12345678
root:ubnt
root:changeme
root:password
root:password1
root:toor
admin:admin
admin:password
admin:password1
admin:admin123
admin:admin1234
admin:12345678
admin:123456
admin:cisco
user:user
test:test
ftp:ftp
ftpuser:ftpuser
oracle:oracle
cisco:cisco
cisco:admin
guest:guest
mysql:mysql
anonymous:anonymous"
DICTS_DIR="$HOME/src/dict"
RULES_DIR="$HOME/src/rule"
HASHCAT="${HASHCAT:-hashcat}"
PATATOR="${PATATOR:-patator.py}"

usageexit() {
	cat <<-_EOF
usage: $PROG [-v] (brute|john|hashcat-(infos|dict|brute)|show-defaults) ...
    -v : verbose
actions:
    brute <proto> (-d <netfoot_scandir> | -f <ips.txt> | <ip>[<ip>..]) [-- <patator_opts]
        proto: ssh | http-basic
        THREADS: threads to use [$THREADS]
        CREDENTIALS: optional credentials file (see $PROG show-defaults)
    john <hashfile|->
        JOHN_OPTS
    hashcat-infos
    hashcat-dict <hashtype> <filetype raw|passwd> <hashfile|-> <dict[,dict2][,COMBINE]> [<rules>]
        hashtype examples: 500 (md5), 1500 (descrypt, DES (Unix), Traditional DES)
            7400 (sha256crypt \$5$, SHA256 (Unix))
        dict examples: <yourdict>-COMBINE (fast)
            SecLists/Passwords/passwords_john.txt (fast),
              SecLists/Passwords/honeynet.txt (medium),
              rockyou.txt (slow)
        rules examples: best64.rule (fast), d3ad0ne.rule (medium), dive.rule (slow)
        HASHCAT_OPTS
    hashcat-brute <hashtype> <filetype> <hashfile|->
        HASHCAT_OPTS
    show-defaults
	_EOF
	exit 1
}

trace() {
	echo "# $@"
	eval "$@"
}

[ $# -lt 1 -o X"$1" = "-h" ] && usageexit
verbose=0
[ $1 = "-v" ] && verbose=1 && shift
echo "verbose=$verbose"
action="$1"
shift

case $action in
brute)
	[ $# -lt 2 ] && usageexit
	proto=$1
	shift
	case $proto in
	ssh)
		port=22
        quiet_opts="-x ignore:mesg=\"Authentication failed.\""
        [ $verbose -eq 1 ] && quiet_opts=""
		patator_opts="ssh_login --max-retries=1 \
            -x free=host:fgrep=\"paramiko.ssh_exception.SSHException\" \
            -x free=host+user:fgrep=\"Bad authentication type; allowed types: ['publickey']\" \
            -x free=host+user:code=0 \
            $quiet_opts \
			host=FILE1 user=COMBO00 password=COMBO01 \
			auth_type=auto"
		;;
	http-basic)
		[ $# -lt 3 ] && usageexit
		url="$3"
		port=80
        quiet_opts="-x ignore:code=401"
        [ $verbose -eq 1 ] && quiet_opts=""
		patator_opts="http_fuzz --max-retries=1 \
			$quiet_opts \
			host=FILE1 user_pass=FILE0 \
			url=http://FILE1${url}"
		;;
	*) usageexit ;;
	esac
	case $1 in
	-f)
		[ $# -lt 2 ] && usageexit
		target=$2
        shift; shift
		target_type="file"
		[ ! -e $target ] && echo -e "error: target file does not exist : $target\n" && usageexit
		D="$(echo $target |cut -d'.' -f1)_netcred_brute_$proto"
		;;
	-d)
		[ $# -lt 2 ] && usageexit
		target=$2
        shift; shift
		target_type="netfoot_scandir"
		D="$target/netcred_brute_$proto"
		;;
	*)
		target="$(mktemp /tmp/netcred_ips_XXX)"
		target_type="ip_arguments"
		for ip in $@; do
			echo $ip >> $target
		done
		D="netcred_brute_$proto"
		;;
	esac
    while true; do case $1 in
        --) shift; patator_opts="$patator_opts $*"; break;;
        '') break;;
        *) shift;;
    esac done
	echo "=== running brute $proto ==="
	now="$(date +%Y%m%d_%H%M%S)"
	echo "target           : $target"
	echo "target_type      : $target_type"
	echo "output           : $D"
	echo "THREADS          : $THREADS"
	mkdir -p $D ||exit 1
	ips="$D/ips_$now.txt"
	credentials="$D/credentials_$now.txt"

	echo "[+] computing ip/credentials"
	if [ $target_type = "netfoot_scandir" ]; then
		#find $target/host_*/ -path "*/tcp/$port" -exec cat {}/../../host/ip \; |awk '!x[$0]++' > "$ips"
        find $target/host_*/ -path "*/tcp/22" |while read l; do echo "$(cat $l/../../host/ip)"; done > "$ips"
	else
		cp $target $ips
	fi
	trace cat $ips
	( [ X"$CREDENTIALS" != X"" ] && cat $CREDENTIALS || echo "$CREDENTIALS_DEFAULTS" ) |egrep -v "^#|^$" |grep ':' |cut -d' ' -f1 > "$credentials"
	trace cat $credentials

	echo "[+] running patator"
	trace $PATATOR $patator_opts 1="$ips" 0="$credentials" -t $THREADS -l $D -L netcred

	echo "[*] extracting results from all runs"
	find $D/ -name RESULTS.csv -exec cat {} \; \
		|awk -F',' '{ print $6,$1,$2,$3,$4,$5,$7,$8 }' \
		|sed s/"\"\([^:]*\):\([^:]*\):\([^:]*\)\""/"\3:\2:\1"/ \
		|sort |uniq > $D/results.txt
	echo "stored in $D/results.txt"
	;;
john)
	[ $# -lt 1 ] && usageexit
	[ $1 = "-" ] && cat > /tmp/h || cp $1 /tmp/h
	trace john --show $JOHN_OPTS /tmp/h
	trace nice -n 20 john $JOHN_OPTS /tmp/h
	trace rm /tmp/h
	;;
hashcat-infos)
	trace "find $DICTS_DIR -type f -exec wc -l {} \; |sort -n -r"
	trace "find $RULES_DIR -type f -exec wc -l {} \; |sort -n -r"
	trace $HASHCAT -I
	echo "# $HASHCAT --help : to get hash types"
	;;
hashcat-dict)
	[ $# -lt 4 ] && usageexit
	hashtype=$1
	hashfiletype=$2
	hashfile=$3
	dict=$4
	[ $# -eq 5 ] && HASHCAT_OPTS="$HASHCAT_OPTS -r $RULES_DIR/$5"
	echo > /tmp/dictc2
	echo "[+] compute hashes in /tmp/hc"
	[ $hashfile = "-" ] && cat > /tmp/hc2 || cp $hashfile /tmp/hc2
	if [ $hashfiletype = "passwd" ]; then
		cat /tmp/hc2 |cut -d':' -f2 > /tmp/hc
		# add usernames in dict
		cat /tmp/hc2 |cut -d':' -f1 >> /tmp/dictc2
	else
		cp /tmp/hc2 /tmp/hc
	fi
	rm /tmp/hc2
	echo "[+] computing dictionary in /tmp/dictc"
	IFS=','; for d in $dict; do
		if [ $d = "COMBINE" ]; then
			# combine current dictionary entries
			$HASHCAT -a1 --stdout /tmp/dictc2 /tmp/dictc2 > /tmp/dictc3 ||true
			mv /tmp/dictc3 /tmp/dictc2
			continue
		fi
		dpath=$d
		[ ! -e $dpath ] && dpath=$DICTS_DIR/$d
		[ ! -e $dpath ] && echo "dict $d not found in pwd and $DICTS_DIR" && exit 1
		cat $dpath |egrep -v "^#|^$" |cut -d':' -f2 |cut -d' ' -f1 >> /tmp/dictc2
	done
	if [ $(wc -l /tmp/dictc2 |cut -d' ' -f1) -lt 500000 ]; then
		# enforce unicity of entries if file is not too big
		cat /tmp/dictc2 |awk '!x[$0]++' > /tmp/dictc
	else
		cp /tmp/dictc2 /tmp/dictc
	fi
	rm /tmp/dictc2
	echo "[+] running hashcat ($(wc -l /tmp/hc) hashes)"
	cat /tmp/hc
	trace $HASHCAT --show -m$hashtype -a0 $HASHCAT_OPTS /tmp/hc /tmp/dictc
	trace nice -n 20 $HASHCAT -m$hashtype -a0 $HASHCAT_OPTS /tmp/hc /tmp/dictc
	trace rm /tmp/hc
	trace rm /tmp/dictc
	;;
hashcat-brute)
	[ $# -lt 3 ] && usageexit
	echo XXX TODO
	;;
show-defaults)
	echo "default credentials:
$CREDENTIALS_DEFAULTS"
	;;
*)
	usageexit
	;;
esac
