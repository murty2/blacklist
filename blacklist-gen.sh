#!/bin/bash
# Generate a blacklist of bad hosts

# (C) Murty Rompalli
# Last Updated: 7/3/2021

# NOTE:
#  1. Compile and build iprange as follows:
#       git clone https://github.com/firehol/iprange iprange.git
#       cd iprange.git
#       ./autogen.sh && ./configure --disable-man && make
#       strip iprange
#       cp iprange ..
#
#  2. Run through non-root user's cron: 22 0 * * * ~/scripts/vps/blacklist/blacklist-gen.sh
#
#  3. On the remote server prod1.server.com:
#       Make sure /root/blacklist-apply.sh exists and executable by root. Run via root's cron:
#       0 2 * * * /root/blacklist-apply.sh https://your-website.com/ipset.txt

# TODO: Add IPv6 blacklists and migrate from iprange (which only supports ipv4) to aggregate6
# TODO: Consider blocking DigitalOcean: https://ip.rst.im/blocks/digitalocean
# TODO: Create a separate script (as a replacement for Fail2Ban):
#   Fetch brute force attackers from production boxes first:
#     journalctl -q -t sshd -o cat -S yesterday | grep 'Invalid user' | cut -d' ' -f5 | sort -uV
#   Fetch brute force attackers for Dovecot and webservers (from webserver logs)

[ $(id -u) -eq 0 ] && echo $0: Must NOT be run as root && exit 1
cd $(dirname $0) || exit 2

# Define ipset name and file names
IPSETNAME=blacklist
HOSTS=hosts
RESTORE=/path/to/your-docroot/ipset.txt
LOCK=.lock

# Can we create RESTORE file?
touch $RESTORE || exit 3

# Define executables
IPRANGE=./iprange
which wget > /dev/null && WGET='wget --tries=1 -4q' || exit 4

if ! mkdir $LOCK 2> /dev/null
then
  echo $0: $LOCK exists, aborting
  exit 5
fi

trap 'rmdir $LOCK' EXIT
trap 'echo Exiting on trap; exit 255' INT TERM HUP PIPE

# Blacklists
LIST=(
'contact-form-spammers'  # List of IPv4 addresses that spam us through our /contact form
'https://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1' # Dictionary Attackers
'https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1'  # TOR Exit Nodes
'http://danger.rulez.sk/projects/bruteforceblocker/blist.php' # BruteForceBlocker IP List
'https://www.spamhaus.org/drop/drop.lasso' # Spamhaus Don't Route Or Peer List (DROP)
'https://cinsscore.com/list/ci-badguys.txt' # C.I. Army Malicious IP List
'https://lists.blocklist.de/lists/all.txt' # blocklist.de attackers
'https://blocklist.greensnow.co/greensnow.txt' # GreenSnow
'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset' # Firehol Level 1
'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/stopforumspam_7d.ipset' # Firehol forum
# 'http://ipverse.net/ipblocks/data/countries/xx.zone' # Ban an entire country, see http://ipverse.net/ipblocks/data/countries/
)

# Add static bad hosts: Censys.io scanners, Cyveillance scanners, repeat offenders
cat << XYZ > $HOSTS
# censys.io scanners
74.120.14.0/24
162.142.125.0/24
167.248.133.0/24
192.35.168.0/23

# Other offenders
192.3.143.11
207.244.117.217
142.147.104.0/21
45.83.91.58

# Cyveillance scanners
38.100.19.8/29
38.100.21.0/24
38.100.41.64/26
38.105.71.0/25
38.105.83.0/27
38.112.21.140/30
38.118.42.32/29
65.213.208.128/27
65.222.176.96/27
65.222.185.72/29
151.173.0.0/16

# HTTP Banner Detection by security.ipip.net
103.203.57.0/24

# Russian Girl Romance Scams
178.126.160.0/19
XYZ

# Download all blacklists and extract bad hosts from them
# If a download fails, use a previously downloaded file (if any)
for i in "${!LIST[@]}"
do
  if [[ ! "${LIST[$i]}" =~ ^https?:// ]]
  then
    echo >> $HOSTS
    echo \# ${LIST[$i]} >> $HOSTS
    cat "${LIST[$i]}" >> $HOSTS
    continue
  fi

  $WGET -O $i.tmp ${LIST[$i]}

  if [ -f $i.tmp -a -s $i.tmp ]
  then
    \mv -f $i.tmp $i
  else
    echo WARNING: wget error: ${LIST[$i]}
    \rm -vf $i.tmp
  fi

  [ -f $i -a -s $i ] || continue
  echo >> $HOSTS
  echo \# ${LIST[$i]} >> $HOSTS

  cat $i |
    sed -e 's/<[^<>]*>//g' -e 's/#.*//' -e 's/^\s*//' -e 's/\b0*\B//g' |
    grep -Po '^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b' |
    sed -r -e '/^(0\.0\.0\.0|10\.|127\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.|22[4-9]\.|23[0-9]\.)/d' |
    grep '\S' >> $HOSTS
done

# Daily entries by stamparm: only those offenders that appear more than twice
echo >> $HOSTS
echo \# https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt >> $HOSTS
$WGET -O - https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt |
  sed -e 's/<[^<>]*>//g' -e 's/#.*//' -e 's/^\s*//' -e 's/\b0*\B//g' |
  grep -v -E '\s[1-2]$' |
  awk '{print $1}' |
  grep '\S' >> $HOSTS

# Daily entries from Scam Analytics
echo >> $HOSTS
echo \# https://scamalytics.com/ip >> $HOSTS
$WGET -O - https://scamalytics.com/ip  |
  grep -o '>\s*\([0-9]\+\.\)\{3\}[0-9]\+\s*<' |
  tr -cd '[0-9\.\n]' >> $HOSTS

# WARNING: Because each line has IP addresses, which are not strictly numbers,
# sort -un does NOT work. Therefore: Either use sort -n | sort -u
# Or, sort -uV
if [ -x $IPRANGE ]
then
  sed -e 's/#.*//' -e 's/\s*//g' $HOSTS | grep '\S' | sort -uV | $IPRANGE --optimize - > $HOSTS.opt
  HOSTSFILE=$HOSTS.opt
else
  sed -e 's/#.*//' -e 's/\s*//g' $HOSTS | grep '\S' | sort -uV > $HOSTS.unopt
  echo WARNING: $IPRANGE missing, will use unoptimized hosts
  HOSTSFILE=$HOSTS.unopt
fi

# Check if we have any hosts to block
if ! [ -f $HOSTSFILE -a -s $HOSTSFILE ]
then
  echo $0: $HOSTSFILE is empty or missing, aborting
  exit 6
fi

# Generate blacklist of bad hosts, i.e. ipset rules
echo flush $IPSETNAME.tmp > $RESTORE

while read ip
do
  echo add $IPSETNAME.tmp $ip
done < $HOSTSFILE >> $RESTORE

echo swap $IPSETNAME $IPSETNAME.tmp >> $RESTORE
echo destroy $IPSETNAME.tmp >> $RESTORE
gzip $RESTORE
