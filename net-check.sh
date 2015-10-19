#!/bin/bash
##################################################
# Name: net-check.sh
# Desc: A performance analysis and suggestion tool for faster linux networking.
# The goal of this script is to clearly identify and explain each tunable for networking performance.
# Date: 17/10/2015
# Author: Michael Jones <mj@mikejonesey.co.uk>
# Licence: GNU LGPL V3
##################################################
# References, info sources and thanks:
# Stephen Hemminger, Bufferbloat, Linuxcon 2015
# Alessandro Selli, Traffic Control, Linuxcon 2015
# man pages: tcp, tcpdump, netstat
# docs: kernel, systemtap
# Documentation/networking/ip-sysctl.txt (/proc/sys/net/ipv4/* Variables)
# Documentation/networking/ixgb.txt (Linux Base Driver for 10 Gigabit Intel(R) Ethernet Network Connection)
# Documentation/networking/cxgb.txt (Chelsio N210 10Gb Ethernet Network Controller)
# Documentation/sysctl/net.txt (Documentation for /proc/sys/net/*)
# http://www.acc.umu.se/~maswan/linux-netperf.txt
# http://www.bufferbloat.net/projects/codel/wiki
# http://www.linuxfoundation.org/collaborate/workgroups/networking/netem
# http://luxik.cdi.cz/~devik/qos/htb/manual/theory.htm
# https://www.frozentux.net/ipsysctl-tutorial/chunkyhtml/tcpvariables.html
# http://web.archive.org/web/20150214142136/https://www.frozentux.net/ipsysctl-tutorial/chunkyhtml/tcpvariables.html (for images / graphs)
# https://www.frozentux.net/ipsysctl-tutorial/chunkyhtml/otherresources.html
# https://fasterdata.es.net/host-tuning/linux/
# http://www.psc.edu/index.php/networking/641-tcp-tune
# https://gettys.wordpress.com/2010/12/03/introducing-the-criminal-mastermind-bufferbloat/
# http://www.psc.edu/index.php/networking/641-tcp-tune#Linux
# https://tools.ietf.org/html/rfc1337
# http://www.isi.edu/touch/pubs/infocomm99/infocomm99-web/
#

NICS=($(ls -1 /sys/class/net/))
# a remote host for ping, rtt calc
REMOTE_TEST_HOST=""
# If no remote test host is specified, check for file with value
if [ -z "$REMOTE_TEST_HOST" ]; then
	if [ -f "vars/REMOTE_TEST_HOST" ]; then
		#file in .gitignore (custom value)
		REMOTE_TEST_HOST=$(cat "vars/REMOTE_TEST_HOST")
	else
		#no custom value specified, use gw for testing
		GW=$(route -n | awk '{print $2}' | tail -n +3 | grep -v ^0 | head -1)
	fi
fi

function printText(){
	if [ "$1" == "inf" ]; then
		#info
		printf "\e[0;33m"
	elif [ "$1" == "atn" ]; then
		#attention
		printf "\e[1;33m"
	elif [ "$1" == "pro" ]; then
		#property
		printf "\e[0;32m"
	elif [ "$1" == "val" ]; then
		#value
		printf "\e[0;36m"
	elif [ "$1" == "err" ]; then
		#error
		printf "\e[0;31m"
	fi
	while read aline; do echo $aline; done
	echo -ne "\e[0m"
}

function title(){
	clear
	echo "##################################################"
	echo "# $1..."
	echo "##################################################"
}

function kernelCheck(){
	curKern=($(uname -r | sed 's/-.*//; s/\./ /g'))
	parsedKern=($(echo "$1" | sed 's/-.*//; s/\./ /g'))
	if [ "${curKern[0]}" -gt "${parsedKern[0]}" ]; then
		# Kerner Greater
		return 0
	elif [ "${curKern[0]}" -ge "${parsedKern[0]}" -a "${curKern[1]}" -gt "${parsedKern[1]}" ]; then
		# Major Version Greater
		return 0
	elif [ "${curKern[0]}" -ge "${parsedKern[0]}" -a "${curKern[1]}" -ge "${parsedKern[1]}" -a "${curKern[2]}" -ge "${parsedKern[2]}" ]; then
		# Minor Version Greater
		return 0
	else
		return 1
	fi
}

function gigECheck(){
	#todo, something better than ethtool for this, (gig wireless won't be picked up...)
	if [ -n "$1" ]; then
		if [ -n "$(ethtool "$1" 2>/dev/null | grep 1000base)" ]; then
			return 0
		else
			return 1
		fi
	else
		for NIC in ${NICS[@]}; do
			if [ -n "$(ethtool "$NIC" 2>/dev/null | grep 1000base)" ]; then
				return 0
			fi
		done
		return 1
	fi
}

function L100Check(){
	if [ -n "$1" ]; then
		if [ -n "$(ethtool "$1" 2>/dev/null | grep 100base)" ]; then
			return 0
		else
			return 1
		fi
	else
		for NIC in ${NICS[@]}; do
			if [ -n "$(ethtool "$NIC" 2>/dev/null | grep 100base)" ]; then
				return 0
			fi
		done
		return 1
	fi
}

##################################################
# Net check...
##################################################
# check various networking stats to find issues...

function netCheck(){
	title "Checking Network..."
	which tcpdump &>/dev/null
	if [ "$?" != "0" ]; then
		echo "Please install tcpdump, or export PATH"
	else
		# Quick overview of packets, fails, re-trans
		netstat -i | column -t
		echo

		bInterface=$(ifconfig | sed 's/^$/~/' | tr "\n" "_" | sed 's/~/\n/g; s/_//g' | grep "RX" | sed 's/ .*RX bytes:/ /; s/ (.*//' | sort -k2 -n | tail -1 | awk '{print $1}')

		echo "Checking for services causing packet resend (10 Secs)"
		# check for remote services causing issues / RST
		tcpinfo=$(timeout 10 tcpdump -i$bInterface -n -v 'tcp[tcpflags] & (tcp-rst) != 0' 2>&1 | grep -v ^$)
		if [ -n "$(echo "$tcpinfo" | grep -v " packets " | grep -v "^tcpdump:")" ]; then
			echo "$tcpinfo"
		else
			echo "No issues found"
		fi
		echo

		echo "Checking if the recieve que is filling up..."
		# check for recv queue filling up...
		netc1=$(netstat -anpA inet 2>/dev/null | sort -k2 -n | tail -10 | expand | egrep -v "(tcp|udp)[ ]*0")
		if [ -n "$netc1" ]; then
			echo "$netc1"
		else
			echo "No issues found"
		fi
		echo

		echo "Checking if the send queue is filling up..."
		# check for send queue filling up...
		netc1=$(netstat -anpA inet 2>/dev/null | sort -k3 -n | tail -10 | expand | egrep -v "(tcp|udp)[ ]*[0-9]*[ ]*0")
		if [ -n "$netc1" ]; then
			echo "$netc1"
		else
			echo "No issues found"
		fi
		echo

		#test for high rate of segments retransmited

	fi

	read -p "Press enter to continue..."
}

function sizeMatters(){
##################################################
# Sizes...
##################################################

title "Sizes..."

##################################################
# INTRO
##################################################

# /proc/sys/net/core/optmem_max
# frozentux stated tcp_mem and tcp_wmem can be finetuned but tcp_rmem should be autotuned by OS.
# autotuning does apply to tcp_rmem, so this makes sense, but;
# 80% of websites seem to say tcp_mem should be autotuned fine by the OS.
# fasterdata.es.net wrote tcp_mem and optmem_max should be autotuned by OS.

# "Logical" thinking:
# the OS knows how much memory you have availible and can allocate pretty good values for tcp_mem (this could be tuned further, but should be pretty good as is).
# the OS does not know what applications or usage you will be applying (volume vs 
# in short;
# (userspace vs networking), i'd expect autotuned by OS.
# tcp (size vs quantity) i'd expect some tweeking even if the OS does pretty good guessing.
# therefore i'd expect tcp_mem to be fine, but tcp_rmem and tcp_wmem to need a small amount of tweeeking.

# tcp autotuning was introduced in linux 2.6.6 and 2.4.16 (this adjusts the tcp_rmem and default dynamically, up to the defined max).
# eg; /proc/sys/net/ipv4/tcp_rmem [MIN] [AUTO] [MAX]; the min and max can still be tweeked, but the kernel should adjust the default automagically.
# autotuning does not apply to rmem_default or wmem_default, these should still be set to the preffered buffer size.
# to check if autotuning is switched on check: /proc/sys/net/ipv4/tcp_moderate_rcvbuf

PAGE_SIZE=$(getconf PAGESIZE)

##################################################
# BUFFER SIZE
##################################################
# a smaller buffer means slower rate of data sent
# an oversized buffer will cause applications to misbehave.
# I would stick with 16MB or 32MB

# 16MB for the norm gigE
SOC_BUF_SIZE="16777216"

# 32 MB for host with a 10G NIC
#SOC_BUF_SIZE="33554432"

# 64 MB for host with a 10G/40G NIC
#SOC_BUF_SIZE="67108864"

# 128 MB for host with a 40G NIC
#SOC_BUF_SIZE="134217728"

##################################################
# AUTO TUNING
##################################################

# If set, TCP performs receive buffer auto-tuning, attempting to
# automatically size the buffer (no greater than tcp_rmem[2]) to
# match the size required by the path for full throughput.  Enabled by
# default.
TCP_RMEM_AUTO=$(cat /proc/sys/net/ipv4/tcp_moderate_rcvbuf 2>/dev/null)

##################################################
# tcp_adv_win_scale
##################################################
# This variable is used to tell the kernel how much of the socket buffer space should be used for TCP window size, and how much to save for an application buffer.
# If tcp_adv_win_scale is negative, the following equation is used to calculate the buffer overhead for window scaling: 
# bytes - (bytes/2^-tcp_adv_win_scale)
# Where bytes are the amount of bytes in the window. If the tcp_adv_win_scale value is positive, the following equation is used to calculate the buffer overhead: 
# bytes / 2^tcp_adv_win_scale
# The tcp_adv_win_scale variable takes an integer value and is per default set to 2. 
# This in turn means that the application buffer is 1/4th of the total buffer space specified in the tcp_rmem variable.
tcp_adv_win_scale=$(cat /proc/sys/net/ipv4/tcp_adv_win_scale)

# speed math...
# divide window by latency
# (tcp_adv_win_scale default is 2)
# (window/2^tcp_adv_win_scale)/0.150 = ...
# (87380 - 87380/2^2)/0.150 = 436906 bytes/s, or about 400 kbyte/s
# (873800 - 873800/2^2)/0.150 = 4369000 bytes/s, or about 4Mbytes/s

# This will enusre that immediatly subsequent connections use these values (set to 1 to enable)
#echo "/proc/sys/net/ipv4/route/flush"
#cat /proc/sys/net/ipv4/route/flush

# each driver sets it's own tx_ring, rx_ring
# application can set SO_SNDBUF and SO_RCVBUF

#man 7 socket
# rmem_default = default size of receive buffers used by sockets (bytes)
# wmem_default = default size of send buffers used by sockets (bytes)

echo "Default UNIX recieve buffer size: " | printText inf
if [ "$TCP_RMEM_AUTO" == "1" ]; then
	echo -e "/proc/sys/net/core/rmem_default \e[1;32m(auto)" | printText pro
else
	echo "/proc/sys/net/core/rmem_default" | printText pro
fi
cat /proc/sys/net/core/rmem_default | printText val
echo

echo "Default UNIX send buffer size: " | printText inf
if [ "$TCP_RMEM_AUTO" == "1" ]; then
	echo -e "/proc/sys/net/core/wmem_default \e[1;32m(auto)" | printText pro
else
	echo "/proc/sys/net/core/wmem_default" | printText pro
fi
cat /proc/sys/net/core/wmem_default | printText val
echo

##################################################
# Socket Buffer Size (bytes)
##################################################
#This sets the max OS receive buffer size for all types of connections.
echo "Maxiumum receive buffer size for all connections: " | printText inf
echo "/proc/sys/net/core/rmem_max" | printText pro
cat /proc/sys/net/core/rmem_max | printText val
if [ "$(cat /proc/sys/net/core/rmem_max)" != "$SOC_BUF_SIZE" ]; then
	read -p "Set rmem_max to the custom socket buffer size of $SOC_BUF_SIZE? (y/n) [n] "
	if [ "$REPLY" == "y" ]; then
		sed -i "s/^\(net.core.rmem_max.*\)/#$(date +"%Y%m%d")#\1/" /etc/sysctl.conf
		sysctl -w net.core.rmem_max=$SOC_BUF_SIZE >> /etc/sysctl.conf
		if [ "$TCP_RMEM_AUTO" == "1" ]; then
			echo "setsockopt() disables autotuning, don't use it."
			echo "Restart applications like apache, unset ReceiveBufferSize if the setting has been customised."
			echo "In custom applications unset the SO_RCVBUF"
		else
			echo "setsockopt() enables utilising the full buffer."
			echo "Restart applications like apache, if SendBufferSize has not been customised it will get the new value."
			echo "In custom applications set the SO_RCVBUF to the same value."
		fi
	fi
fi
echo

##################################################
# Socket Recieve Size (bytes)
##################################################
#This sets the max OS send buffer size for all types of connections.
echo "Maxiumum receive buffer size for all connections: " | printText inf
echo "/proc/sys/net/core/wmem_max" | printText pro
cat /proc/sys/net/core/wmem_max | printText val
if [ "$(cat /proc/sys/net/core/wmem_max)" != "$SOC_BUF_SIZE" ]; then
	read -p "Set wmem_max to the custom socket buffer size of $SOC_BUF_SIZE? (y/n) [n] "
	if [ "$REPLY" == "y" ]; then
		sed -i "s/^\(net.core.wmem_max.*\)/#$(date +"%Y%m%d")#\1/" /etc/sysctl.conf
		sysctl -w net.core.wmem_max=$SOC_BUF_SIZE >> /etc/sysctl.conf
		if [ "$TCP_RMEM_AUTO" == "1" ]; then
			echo "setsockopt() disables autotuning, don't use it."
			echo "Restart applications like apache, unset ReceiveBufferSize if the setting has been customised."
			echo "In custom applications unset the SO_RCVBUF"
		else
			echo "Restart applications like apache, if SendBufferSize has not been customised it will get the new value."
			echo "In custom applications set the SO_SNDBUF to the same value."
		fi
	fi
fi
echo

##################################################
# TCP_MEM
##################################################
#The tcp_mem variable defines how the TCP stack should behave when it comes to memory usage. 
# The values must be specified in pages sizes of (4k)

# low		TCP doesn't regulate its memory allocation when the number of pages it has allocated globally is below this number.
# pressure  When the amount of memory allocated by TCP exceeds this number of pages, TCP moderates its memory consumption.  This memory pressure state
#			is exited once the number of pages allocated falls below the low mark.
# high		The maximum number of pages, globally, that TCP will allocate.  This value overrides any other limits imposed by the kernel.

# If you go up above the middle value of net/ipv4/tcp_mem, you enter 
# tcp_memory_pressure, which means that new tcp windows won't grow until 
# you have gotten back under the pressure value. Allowing bigger windows means
# that it takes fewer connections for someone evil to make the rest of the
# tcp streams to go slow.

echo "Maxiumum RAM for TCP: " | printText inf
echo "/proc/sys/net/ipv4/tcp_mem [p] [p] [p]" | printText pro
TCP_MEM=($(cat /proc/sys/net/ipv4/tcp_mem))
#.. calc current load...
#.. calc max
#.. calc middle
#.. display options (WITH WARNING, increase ram over prop)...
cat /proc/sys/net/ipv4/tcp_mem | printText val
echo

##################################################
# TCP_RMEM
##################################################
echo "[b]1 minimum receive buffer for each TCP connection, this buffer is always allocated to a TCP socket, even under high pressure on the system." | printText inf
# With autotuning, leave at default, (optimal for typical small flows). large default buffer waste memory and can hurt performance.
echo "[b]2 default receive buffer allocated for each TCP socket. This value overrides the net.core.rmem_default value used by other protocols." | printText inf
echo "[b]3 maximal size of receive buffer allowed (net.core.rmem_max and setsockopt (SO_RCVBUF) overrides)" | printText inf
TCP_RMEM=($(cat /proc/sys/net/ipv4/tcp_rmem))
if [[ -f "/proc/sys/net/ipv4/tcp_moderate_rcvbuf" && "$TCP_RMEM_AUTO" == "1" ]]; then
	echo -e "/proc/sys/net/ipv4/tcp_rmem [(8192)] \e[1;32m[(87380) (auto)]\e[0;32m [(87380 and 4194304)]\e[0m" | printText pro
else
	echo "/proc/sys/net/ipv4/tcp_rmem [b] [b] [b]" | printText pro
fi
cat /proc/sys/net/ipv4/tcp_rmem | printText val
if [ ! -f "/proc/sys/net/ipv4/tcp_moderate_rcvbuf" ]; then
	echo "Time to upgrade your kernel..."
elif [ "$TCP_RMEM_AUTO" == "0" ]; then
	echo "Set to auto..."
	echo "/proc/sys/net/ipv4/tcp_moderate_rcvbuf" | printText pro
	cat /proc/sys/net/ipv4/tcp_moderate_rcvbuf | printText err
fi
echo

##################################################
# TCP_WMEM
##################################################
echo "[b]1 minimum TCP send buffer space available for a single TCP socket" | printText inf
echo "[b]2 default buffer space allowed for a single TCP socket to use." | printText inf
echo "[b]3 the maximum TCP send buffer space. (net.core.wmem_max and setsockopt () overrides)" | printText inf
echo "/proc/sys/net/ipv4/tcp_wmem [(4096B)] [(16384)] [(65536 and 4194304)]" | printText pro
cat /proc/sys/net/ipv4/tcp_wmem | printText val
echo

# Maximum backlog size
# Sets the maximum number of packets allowed to queue when a particular interface receives packets faster than the kernel can process them.
# The default value for this file is 300 in older kernels and 1000 in newer kernels.
echo "Maximum backlog size (packets)" | printText inf
echo "/proc/sys/net/core/netdev_max_backlog" | printText pro
cat /proc/sys/net/core/netdev_max_backlog | printText val
echo

##################################################
# OTHER
##################################################
if [ "$(cat /proc/sys/net/ipv4/tcp_timestamps)" == "1" ]; then
	echo "Save CPU, switch off tcp timestamps" | printText inf
	echo "/proc/sys/net/ipv4/tcp_timestamps" | printText pro
	cat /proc/sys/net/ipv4/tcp_timestamps | printText val
	read -p "Switch off tcp_timestamps? (y/n) [n] "
	if [ "$REPLY" == "y" ]; then
		sed -i "s/^\(net.ipv4.tcp_timestamps.*\)/#$(date +"%Y%m%d")#\1/" /etc/sysctl.conf
		sysctl -w net.ipv4.tcp_timestamps=0 >> /etc/sysctl.conf
	fi
	echo
fi

if [ "$(cat /proc/sys/net/ipv4/tcp_sack)" == "1" ]; then
	echo "Enable/Disable select acknowledgments (SACKS), good for fast bus -> memory interface systems." | printText inf
	echo "/proc/sys/net/ipv4/tcp_sack" | printText pro
	cat /proc/sys/net/ipv4/tcp_sack | printText val
	read -p "Switch off tcp_sack? (y/n) [n] "
	if [ "$REPLY" == "y" ]; then
		sed -i "s/^\(net.ipv4.tcp_sack.*\)/#$(date +"%Y%m%d")#\1/" /etc/sysctl.conf
		sysctl -w net.ipv4.tcp_sack=0 >> /etc/sysctl.conf
	fi
	echo
fi

# TIME-WAIT is always 60 secs, unless higher jiffies.
# include/net/tcp.h
# #define TCP_TIMEWAIT_LEN (60*HZ) /* how long to wait to destroy TIME-WAIT
#                                  * state, about 60 seconds     */

#10,000 new connections per second = 600,000 sockets in the TIME-WAIT state

# gdb /usr/lib/debug/boot/vmlinux-$(uname -r)
#...
#(gdb) print sizeof(struct tcp_timewait_sock)
#$1 = 192
#(gdb) print sizeof(struct tcp_sock)
#$2 = 1784
#(gdb) print sizeof(struct inet_bind_bucket)
#$3 = 48

#tcp_rfc1337
# Docs:
# 	If set, the TCP stack behaves conforming to RFC1337. If unset,
# 	we are not conforming to RFC, but prevent TCP TIME_WAIT
# 	assassination.
#
# In short TIME_WAIT assasination is a good thing, as it enables the
# re-use of the same source port imediatley after it has been gracefully closed
#
# as far as I can tell the only reason the default is off, is becuase
# the implemented solution is not a complete solution.
#
# TIME-WAIT disrupts a clean TCP flow, uses up ports,
# open more ports by using port ranges, additional ips...
# ignore RST segments in the TIME-WAIT state
# set to 1
if [ "$(cat /proc/sys/net/ipv4/tcp_rfc1337)" == "0" ]; then
	echo "Enable tcp_rfc1337 for re-use of ports" | printText inf
	echo "/proc/sys/net/ipv4/tcp_rfc1337" | printText pro
	cat /proc/sys/net/ipv4/tcp_rfc1337 | printText val
	read -p "Enable tcp_rfc1337? (y/n) [n] "
	if [ "$REPLY" == "y" ]; then
		sed -i "s/^\(net.ipv4.tcp_rfc1337.*\)/#$(date +"%Y%m%d")#\1/" /etc/sysctl.conf
		sysctl -w net.ipv4.tcp_rfc1337=1 >> /etc/sysctl.conf
	fi
	echo
fi

#tcp_retries1
# unacknowledged RTO retransmissions
# set to 3 (default), also RFC 1122 reccomends 3+
if [ "$(cat /proc/sys/net/ipv4/tcp_retries1)" != "3" ]; then
	echo "Set tcp_retries1 to 3" | printText inf
	echo "/proc/sys/net/ipv4/tcp_retries1" | printText pro
	cat /proc/sys/net/ipv4/tcp_retries1 | printText val
	read -p "Set tcp_retries1 to 3? (y/n) [n] "
	if [ "$REPLY" == "y" ]; then
		sed -i "s/^\(net.ipv4.tcp_retries1.*\)/#$(date +"%Y%m%d")#\1/" /etc/sysctl.conf
		sysctl -w net.ipv4.tcp_retries1=3 >> /etc/sysctl.conf
	fi
	echo
fi

#tcp_retries2
# This value influences the timeout of an alive TCP connection,
# when RTO retransmissions remain unacknowledged.
# Given a value of N, a hypothetical TCP connection following
# exponential backoff with an initial RTO of TCP_RTO_MIN would
# retransmit N times before killing the connection at the (N+1)th RTO.
#
# The default value of 15 yields a hypothetical timeout of 924.6
# seconds and is a lower bound for the effective timeout.
# TCP will effectively time out at the first RTO which exceeds the
# hypothetical timeout.
#
# RFC 1122 recommends at least 100 seconds for the timeout,
# which corresponds to a value of at least 8.
# option 6 for lb or apache, 8 for other
if [ "$(cat /proc/sys/net/ipv4/tcp_retries2)" != "6" -a "$(cat /proc/sys/net/ipv4/tcp_retries2)" != "8" ]; then
	echo "Configure tcp_retries2" | printText inf
	echo "/proc/sys/net/ipv4/tcp_retries2" | printText pro
	cat /proc/sys/net/ipv4/tcp_retries2 | printText val
	echo "1. 6 (for lb or public facing ha/nginx)"
	echo "2. 8 (for all other)"
	echo "3. s (skip)"
	read -p "Set tcp_retries2 (1/2/s) [s] "
	if [ "$REPLY" == "1" ]; then
		sed -i "s/^\(net.ipv4.tcp_retries2.*\)/#$(date +"%Y%m%d")#\1/" /etc/sysctl.conf
		sysctl -w net.ipv4.tcp_retries2=6 >> /etc/sysctl.conf
	elif [ "$REPLY" == "2" ]; then
		sed -i "s/^\(net.ipv4.tcp_retries2.*\)/#$(date +"%Y%m%d")#\1/" /etc/sysctl.conf
		sysctl -w net.ipv4.tcp_retries2=8 >> /etc/sysctl.conf
	fi
	echo
fi

#tcp_synack_retries
# Number of times SYNACKs for a passive TCP connection attempt will
# be retransmitted. Should not be higher than 255. Default value
# is 5, which corresponds to 31seconds till the last retransmission
# with the current initial RTO of 1second. With this the final timeout
# for a passive TCP connection will happen after 63seconds.
# set to 5 if not between 1 and 255
if [ "$(cat /proc/sys/net/ipv4/tcp_synack_retries)" -lt "1" -o "$(cat /proc/sys/net/ipv4/tcp_synack_retries)" -gt "255" ]; then
	echo "Set tcp_synack_retries to 5" | printText inf
	echo "/proc/sys/net/ipv4/tcp_synack_retries" | printText pro
	cat /proc/sys/net/ipv4/tcp_synack_retries | printText val
	read -p "Set tcp_synack_retries to 5? (y/n) [n] "
	if [ "$REPLY" == "y" ]; then
		sed -i "s/^\(net.ipv4.tcp_synack_retries.*\)/#$(date +"%Y%m%d")#\1/" /etc/sysctl.conf
		sysctl -w net.ipv4.tcp_synack_retries=5 >> /etc/sysctl.conf
	fi
	echo
fi

#tcp_syn_retries
# set to 6 if outside of 1 and 255
if [ "$(cat /proc/sys/net/ipv4/tcp_syn_retries)" -lt "1" -o "$(cat /proc/sys/net/ipv4/tcp_syn_retries)" -gt "255" ]; then
	echo "Set tcp_syn_retries to 6" | printText inf
	echo "/proc/sys/net/ipv4/tcp_syn_retries" | printText pro
	cat /proc/sys/net/ipv4/tcp_syn_retries | printText val
	read -p "Set tcp_syn_retries to 6? (y/n) [n] "
	if [ "$REPLY" == "y" ]; then
		sed -i "s/^\(net.ipv4.tcp_syn_retries.*\)/#$(date +"%Y%m%d")#\1/" /etc/sysctl.conf
		sysctl -w net.ipv4.tcp_syn_retries=6 >> /etc/sysctl.conf
	fi
	echo
fi

#netdev_max_backlog
# This value should be low, if the kernel is too slow it needs to throw away packets rather than block the nic
# Maximum number  of  packets,  queued  on  the  INPUT  side, when the interface
# receives packets faster than kernel can process them.
# set to 2000 if greater (even this is 3s)
if [ "$(cat /proc/sys/net/core/netdev_max_backlog)" -gt "2000" ]; then
	echo "Reduce netdev_max_backlog" | printText inf
	echo "/proc/sys/net/core/netdev_max_backlog" | printText pro
	cat /proc/sys/net/core/netdev_max_backlog | printText val
	read -p "Set netdev_max_backlog to 2000? (y/n) [n] "
	if [ "$REPLY" == "y" ]; then
		sed -i "s/^\(net.core.netdev_max_backlog.*\)/#$(date +"%Y%m%d")#\1/" /etc/sysctl.conf
		sysctl -w net.core.netdev_max_backlog=2000 >> /etc/sysctl.conf
	fi
	echo
fi

#somaxconn
# how many connections can be left open for pending applications...
# defaults to 128, SOMAXCONN
# Limit of socket listen() backlog
# should be < apache/haproxy max client/listen queue, otherwise the system will disable SYN cookies
# set to 128 (if smaller and ram > 1G), or warn if greater than 1024
if [ "$(cat /proc/sys/net/core/somaxconn)" -lt "128" ]; then
	echo "Increase somaxconn" | printText inf
	echo "/proc/sys/net/core/somaxconn" | printText pro
	cat /proc/sys/net/core/somaxconn | printText val
	read -p "Set somaxconn to 128? (y/n) [n] "
	if [ "$REPLY" == "y" ]; then
		sed -i "s/^\(net.core.somaxconn.*\)/#$(date +"%Y%m%d")#\1/" /etc/sysctl.conf
		sysctl -w net.core.somaxconn=128 >> /etc/sysctl.conf
	fi
	echo
elif [ "$(cat /proc/sys/net/core/somaxconn)" -gt "1024" ]; then
	echo "Posibly decrease somaxconn" | printText inf
	echo "/proc/sys/net/core/somaxconn" | printText pro
	cat /proc/sys/net/core/somaxconn | printText val
	echo "Never set somaxconn > application concurrent connections"
	echo "If set higher the system will disable SYN cookies"
	echo
fi

#tcp_max_syn_backlog
# used when an application is non responsive
# goal is to queue packets for an overloaded software application
# mininum value of 128 (low memory machines)
# max grows with memory (rough guess 128+(128*8Gtotal ram), but can be increased further)
# If server suffers from overload, try increasing this number.
# set to 256 if lower
if [ "$(cat /proc/sys/net/ipv4/tcp_max_syn_backlog)" -gt "2000" ]; then
	echo "Increase tcp_max_syn_backlog" | printText inf
	echo "/proc/sys/net/ipv4/tcp_max_syn_backlog" | printText pro
	cat /proc/sys/net/ipv4/tcp_max_syn_backlog | printText val
	read -p "Set tcp_max_syn_backlog to 256? (y/n) [n] "
	if [ "$REPLY" == "y" ]; then
		sed -i "s/^\(net.ipv4.tcp_max_syn_backlog.*\)/#$(date +"%Y%m%d")#\1/" /etc/sysctl.conf
		sysctl -w net.ipv4.tcp_max_syn_backlog=256 >> /etc/sysctl.conf
	fi
	echo
fi

#tcp_tw_recycle
# reuse a TIME-WAIT connection for an incoming or outgoing connection
# difficult to detect and difficult to diagnose problems
# set to 0 (when enabled can give some unwanted side-effects)
# see tcp(7)
# when enabled it won't handle connections from two different computers behind the same NAT.
# (the two computers don't share a timestamp clock, one connection per minute)
# this should only ever be enabled in backend systems (2nd - 3rd tier or non www facing).
# for www facing ha or nginx, concider disabling socket lingering instead.
if [ "$(cat /proc/sys/net/ipv4/tcp_tw_recycle)" != "0" ]; then
	echo "tcp_tw_recycle should only be used on non public facing servers" | printText inf
	echo "/proc/sys/net/ipv4/tcp_tw_recycle" | printText pro
	cat /proc/sys/net/ipv4/tcp_tw_recycle | printText val
	read -p "Disable tcp_tw_recycle? (y/n) [n] "
	if [ "$REPLY" == "y" ]; then
		sed -i "s/^\(net.ipv4.tcp_tw_recycle.*\)/#$(date +"%Y%m%d")#\1/" /etc/sysctl.conf
		sysctl -w net.ipv4.tcp_tw_recycle=0 >> /etc/sysctl.conf
	fi
	echo
fi

#tcp_tw_reuse
# reuse a TIME-WAIT connection for an outgoing connection
# (not much use for incoming connections)
# set to 0 (but message that it can be 1 on an lb or high load apache)
# see RCF1323 - two four-byte timestamp fields
# The first one is the current value of the timestamp clock of the TCP sending the option
# The second one is the most recent timestamp received from the remote host.
# TWRecycled counter will be increased (no reuse counter)

#tcp_keepalive_time
# default, every 2hours
# how often a tcp keep alive message is sent out
# 7200 > 1200 (if default, set)
# a lower value will help clear the overall number of connections by ensuring valid connection are kept open.
# a higher value will in general use less cpu
if [ "$(cat /proc/sys/net/ipv4/tcp_keepalive_time)" -gt "1200" ]; then
	echo "Decrease tcp_keepalive_time to send more keep alive messages" | printText inf
	echo "/proc/sys/net/ipv4/tcp_keepalive_time" | printText pro
	cat /proc/sys/net/ipv4/tcp_keepalive_time | printText val
	read -p "Decrease tcp_keepalive_time to 1200? (y/n) [n] "
	if [ "$REPLY" == "y" ]; then
		sed -i "s/^\(net.ipv4.tcp_keepalive_time.*\)/#$(date +"%Y%m%d")#\1/" /etc/sysctl.conf
		sysctl -w net.ipv4.tcp_keepalive_time=1200 >> /etc/sysctl.conf
	fi
	echo
fi

#tcp_fin_timeout
# how long to leave expired tcp connections in FIN_WAIT_2
# default 60 secs
# While a perfectly valid "receive only" state for an 
# un-orphaned connection, an orphaned connection in FIN_WAIT_2 state could otherwise wait
# forever for the remote to close its end of the connection.
# set to 20, common applications don't have recieve only tcp connections.
if [ "$(cat /proc/sys/net/ipv4/tcp_fin_timeout)" -gt "20" ]; then
	echo "Decrease tcp_fin_timeout to kill off FIN_WAIT_2 connection faster" | printText inf
	echo "/proc/sys/net/ipv4/tcp_fin_timeout" | printText pro
	cat /proc/sys/net/ipv4/tcp_fin_timeout | printText val
	read -p "Decrease tcp_fin_timeout to 20? (y/n) [n] "
	if [ "$REPLY" == "y" ]; then
		sed -i "s/^\(net.ipv4.tcp_fin_timeout.*\)/#$(date +"%Y%m%d")#\1/" /etc/sysctl.conf
		sysctl -w net.ipv4.tcp_fin_timeout=20 >> /etc/sysctl.conf
	fi
	echo
fi

#tcp_max_orphans
#each orphan eats up to ~64K of unswappable memory
# calc on ram
# protect from dos, on internal systems this value can be lowered to around 10000
# on www systems increase the value to match ram, to the tone of 30000 per 8G ram
# (cleaning these consumes cpu, leaving them consumes ram).

#tcp_no_metrics_save
# set to 0, metrics are useful, only disable if tcp performance degrades over time and test.
if [ "$(cat /proc/sys/net/ipv4/tcp_no_metrics_save)" != "0" ]; then
	echo "Disable tcp_no_metrics_save to use tcp metrics, only disable if tcp perf degrades over time." | printText inf
	echo "/proc/sys/net/ipv4/tcp_no_metrics_save" | printText pro
	cat /proc/sys/net/ipv4/tcp_no_metrics_save | printText val
	read -p "Disable tcp_no_metrics_save? (y/n) [n] "
	if [ "$REPLY" == "y" ]; then
		sed -i "s/^\(net.ipv4.tcp_no_metrics_save.*\)/#$(date +"%Y%m%d")#\1/" /etc/sysctl.conf
		sysctl -w net.ipv4.tcp_no_metrics_save=0 >> /etc/sysctl.conf
	fi
	echo
fi

#tcp_orphan_retries
# influences the timeout of a locally closed TCP connection, when RTO retransmissions remain unacknowledged.
# see tcp_retries2
# defaults to 8, If your machine is a loaded WEB server,
# you should think about lowering this value, such sockets
# may consume significant resources. Cf. tcp_max_orphans.
# set to 3
# note 0 is a special case...
# tcp_timer.c
# 98 /* Calculate maximal number or retries on an orphaned socket. */
# 99 static int tcp_orphan_retries(struct sock *sk, int alive)
# 100 {
# 101         int retries = sysctl_tcp_orphan_retries; /* May be zero. */
# 102 
# 103         /* We know from an ICMP that something is wrong. */
# 104         if (sk->sk_err_soft && !alive)
# 105                 retries = 0;
# 106 
# 107         /* However, if socket sent something recently, select some safe
# 108          * number of retries. 8 corresponds to >100 seconds with minimal
# 109          * RTO of 200msec. */
# 110         if (retries == 0 && alive)
# 111                 retries = 8;
# 112         return retries;
# 113 }
# As a result for a totaly overloaded web/lb the optimum would be a value of 1
if [ "$(cat /proc/sys/net/ipv4/tcp_orphan_retries)" != "3" ]; then
	echo "Unacklowledged retransmissions have a heavy resource cost, reduce tcp_orphan_retries on loaded web servers." | printText inf
	echo "/proc/sys/net/ipv4/tcp_orphan_retries" | printText pro
	cat /proc/sys/net/ipv4/tcp_orphan_retries | printText val
	read -p "Decrease tcp_orphan_retries to 3? (y/n) [n] "
	if [ "$REPLY" == "y" ]; then
		sed -i "s/^\(net.ipv4.tcp_orphan_retries.*\)/#$(date +"%Y%m%d")#\1/" /etc/sysctl.conf
		sysctl -w net.ipv4.tcp_orphan_retries=3 >> /etc/sysctl.conf
	fi
	echo
fi

# netdev_budget
# how many packets to take in one go, NIC>BUF.
# ideally left at default unless box is readding alot of data.
# if network is 1GE 600
# default is 300
gigECheck
gigE="$?"
if [ "$gigE" == "0" ]; then
	netdev_budget="600"
else
	netdev_budget="300"
fi
if [ "$(cat /proc/sys/net/core/netdev_budget)" != "$netdev_budget" ]; then
	echo "How many packets should be taken in one go?" | printText inf
	echo "/proc/sys/net/core/netdev_budget" | printText pro
	cat /proc/sys/net/core/netdev_budget | printText val
	read -p "Decrease netdev_budget to $netdev_budget? (y/n) [n] "
	if [ "$REPLY" == "y" ]; then
		sed -i "s/^\(net.core.netdev_budget.*\)/#$(date +"%Y%m%d")#\1/" /etc/sysctl.conf
		sysctl -w net.core.netdev_budget=$netdev_budget >> /etc/sysctl.conf
	fi
	echo
fi
  
##################################################
# CALCS
##################################################
calc_max_tcp_no_pressure_bytes=$(echo "${TCP_MEM[1]}*$PAGE_SIZE" | bc)
calc_max_tcp_con_no_pressure=$(echo "scale=0; $calc_max_tcp_no_pressure_bytes/${TCP_RMEM[1]}" | bc)
calc_max_tcp_bytes=$(echo "${TCP_MEM[2]}*$PAGE_SIZE" | bc)
calc_max_tcp_con=$(echo "scale=0; $calc_max_tcp_bytes/${TCP_RMEM[0]}" | bc)
speed_guess=$(echo "scale=2; ((${TCP_RMEM[1]}-(${TCP_RMEM[1]}/2^$tcp_adv_win_scale))/0.150)/1000000" | bc)
speed_guess_mbps=$(echo "scale=2; $speed_guess*8" | bc)
slow_speed_guess=$(echo "scale=2; ((${TCP_RMEM[0]}-(${TCP_RMEM[0]}/2^$tcp_adv_win_scale))/0.150)/1000000" | bc)
slow_speed_guess_mbps=$(echo "scale=2; $slow_speed_guess*8" | bc)
ram_at_optimum_usage=$(echo "scale=2; $calc_max_tcp_no_pressure_bytes/1000000" | bc)
max_networking_ram=$(echo "scale=2; (${TCP_MEM[2]}*$PAGE_SIZE)/1000000" | bc)

echo "Max connections $calc_max_tcp_con_no_pressure with optimum throughput of $speed_guess Mbytes/s ($speed_guess_mbps Mbps)" | printText atn
echo "Pressure connections (Max: $calc_max_tcp_con) will be $slow_speed_guess Mbytes/s ($slow_speed_guess_mbps Mbps)" | printText atn
echo "RAM used by networking at optimum: $ram_at_optimum_usage MB" | printText atn
echo "Max RAM used by networking: $max_networking_ram MB" | printText atn
echo

#MTU=$(ip link list dev eth3 | head -1 | grep -o "mtu [0-9]*" | awk '{print $2}')
#RTT=$(echo "scale=4; "$(tc qdisc show dev eth3 | grep -o "target [0-9\.]*" | awk '{print $2}')"/1000" | bc)
#PING_RTT=$(ping -c 5 "$REMOTE_TEST_HOST" 2>&1 | grep -o "time=[0-9\.]*" | sed 's/time=//' | awk '{tot+=$1}END{print "scale=4; ("tot"/10)/1000"}' | bc)
#if [[ -n "$PING_RTT" && "$(echo "$RTT-$PING_RTT" | bc | grep -o "^.")" == "-" ]]; then
#	RTT="$PING_RTT"
#fi
#echo "RTT:$RTT"
#gigECheck
#if [ "$?" == "0" ]; then
#	#Gig eth 1000 (in bits)
#	LINERATE=1048576000
#else
#	L100Check
#	if [ "$?" == "0" ]; then
#		#100mbs (in bits)
#		LINERATE=104857600
#	else
#		#10mbs (in bits)
#		LINERATE=10485760
#	fi
#fi

#Throughput = TCPWindow / round-trip-delay = 65535 Bytes / .06 Sec = 1,092,250 Bytes/Sec
#THEORETICAL_THROUGHPUT=$(echo "scale=2; $MTU/$RTT/")

#(MSS/RTT)*(C/sqrt(Loss))10-08

#The TCP Window (RWIN) needs to be large enough to fit the
#BDP (bits) = total_available_bandwidth (bits/sec) x round_trip_time (sec)
#BDP=$(echo "scale=0; ($LINERATE*$RTT)/1" | bc)
#1024 data storage, 1000 data communication
#BDPK=$(echo "scale=2; $LINERATE*$RTT/1000" | bc)
#echo "Bandwidth Delay Product: $BDP bits ($BDPK Kbit)"

##################################################
# Notes
##################################################

# 10GIGE - setup 1
#net.ipv4.tcp_timestamps=0
#net.ipv4.tcp_sack=0
#net.core.rmem_max=1024000
#net.core.wmem_max=1024000
#net.core.rmem_default=524287
#net.core.wmem_default=524287
#net.core.optmem_max=524287
#net.core.netdev_max_backlog=300000
#net.ipv4.tcp_rmem="10000000 10000000 10000000"
#net.ipv4.tcp_wmem="10000000 10000000 10000000"
#net.ipv4.tcp_mem="10000000 10000000 10000000"

# 10GIGE - setup 2
# turn TCP timestamp support off, default 1, reduces CPU use
#net.ipv4.tcp_timestamps = 0
# turn SACK support off, default on
# on systems with a VERY fast bus -> memory interface this is the big gainer
#net.ipv4.tcp_sack = 0
# set min/default/max TCP read buffer, default 4096 87380 174760
#net.ipv4.tcp_rmem = 10000000 10000000 10000000
# set min/pressure/max TCP write buffer, default 4096 16384 131072
#net.ipv4.tcp_wmem = 10000000 10000000 10000000
# set min/pressure/max TCP buffer space, default 31744 32256 32768
#net.ipv4.tcp_mem = 10000000 10000000 10000000
### CORE settings (mostly for socket and UDP effect)
# set maximum receive socket buffer size, default 131071
#net.core.rmem_max = 524287
# set maximum send socket buffer size, default 131071
#net.core.wmem_max = 524287
# set default receive socket buffer size, default 65535
#net.core.rmem_default = 524287
# set default send socket buffer size, default 65535
#net.core.wmem_default = 524287
# set maximum amount of option memory buffers, default 10240
#net.core.optmem_max = 524287
# set number of unprocessed input packets before kernel starts dropping them; default 300
#net.core.netdev_max_backlog = 300000

# Que disciplines have their own buffers ontop of OS buffer

# Capacity of CPU to keep up with the flux (load, jiffies)

# Number of hops (switches, routers)...
read -p "Press enter to continue..."
}

function adjustNic(){
	title "Processing nic: $NIC"
##################################################
# Queueing Schedulers
##################################################
#- Classless
#+ Classful
# Classful qdiscs use one of three methods to classify packets:
# 1. Type of service / differeciated services
# 2. filters
# 3. SO_PRIORITY field (can be set by application setsoc...)

#- pfifo_fast : three band packet-FIFO (default classless qdisc)
#+ prio : priority queing discipline
#- pfifo : packet-limited FIFO
#- bfifo : byte-limited FIFO
#+ cbq : Class based queueing
#+ htb : Hierarchical Token Bucket (cbq replacement)
#+ tbf : Token Bucket Filter
#- red : Randon Early Detection
#- choke : Choose and Keep for (un)responsive flow
#+ codel : Controlled-Delay Active Queue Management
#+ drr : Deficit Round Tobin Scheduler
#- fq_codel : Fair Queuing (FQ) with controlled delay
#+ hfsc : Hierarchical Fair Service Curve
#+ mqprio : Multiqueue Priority Qdisc
#- sfb : Stochastic Fair Blue
#- sfq : Stochatic Fairness Queueing
#- stab : Generic size table manipulations
#+ mq : Muliqueue dummy scheduler, aka RSS (Receive Side Scaling)
#+ cake : Common Applications Kept Enhanced (enhanced htb, fq_codel)

echo "Default Queue Discipline" | printText inf
if [ -f "/proc/sys/net/core/default_qdisc" ]; then
	echo "/proc/sys/net/core/default_qdisc" | printText pro
	cat /proc/sys/net/core/default_qdisc | printText val
	if [ "$(cat /proc/sys/net/core/default_qdisc)" != "fq_codel" ]; then
		read -p "Would you like to set your default queue disciple to fq_codel? (y/n) [n] "
		if [ "$REPLY" == "y" ]; then
			sed -i "s/^\(net.core.default_qdisc =.*\)/#$(date +"%Y%m%d")#\1/" /etc/sysctl.conf
			sysctl -w net.core.default_qdisc=fq_codel >> /etc/sysctl.conf
		fi
	fi
else
	echo "Upgrade your kernel..." | printText val
fi
echo

# Que Filters
# ematch : Extended matches for use with "basic" or "flow" filters
# bpf : BPF programmable classifier and actions (NEW)
# 	cBPF : Classic Berkeley Packet Filter (actually runs eBPF)
#	eBPF : Extended Berkeley Packet Filter

# Default qdisc for dev
#Changing them
#voice, video, best effort and background
#tc qdisc replace dev $NIC root prio
echo "Queue discipline for $NIC" | printText inf
ip link list dev $NIC | head -1 | grep -o "qdisc [a-z_]*" | printText val
curqdisc=$(ip link list dev $NIC | head -1 | grep -o "qdisc [a-z_]*" | awk '{print $2}')
# check if eth or wifi
if [ -d "/sys/class/net/$NIC/phy80211" ]; then
	if [ "$curqdisc" != "mq" ]; then
		echo "Detected nic $NIC is wifi, preffered qdisc is mq, current qdisc is $curqdisc" | printText inf
		read -p "Set queue discipline to mq for $NIC? (y/n) [n] "
		if [ "$REPLY" == "y" ]; then
			#tc qdisc replace dev $NIC root mq
			# some firewalls block ecn, if the data is not to hit the net, remove noecn
			tc qdisc replace dev $NIC handle 1 root mq
			tc qdisc replace dev $NIC parent 1:1 fq_codel noecn
			tc qdisc replace dev $NIC parent 1:2 fq_codel
			tc qdisc replace dev $NIC parent 1:3 fq_codel
			tc qdisc replace dev $NIC parent 1:4 fq_codel noecn
		fi
	fi
else
	kernelCheck "3.1.0"
	if [ "$?" == "0" ]; then
		#todo, check for really big nextwork, (suggest sch_fq).
		if [ "$curqdisc" != "fq_codel" ]; then
			echo "Detected nic $NIC is ethernet" | printText inf
			read -p "Set queue discipline to fq_codel for $NIC? (y/n) [n] "
			if [ "$REPLY" == "y" ]; then
				tc qdisc replace dev $NIC root fq_codel
			fi
		fi
	else
		# Older kernel optimisation
		kernelCheck "2.4.26"
		if [ "$?" == "0" ]; then
		#If you are going to use HTB, edit linux/include/net/pkt_sched.h, changing PSCHED_JIFFIES to PSCHED_CPU.
		#If you want ultimate precision, edit linux/net/sched/sch_htb.c, changing HYSTERESIS from 1 to 0.  
		#Otherwise, HTB will dequeue packets in pairs (to improve response).
		#There is a serious bug in HTB before version 3.17, so use a kernel version 2.4.26 or newer.		
		echo "Preffered queue discipline is the Hierarchy Token Bucket" | printText inf
		echo "Upgrade kernel for better queueing" | printText inf
		# Set to
		if [ "$curqdisc" != "htb" ]; then
			echo "Detected nic $NIC is ethernet" | printText inf
			read -p "Set queue discipline to htb for $NIC? (y/n) [n] "
			if [ "$REPLY" == "y" ]; then
				# HTB will route all unclassified traffic (via a default que)
				echo "todo..." | printText val
				tc qdisc replace dev $NIC root htb
				if [ 1 == 2 ]; then # HTB CLASSFUL
					# Layer 1 - root
					tc qdisc add dev $NIC root handle 1:0 htb
					# Layer 2 - full bucket
					tc class add dev $NIC parent 1:0 classid 1:1 htb rate 2048kbit
					# Layer 3 - rate limited buckets
					tc class add dev $NIC parent 1:1 classid 1:2 htb rate 1248kbit ceil 2048kbit	# burst fast channel
					tc class add dev $NIC parent 1:1 classid 1:3 htb rate 400kbit ceil 400kbit		# burst slow channel
					tc class add dev $NIC parent 1:1 classid 1:4 htb rate 400kbit ceil 400kbit		# restricted channel
					# Layer 4 - extra splitting...
					# ...
				fi
			fi
		fi
		else
			# Really old kernel support
			echo "hmm..."
		fi
	fi
fi
# /sys/class/net
echo

##################################################
# Queue Length (qlen / txqueuelen)
##################################################
# Default que length for dev
# for : pfifo_fast, sch_fifo, sch_gred, sch_htb, sch_plug, sch_sfb, sch_teql
# (HTB and a few others don't use this queue)
# For the txqueuelen, this is mostly relevant for gigE. Old kernels have shipped with a default txqueuelen of 100,
# which is definately too low and hurts performance.
# a larger que means less packets gets dropped under congestion. as soon as congestion is found tcp slows down transfer.
# if the tcp_congestion_control can't detect congestion the resulting retransmission happens too late resulting in large latencies.
# on older kernels use 1000 or less (600 htcp or 400 cubic)
# in newer kernels use 1000 ir more (cubic network permiting)
# always keep the txqueuelen relative to the transfer speed (a queue cannot drain until packets have been transmitted)
# the goal of the buffer is to allow space to accept a very small amount of "extra" packets that would otherwise trigger congestion flags (when there is little or no congestion). If you have congestion, you should test reducing the value of the queue.
# Kleinrock : bandwidth * the delay * sqrt(Nflows) = an upper bound
echo "Queue Length for $NIC" | printText inf
ip link list dev $NIC | head -1 | grep -o "qlen [0-9]*" | printText val
customsaved=$(cat /etc/rc.local | grep "^ip link set dev $NIC txqueuelen")
curquelen=$(ip link list dev $NIC | head -1 | grep -o "qlen [0-9]*" | sed 's/.* //')
if [[ -z "$customsaved" ]]; then
	echo "Queue length could be optimised"
	echo "Set queue len to: "
	echo "1. 500 (Smaller)"
	echo "2. 1000 (Default)"
	echo "3. 2000 (Larger queue, WARNING: setting the queue too high can oversaturate your nic buffers)"
	echo "s. skip (no change)"
	read -p "Select option (1|2|s) [s] or type custom int value: "
	if [ "$REPLY" == "1" ]; then
		ip link set dev $NIC txqueuelen 500
		sed -i "s/^\(ip link set dev $NIC txqueuelen .*\)/#$(date +"%Y%m%d")#\1/" /etc/rc.local
		echo "ip link set dev $NIC txqueuelen 500" >> /etc/rc.local
		sed -i '/^exit 0/d' /etc/rc.local
		echo "exit 0" >> /etc/rc.local
		ip link list dev $NIC | head -1 | grep -o "qlen [0-9]*" | printText val
	elif [ "$REPLY" == "2" ]; then
		ip link set dev $NIC txqueuelen 1000
		sed -i "s/^\(ip link set dev $NIC txqueuelen .*\)/#$(date +"%Y%m%d")#\1/" /etc/rc.local
		echo "ip link set dev $NIC txqueuelen 1000" >> /etc/rc.local
		sed -i '/^exit 0/d' /etc/rc.local
		echo "exit 0" >> /etc/rc.local
		ip link list dev $NIC | head -1 | grep -o "qlen [0-9]*" | printText val
	elif [ "$REPLY" == "3" ]; then
		ip link set dev $NIC txqueuelen 2000
		sed -i "s/^\(ip link set dev $NIC txqueuelen .*\)/#$(date +"%Y%m%d")#\1/" /etc/rc.local
		echo "ip link set dev $NIC txqueuelen 2000" >> /etc/rc.local
		sed -i '/^exit 0/d' /etc/rc.local
		echo "exit 0" >> /etc/rc.local
		ip link list dev $NIC | head -1 | grep -o "qlen [0-9]*" | printText val
	elif [[ -n "$REPLY" && "$REPLY" -gt "3" ]]; then
		ip link set dev $NIC txqueuelen $REPLY
		sed -i "s/^\(ip link set dev $NIC txqueuelen .*\)/#$(date +"%Y%m%d")#\1/" /etc/rc.local
		echo "ip link set dev $NIC txqueuelen $REPLY" >> /etc/rc.local
		sed -i '/^exit 0/d' /etc/rc.local
		echo "exit 0" >> /etc/rc.local
		ip link list dev $NIC | head -1 | grep -o "qlen [0-9]*" | printText val
	fi
fi
echo

# Queues are run by the kernel at each jiffy
# Jiffies are set to:
# 100Hz for kernels 2.4<
# 1000Hz for kernels 2.6.0 to 2.6.12
# 100,250 (defauly) and 1000 from kernel 2.6.13
# 100,250,300 and 1000 for kern 2.6.20 >

# CONFIG_HZ_PERIODIC
# CONFIG_HZ_100
# CONFIG_HZ_250
# CONFIG_HZ_300 = y
# CONFIG_HZ_1000
# CONFIG_HZ=300

# 300 packets / sec (1500 byte each) = 450KB/sec traffic

##################################################
# Maximum Transfer Unit (JUMBO FRAMES)
##################################################
# ways to use more bandwidth:
# Packet size, standard, jumbo, super sized
# 300 packets/sec at 1500 frame size = 450KB/sec traffic generated
# 300 packets/sec at 4000 frame size = 1200KB/sec traffic generated
# 300 packets/sec at 9000 frame size = 2700KB/sec traffic generated
#1500, 2304, 4000, 9000
echo "Frame size for $NIC" | printText inf
ip link list dev $NIC | head -1 | grep -o "mtu [0-9]*" | printText val
CURRENT_MTU=$(ip link list dev $NIC | head -1 | grep -o "mtu [0-9]*" | awk '{print $2}')
if [ "$CURRENT_MTU" -lt "1500" ]; then
	read -p "Increase mtu to mininum reccomended size? (y/n) [n] "
	if [ "$REPLY" == "y" ]; then
		ip link set dev $NIC mtu 1500
	fi
fi
if [ "$CURRENT_MTU" -lt "1501" ]; then
	tcp_mtu_probing=$(cat /proc/sys/net/ipv4/tcp_mtu_probing)
	kernelCheck "2.6.17"
	if [ "$?" != "0" ]; then
		echo "Kernel version $(uname -r) does not support jumbo frames" | printText inf
		if [ "$tcp_mtu_probing" == "1" ]; then
			echo "Mtu probing not required (no jumbo frames)" | printText inf
			echo "/proc/sys/net/ipv4/tcp_mtu_probing" | printText pro
			cat /proc/sys/net/ipv4/tcp_mtu_probing | printText val
			read -p "Disable MTU Probing? (y/n) [n] "
			if [ "$REPLY" == "y" ]; then
				sed -i "s/^\(net.ipv4.tcp_mtu_probing =.*\)/#$(date +"%Y%m%d")#\1/" /etc/sysctl.conf
				sysctl -w net.ipv4.tcp_mtu_probing=0 >> /etc/sysctl.conf
			fi
		fi
	else
		echo "Kernel version $(uname -r) supports jumbo frames" | printText inf
		gigECheck "$NIC"
		if [ "$?" != "0" ]; then
			echo "$NIC is not gigE, Jumbo frames not reccomended" | printText inf
		else
			JUMBOSIZE=4000
			echo "setting jumbo Max Transfer Unit size of $JUMBOSIZE"
			ip link set dev $NIC mtu $JUMBOSIZE 2>/dev/null
			if [ "$?" == "0" ]; then
				#test larger page
				# 20 bytes for the internet protocol header
				# 8 bytes for the ICMP header and timestamp
				echo "Testing new frame size..."
				ping -M do -c 4 -s $(($JUMBOSIZE-28)) 10.10.0.1 &>/dev/null
				if [ "$?" != "0" ]; then
					echo "Frame size not good, setting to 1500 (normal)."
					ip link set dev $NIC mtu 1500
				else
					echo "Test Passed, with frame size: $JUMBOSIZE"
					if [ "$tcp_mtu_probing" == "1" ]; then
						echo "Mtu reccomended (jumbo frames)" | printText inf
						echo "/proc/sys/net/ipv4/tcp_mtu_probing" | printText pro
						cat /proc/sys/net/ipv4/tcp_mtu_probing | printText val
						read -p "Enable MTU Probing? (y/n) [n] "
						if [ "$REPLY" == "y" ]; then
							sed -i "s/^\(net.ipv4.tcp_mtu_probing =.*\)/#$(date +"%Y%m%d")#\1/" /etc/sysctl.conf
							sysctl -w net.ipv4.tcp_mtu_probing=1 >> /etc/sysctl.conf
						fi
					fi

				fi
			else
				echo "Skipping test, changing frame size failed."
			fi
		fi
	fi
fi
echo

# large recieve offload (LRO)
# friends: TSO, LSO, LFO, UFO, GSO 
# -GRO generic receive offload
# ideal for proxies, proxy based apps, IDS, IPS, firewall, server apps recieving vast amounts of packets.
# implemented in Linux 2.6.18 kernel
kernelCheck "2.6.18"
if [ "$?" != "0" ]; then
	echo "Kernel $(uname -r) does not support LRO" | printText inf
else
	echo "Kernel $(uname -r) does support LRO" | printText inf
	ethtool -K $NIC gro off
	read -p "Large recieve offload? (y/n) [n] "
	if [ "$REPLY" == "y" ]; then
		ethtool -K $NIC lro on
	else
		ethtool -K $NIC lro off 2>/dev/null
	fi
fi

# qdisc queue not single packets data

# full duplex
#ethtool -s $NIC speed 100 duplex full
read -p "Press enter to continue..."
}

function congestionControl(){
##################################################
# Congestion Control
##################################################

title "Congestion Control..."

#modprobe tcp_bic
#modprobe tcp_cubic [default]
#modprobe tcp_highspeed
#modprobe tcp_htcp
#modprobe tcp_reno
#modprobe tcp_vegas
#modprobe tcp_westwood
#modprobe tcp_yeah

# availible
echo "Loaded / Availible congestion control modules: " | printText inf
echo "/proc/sys/net/ipv4/tcp_available_congestion_control" | printText pro
cat /proc/sys/net/ipv4/tcp_available_congestion_control | printText val
echo

# current
echo "Current congestion control modules: " | printText inf
echo "/proc/sys/net/ipv4/tcp_congestion_control" | printText pro
cat /proc/sys/net/ipv4/tcp_congestion_control | printText val
CONCTRL=$(cat /proc/sys/net/ipv4/tcp_congestion_control)
echo

kernelCheck "2.6.33"
if [ "$?" != "0" -a "$CONCTRL" != "htcp" ]; then
	#Use htcp (bugs in others)
	read -p "Switch to htcp congestion control? (y/n) [n] "
	if [ "$REPLY" == "y" ]; then
		sed -i "s/^\(net.ipv4.tcp_congestion_control =.*\)/#$(date +"%Y%m%d")#\1/" /etc/sysctl.conf
		sysctl -w net.ipv4.tcp_congestion_control=htcp >> /etc/sysctl.conf
	fi
elif [ "$CONCTRL" != "cubic" ]; then
	#Use cubic
	read -p "Switch to cubic congestion control? (y/n) [n] "
	if [ "$REPLY" == "y" ]; then
		sed -i "s/^\(net.ipv4.tcp_congestion_control =.*\)/#$(date +"%Y%m%d")#\1/" /etc/sysctl.conf
		sysctl -w net.ipv4.tcp_congestion_control=cubic >> /etc/sysctl.conf
	fi
fi

read -p "Press enter to continue..."
}

##################################################
# Simulation...
##################################################

function netSim(){
	# Network buffers should be temporarily increased or the network will be extra slow...

	# Slow down / Mess up outgoing traffic...
	for NIC in ${NICS[@]}; do
		if [ "$NIC" == "lo" ]; then
			# packet loss may not be effective on local loopback
			continue
		else
			# network can be dellayed in amounts defined by jiffies
			# 10ms on 100Hz kern 2.6-
			#echo "tc qdisc add dev $NIC root netem delay 200ms 10ms 25%"
			tc qdisc add dev $NIC root netem delay 200ms 10ms 25%
			# smallest = 0.0000000232%
			# 0.1% = 1/1000...
			# emulate packet burst losses:
			#echo "tc qdisc change dev $NIC root netem loss 0.3% 25%"
			tc qdisc change dev $NIC root netem loss 0.3% 25%
			# packet duplication (can be burst, same a packet loss):
			#echo "tc qdisc change dev $NIC root netem duplicate 1%"
			tc qdisc change dev $NIC root netem duplicate 1%
			# packet corruption: (required kern >= 2.6.16)
			kernelCheck "2.6.16"
			if [ "$?" == "0" ]; then
				#echo "tc qdisc change dev $NIC root netem corrupt 0.1% "
				tc qdisc change dev $NIC root netem corrupt 0.1% 
			fi
			# Re-ordering
			#tc qdisc change dev $NIC root netem gap 5 delay 10ms
			#echo "tc qdisc change dev $NIC root netem delay 10ms reorder 25% 50%"
			tc qdisc change dev $NIC root netem delay 10ms reorder 25% 50%
			#tc qdisc change dev $NIC root netem delay 100ms 75ms
			# Rate limiting...
			# not build into netem, htb or tbf will need to be used, skipping for now...
		fi
	done
	echo "Network is now really slow and dropping packets like crazy..." | printText inf
	echo "To go back to normal operation run ./net-check.sh recover" | printText inf
	echo
}

function netRecov(){
	for NIC in ${NICS[@]}; do
		if [ "$NIC" == "lo" ]; then
			# packet loss may not be effective on local loopback
			continue
		else
			#echo "tc qdisc delete dev $NIC root netem delay 0"
			tc qdisc delete dev $NIC root netem delay 0
		fi
	done
	echo "All back to normal now..." | printText inf
	echo
}

##################################################
# Run the script...
##################################################

if [ "$1" == "debug" ]; then
	#Common queries for checking the network...
	netCheck
elif [ "$1" == "destroy" ]; then
	#Network slow down... busy network emulation...
	netSim
elif [ "$1" == "recover" ]; then
	#Network reset from destroy
	netRecov
else
	#Normal Script
	sizeMatters
	for NIC in ${NICS[@]}; do
		if [ "$NIC" == "lo" ]; then
			#i've not yet looked into local loop back optimisations
			continue
		else
			adjustNic $NIC</dev/tty
		fi
	done
	congestionControl
fi

