#!/bin/bash
##################################################
# Name: net-check.sh
# Desc: A performance analysis and suggestion tool for faster linux networking.
# The goal of this script is to clearly identify and explain each tunable for networking performance.
# Date: 17/10/2015
# Author: Michael Jones <mj@mikejonesey.co.uk>
# Licence: GNU LGPL V3
##################################################
# info sources, references and thanks:
# Stephen Hemminger, Bufferbloat, Linuxcon 2015
# Alessandro Selli, Traffic Control, Linuxcon 2015
# man pages: tcp
# http://www.acc.umu.se/~maswan/linux-netperf.txt
# http://www.bufferbloat.net/projects/codel/wiki
#

NICS=($(ls -1 /sys/class/net/))

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

function sizeMatters(){
##################################################
# Sizes...
##################################################

title "Sizes..."

PAGE_SIZE=$(getconf PAGESIZE)
tcp_adv_win_scale=$(cat /proc/sys/net/ipv4/tcp_adv_win_scale)

# speed math...
# divide window by latency
# (tcp_adv_win_scale default is 2)
# (window/2^tcp_adv_win_scale)/0.150 = ...
# (87380 - 87380/2^2)/0.150 = 436906 bytes/s, or about 400 kbyte/s
# (873800 - 873800/2^2)/0.150 = 4369000 bytes/s, or about 4Mbytes/s

# Socket Buffer Size (bytes)
#This sets the max OS receive buffer size for all types of connections.
echo "Maxiumum receive buffer size for all connections: " | printText inf
echo "/proc/sys/net/core/rmem_max" | printText pro
cat /proc/sys/net/core/rmem_max | printText val
echo

#This sets the max OS send buffer size for all types of connections.
echo "Maxiumum receive buffer size for all connections: " | printText inf
echo "/proc/sys/net/core/wmem_max" | printText pro
cat /proc/sys/net/core/wmem_max | printText val
echo

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
cat /proc/sys/net/ipv4/tcp_mem | printText val
echo

# This will enusre that immediatly subsequent connections use these values (set to 1 to enable)
#echo "/proc/sys/net/ipv4/route/flush"
#cat /proc/sys/net/ipv4/route/flush

# each driver sets it's own tx_ring, rx_ring
# application can set SO_SNDBUF and SO_RCVBUF

#man 7 socket
# rmem_default = default size of receive buffers used by sockets (bytes)
# wmem_default = default size of send buffers used by sockets (bytes)

echo "Default tcp recieve buffer size: " | printText inf
echo "/proc/sys/net/core/rmem_default" | printText pro
cat /proc/sys/net/core/rmem_default | printText val
echo

echo "Default tcp send buffer size: " | printText inf
echo "/proc/sys/net/core/wmem_default" | printText pro
cat /proc/sys/net/core/wmem_default | printText val
echo

# overwritten by:
# min		4K,  lowered  to PAGE_SIZE bytes in low-memory systems (used under presure)
# default ???
# max (On Linux 2.4, the default is 87380*2 bytes, lowered to 87380 in low-memory systems).
echo "[b]1 minimum receive buffer for each TCP connection, this buffer is always allocated to a TCP socket, even under high pressure on the system." | printText inf
echo "[b]2 default receive buffer allocated for each TCP socket. This value overrides the /proc/sys/net/core/rmem_default value used by other protocols." | printText inf
echo "[b]3 maximum receive buffer that can be allocated for a TCP socket" | printText inf
TCP_RMEM=($(cat /proc/sys/net/ipv4/tcp_rmem))
echo "/proc/sys/net/ipv4/tcp_rmem [b] [b] [b]" | printText pro
cat /proc/sys/net/ipv4/tcp_rmem | printText val
echo

# Every TCP socket has this much buffer space to use before the buffer is filled up
#20 (ms) * 100 (Mbps) = 0.02 * 100 / 8 * 1024 = 256 KB
echo "[b]1 minimum TCP send buffer space available for a single TCP socket" | printText inf
echo "[b]2 default buffer space allowed for a single TCP socket to use." | printText inf
echo "[b]3 the maximum TCP send buffer space." | printText inf
echo "/proc/sys/net/ipv4/tcp_wmem [b] [b] [b]" | printText pro
cat /proc/sys/net/ipv4/tcp_wmem | printText val
echo

# Maximum backlog size
# Sets the maximum number of packets allowed to queue when a particular interface receives packets faster than the kernel can process them.
# The default value for this file is 300 in older kernels and 1000 in newer kernels.
echo "Maximum backlog size (packets)" | printText inf
echo "/proc/sys/net/core/netdev_max_backlog" | printText pro
cat /proc/sys/net/core/netdev_max_backlog | printText val
echo

calc_max_tcp_no_pressure_bytes=$(echo "${TCP_MEM[1]}*$PAGE_SIZE" | bc)
calc_max_tcp_con_no_pressure=$(echo "scale=0; $calc_max_tcp_no_pressure_bytes/${TCP_RMEM[1]}" | bc)
speed_guess=$(echo "scale=2; ((${TCP_RMEM[1]}-(${TCP_RMEM[1]}/2^$tcp_adv_win_scale))/0.150)/1000000" | bc)
speed_guess_mbps=$(echo "scale=2; $speed_guess*8" | bc)
slow_speed_guess=$(echo "scale=2; ((${TCP_RMEM[0]}-(${TCP_RMEM[0]}/2^$tcp_adv_win_scale))/0.150)/1000000" | bc)
slow_speed_guess_mbps=$(echo "scale=2; $slow_speed_guess*8" | bc)
ram_at_optimum_usage=$(echo "scale=2; $calc_max_tcp_no_pressure_bytes/1000000" | bc)
max_networking_ram=$(echo "scale=2; (${TCP_MEM[2]}*$PAGE_SIZE)/1000000" | bc)

echo "Max connections $calc_max_tcp_con_no_pressure with optimum throughput of $speed_guess Mbytes/s ($speed_guess_mbps Mbps)" | printText atn
echo "Pressure connections will be $slow_speed_guess Mbytes/s ($slow_speed_guess_mbps Mbps)" | printText atn
echo "RAM used by networking at optimum: $ram_at_optimum_usage MB" | printText atn
echo "Max RAM used by networking: $max_networking_ram MB" | printText atn
echo
read -p "Press enter to continue..."

# Que disciplines have their own buffers ontop of OS buffer

# Packet size, standard, jumbo, super sized

# Capacity of CPU to keep up with the flux (load, jiffies)

# Number of hops (switches, routers)...
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

echo "Maximum backlog size (packets)" | printText inf
echo "/proc/sys/net/core/default_qdisc" | printText pro
cat /proc/sys/net/core/default_qdisc | printText val
if [ "$(cat /proc/sys/net/core/default_qdisc)" != "fq_codel" ]; then
	read -p "Would you like to set your default queue disciple to fq_codel? (y/n) [n] "
	if [ "$REPLY" == "y" ]; then
		sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
		echo "net.core.default_qdisc = fq_codel" >> /etc/sysctl.conf
		sysctl -p
	fi
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
#	if [ "$curqdisc" != "mq" ]; then
		echo "Detected nic $NIC is wifi, preffered qdisc is mq, current qdisc is $curqdisc" | printText inf
		read -p "Set queue discipline to mq?"
		if [ "$REPLY" == "y" ]; then
			#tc qdisc replace dev $NIC root mq
			tc qdisc replace dev $NIC handle 1 root mq
			tc qdisc replace dev $NIC parent 1:1 fq_codel noecn
			tc qdisc replace dev $NIC parent 1:2 fq_codel
			tc qdisc replace dev $NIC parent 1:3 fq_codel
			tc qdisc replace dev $NIC parent 1:4 fq_codel noecn
		fi
#	fi
else
	if [ "$curqdisc" != "fq_codel" ]; then
		echo "Detected nic $NIC is ethernet" | printText inf
		read -p "Set queue discipline to fq_codel?"
		if [ "$REPLY" == "y" ]; then
			tc qdisc replace dev $NIC root fq_codel
		fi
	fi
fi
# /sys/class/net
echo

# Default que length for dev
echo "Queue Length for $NIC" | printText inf
ip link list dev $NIC | head -1 | grep -o "default qlen [0-9]*" | printText val
echo

# For the txqueuelen, this is mostly relevant for gigE, but should not hurt
# anything else. Old kernels have shipped with a default txqueuelen of 100,
# which is definately too low and hurts performance.
ip link set dev $NIC txqueuelen 3000

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

# ways to use more bandwidth:
# jumbo frames
#1500, 2304, 4000, 9000
JUMBOSIZE=4000
CURRENT_MTU=$(ip link list dev $NIC | head -1 | grep -o "mtu [0-9]*" | awk '{print $2}')
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
	fi
else
	echo "Skipping test, changing frame size failed."
fi
# large recieve offload (LRO over GRO) instead of generic receive offload
# ideal for proxies, proxy based apps, IDS, IPS, firewall, server apps recieving vast amounts of packets.
# implemented in Linux 2.6 kernel
ethtool -K $NIC gro off
read -p "Large recieve offload? (y/n) [y] "
if [ "$REPLY" == "y" ]; then
	ethtool -K $NIC lro on
else
	ethtool -K $NIC lro off
fi

# qdisc queue not single packets data

# full duplex
#ethtool -s $NIC speed 100 duplex full
}

function congestionControl(){
##################################################
# Congestion Control
##################################################
#modprobe tcp_bic
#modprobe tcp_cubic [default]
#modprobe tcp_highspeed
#modprobe tcp_htcp
#modprobe tcp_reno
#modprobe tcp_vegas
#modprobe tcp_westwood
#modprobe tcp_yeah

# availible
echo "/proc/sys/net/ipv4/tcp_available_congestion_control"
cat /proc/sys/net/ipv4/tcp_available_congestion_control

# current
echo "/proc/sys/net/ipv4/tcp_congestion_control"
cat /proc/sys/net/ipv4/tcp_congestion_control
}

##################################################
# Run the script...
##################################################
sizeMatters
for NIC in ${NICS[@]}; do
	adjustNic $NIC</dev/tty
done
congestionControl

