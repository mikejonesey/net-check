#!/bin/bash

##################################################
# Sizes...
##################################################

# Socket Buffer Size
#This sets the max OS receive buffer size for all types of connections.
echo "/proc/sys/net/core/rmem_max"
cat /proc/sys/net/core/rmem_max

#This sets the max OS send buffer size for all types of connections.
echo "/proc/sys/net/core/wmem_max"
cat /proc/sys/net/core/wmem_max

#The tcp_mem variable defines how the TCP stack should behave when it comes to memory usage. 
# The first value specified in the tcp_mem variable tells the kernel the low threshold. Below this point, the TCP stack do not bother at all about putting any pressure on the memory usage by different TCP sockets.
# The second value tells the kernel at which point to start pressuring memory usage down.
# The final value tells the kernel how many memory pages it may use maximally. If this value is reached, TCP streams and packets start getting dropped until we reach a lower memory usage again. This value includes all TCP sockets currently in use.
echo "/proc/sys/net/ipv4/tcp_mem"
cat /proc/sys/net/ipv4/tcp_mem

# This will enusre that immediatly subsequent connections use these values (set to 1 to enable)
#echo "/proc/sys/net/ipv4/route/flush"
#cat /proc/sys/net/ipv4/route/flush

# each driver sets it's own tx_ring, rx_ring
# application can set SO_SNDBUF and SO_RCVBUF

#man 7 socket
# rmem_default = default size of receive buffers used by sockets (bytes)
# wmem_default = default size of send buffers used by sockets (bytes)

echo "/proc/sys/net/core/rmem_default"
cat /proc/sys/net/core/rmem_default

echo "/proc/sys/net/core/wmem_default"
cat /proc/sys/net/core/wmem_default

# overwritten by:
echo "/proc/sys/net/ipv4/tcp_rmem [b] [b] [b]"
echo "[b]1 minimum receive buffer for each TCP connection, this buffer is always allocated to a TCP socket, even under high pressure on the system."
echo "[b]2 default receive buffer allocated for each TCP socket. This value overrides the /proc/sys/net/core/rmem_default value used by other protocols."
echo "[b]3 maximum receive buffer that can be allocated for a TCP socket"
cat /proc/sys/net/ipv4/tcp_rmem

# Every TCP socket has this much buffer space to use before the buffer is filled up
echo "/proc/sys/net/ipv4/tcp_wmem [b] [b] [b]"
echo "[b]1 minimum TCP send buffer space available for a single TCP socket"
echo "[b]2 default buffer space allowed for a single TCP socket to use."
echo "[b]3 the maximum TCP send buffer space."
cat /proc/sys/net/ipv4/tcp_wmem

# Maximum backlog size (default 1000 packets)
echo "/proc/sys/net/core/netdev_max_backlog"
cat /proc/sys/net/core/netdev_max_backlog

# Que disciplines have their own buffers ontop of OS buffer

# Packet size, standard, jumbo, super sized

# Capacity of CPU to keep up with the flux (load, jiffies)

# Number of hops (switches, routers)...

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

echo "/proc/sys/net/core/default_qdisc"
cat /proc/sys/net/core/default_qdisc

# Que Filters
# ematch : Extended matches for use with "basic" or "flow" filters
# bpf : BPF programmable classifier and actions (NEW)
# 	cBPF : Classic Berkeley Packet Filter (actually runs eBPF)
#	eBPF : Extended Berkeley Packet Filter

# Default qdisc for dev
ip link list dev wlan0 | head -1 | grep -o "qdisc [a-z_]*"

# Default que length for dev
ip link list dev wlan0 | head -1 | grep -o "default qlen [0-9]*"

#Changing them
ip link set dev wlan0 txqueuelen 2000
tc qdisc replace dev wlan0 root fq_codel
#tc qdisc replace dev wlan0 root prio

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
CURRENT_MTU=$(ip link list dev wlan0 | head -1 | grep -o "mtu [0-9]*" | awk '{print $2}')
echo "setting jumbo Max Transfer Unit size of $JUMBOSIZE"
ip link set dev wlan0 mtu $JUMBOSIZE

#test larger page
# 20 bytes for the internet protocol header
# 8 bytes for the ICMP header and timestamp
ping -M do -c 4 -s $(($JUMBOSIZE-28)) 10.10.0.1 &>/dev/null
if [ "$?" != "0" ]; then
	echo "Frame size not good, setting to 1500 (normal)."
	ip link set dev wlan0 mtu 1500
fi

# large recieve offload (LRO over GRO) instead of generic receive offload
# ideal for proxies, proxy based apps, IDS, IPS, firewall, server apps recieving vast amounts of packets.
# implemented in Linux 2.6 kernel
ethtool -K ethX lro off
ethtool -K ethX gro off
#ethtool -K ethX lro on
#ethtool -K ethX gro on

# qdisc queue not single packets data

# full duplex
#ethtool -s eth3 speed 100 duplex full

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

##################################################
# Nic Control
##################################################
#ifconfig eth2 txqueuelen 10000

