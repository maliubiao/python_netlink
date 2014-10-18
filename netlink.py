import socket
import struct
import cStringIO
import pdb 
import io 

NETLINK_ROUTE = 0
NETLINK_UNUSED = 1
NETLINK_USERSOCK = 2
NETLINK_FIREWALL = 3
NETLINK_SOCK_DIAG = 4
NETLINK_NFLOG = 5
NETLINK_XFRM = 6
NETLINK_SELINUX = 7
NETLINK_ISCSI = 8
NETLINK_AUDIT = 9
NETLINK_FIB_LOOKUP = 10
NETLINK_CONNECOTR = 11
NETLINK_NETFILTER = 12
NETLINK_IP6_FW = 13
NETLINK_DNRTMSG = 14
NETLINK_KOBJECT_UEVENT = 15
NETLINK_GENERIC = 16
NETLINK_SCSITRANSPORT = 18
NETLINK_ECRYPTFS = 19
NETLINK_RDMA = 20
NETLINK_CRYPTO = 21

AF_UNPSEC = 0
AF_UNIX = 1
AF_LOCAL= 1
AF_INET = 2
AF_BRIDGE = 7
AF_INET6 = 10
AF_NETLINK = 16
AF_PACKET = 17 

IPPROTO_IP = 0
IPPROTO_ICMP = 1
IPPROTO_IGMP = 2
IPPROTO_IPIP = 4
IPPROTO_TCP = 6
IPPROTO_EGP = 8 
IPPROTO_PUP = 12
IPPROTO_UDP = 17
IPPROTO_TP = 29
IPPROTO_DCCP = 33
IPPROTO_IPV6 = 41
IPPROTO_RSVP = 46
IPPROTO_GRE = 47
IPPROTO_ESP = 50
IPPROTO_AH = 51
IPPROTO_MTP = 92
IPPROTO_BEETPH = 94
IPPROTO_ENCAP = 98
IPPROTO_PIM = 103
IPPROTO_COMP = 108
IPPROTO_SCTP = 132
IPPROTO_UDPLITE = 136
IPPROTO_RAW = 255

TCPF_ESTABLISHED = 1 << 1
TCPF_SYN_SENT = 1 << 2
TCPF_SYN_RECV = 1 << 3
TCPF_FIN_WAIT1 = 1 << 4
TCPF_FIN_WAIT2 = 1 << 5
TCPF_TIME_WAIT = 1 << 6
TCPF_CLOSE = 1 << 7
TCPF_CLOSE_WAIT = 1 << 8
TCPF_LAST_ACK = 1 << 9
TCPF_LISTEN = 1 << 10
TCPF_CLOSING = 1 << 11
TCPF_ALL = 0xfff

F_REQUEST = 1
F_MULTI = 2
F_ACK = 4
F_ECHO = 8
F_DUMP_INTR = 16 

#Modifiers to GET request
F_ROOT = 0x100
F_MATCH = 0x200
F_AOTMIC = 0x400
F_DUMP = F_ROOT | F_MATCH
#Modifiers to NEW request
F_REPLACE = 0x100
F_EXCL = 0x200
F_CREATE = 0x400
F_APPEND = 0x800


NOOP = 0x1
ERROR = 0x2
DONE = 0x3
OVERRUN = 0x4
MIN_TYPE = 0x10

RTM_NEWLINK = 16
RTM_DELLINK = 17 
RTM_GETLINK = 18
RTM_SETLINK = 19

RTM_NEWADDR = 20
RTM_DELADDR = 21
RTM_GETADDR = 22

RTM_NEWROUTE = 24
RTM_DELROUTE = 25
RTM_GETROUTE = 26 

RTM_NEWNEIGH = 28
RTM_DELNEIGH = 29
RTM_GETNEIGH = 30

RTM_NEWRULE = 32
RTM_DELRULE = 33
RTM_GETRULE = 34

RTM_NEWQDISC = 36
RTM_DELQDISC = 37
RTM_GETQDISC = 38

RTM_NEWTCLASS = 40
RTM_DELTCLASS = 41
RTM_GETTCLASS = 42

RTM_NEWTFILTER = 44
RTM_DELTFILTER = 45
RTM_GETTFILTER = 46

RTM_NEWACTION = 48
RTM_DELACTION = 49
RTM_GETACTION = 50

RTM_NEWPREFIX = 52
RTM_GETMULTICAST = 58
RTM_GETANYCAST = 62

RTM_NEWNEIGHTBL = 64
RTM_GETNEIGHTBL = 66
RTM_SETNEIGHTBL = 67

RTM_NEWNDUSEROPT = 68
RTM_NEWADDRLABEL = 72
RTM_DELADDRLABEL = 73
RTM_GETADDRLABEL = 74

RTM_GETDCB = 78
RTM_SETDCB = 79
RTM_NEWNETCONF = 80
RTM_GETNETCONF = 82
RTM_NEWMDB = 84
RTM_DELMDB = 85
RTM_GETMDB =  86

#for GETROUTE
rtmsg = (
        ("family", "B"),
        ("dst_len", "B"),
        ("src_len", "B"),
        ("tos", "B"),
        ("table", "B"),
        ("protocol", "B"),
        ("scope", "B"),
        ("type", "B"),
        ("flags", "I")
        )


def new_rtmsg(d):
    return new_struct(d, rtmsg)

def parse_rtmsg(b):
    return parse_struct(b, rtmsg)

#rtm_type
RTN_UNSPEC = 0
#Gateway or direct route
RTN_UNICAST = 1
#accept locally
RTN_LOCAL = 2
#accept locally as broadcast, send as broadcast
RTN_ANYCAST = 3
#Multicast route
RTN_MULTICAST = 4
#Drop
RTN_BLACKHOLE = 5
#Destination is unreachable
RTN_UNREACHABLE = 6
#Administratively prohibited
RTN_PROHIBIT = 7
#Not in this table
RTN_THROW = 8
#Translate this address
RTN_NAT = 9
#use external resolver
RTN_XRESOLVE = 10

#rtm_protocol
RTPROT_UNSPEC = 0
#Route installed by ICMP redirects, not used by current IPv4
RTPROT_REDIRECT = 1
#Route installed by kernel
RTPROT_KERNEL = 2
#Route instaled during boot
RTPROT_BOOT = 3
#Route installed by administrator
RTPROT_STATIC = 4
#GeteD
RTPROT_GATED = 8
#RDISC/ND router advertisements
RTPROT_RA = 9
#Merit MRT
RTPROT_MRT = 10
#Zebra
RTPROT_ZEBRA = 11
#BIRD
RTPROT_BIRD = 12
#DECnet routing daemon
RTPROT_DNROUTED = 13
#XORP
RTPROT_XORP = 14
#Netsukuku
RTPROT_NTK = 15
#DHCP client
RTPROT_DHCP = 16
#Multicast daemon
RTPROT_MROUTED = 17

#rtm_scope, sort of distance to the destination
#everywhere in the Universe
RT_SCOPE_UNIVERSE = 0
RT_SCOPE_SITE = 200
#destionations, located on directly attached link
RT_SCOPE_LINK = 253
#local addresses
RT_SCOPE_HOST = 254
#reserved for not existing destinations
RT_SCOPE_NOWHERE = 255

#rtm_flags
#Notify user of route change
RTM_F_NOTIFY = 0x100
#This route is cloned
RTM_F_CLONED = 0x200
#Multipath equalizer: NI
RTM_F_EQUALIZE = 0x400
#Prefix addresses
RTM_F_PREFIX = 0x800

#reserved table identifiers
RT_TABLE_UNSPEC = 0
RT_TABLE_COMPAT = 252
RT_TABLE_DEFAULT = 253
RT_TABLE_MAIN = 254
RT_TABLE_LOCAL = 255 

#routing message attrs
RTA_UNSPEC = 0
RTA_DST = 1
RTA_SRC = 2
RTA_IIF = 3
RTA_OIF = 4
RTA_GATEWAY = 5
RTA_PRIORITY = 6
RTA_PREFSRC = 7
RTA_METRICS = 8
RTA_MULTIPATH = 9
RTA_PROTOINFO = 10
RTA_FLOW = 11
RTA_CACHEINFO = 12
RTA_SESSION = 13
RTA_MP_ALGO = 14
RTA_TABLE = 15
RTA_MARK = 16
RTA_MFC_STATS = 17 

IFLA_UNSPEC = 0
IFLA_ADDRESS = 1 #
IFLA_BROADCAST = 2 #
IFLA_IFNAME = 3 #
IFLA_MTU = 4 #
IFLA_LINK = 5
IFLA_QDISC = 6 #
IFLA_STATS = 7 #
IFLA_COST = 8
IFLA_PRIORITY = 9
IFLA_MASTER = 10
IFLA_WIRELESS = 11
IFLA_PROTINFO = 12
IFLA_TXQLEN = 13 #
IFLA_MAP = 14 #
IFLA_WEIGHT = 15
IFLA_OPERSTATE = 16 #
IFLA_LINKMODE = 17 #
IFLA_LINKINFO = 18
IFLA_NET_NS_PID = 19
IFLA_IFALIAS = 20
IFLA_NUM_VF = 21
IFLA_VFINFO_LIST = 22
IFLA_STATS64 = 23 #
IFLA_VF_PORTS = 24
IFLA_PORT_SELF = 25
IFLA_AF_SPEC = 26 #
IFLA_GROUP = 27 #
IFLA_NET_NS_FD = 28
IFLA_EXT_MASK = 29
IFLA_PROMISCUITY = 30 #
IFLA_NUM_TX_QUEUES = 31 #
IFLA_NUM_RX_QUEUES = 32 #
IFLA_CARRIER = 33 #
IFLA_PHYS_PORT_ID = 34
IFLA_CARRIER_CHANGES = 35 

SOCK_DIAG_BY_FAMILY = 20

NLA_UNSPEC = 0
NLA_U8 = 1
NLA_U16 = 2
NLA_U32 = 3
NLA_U64 = 4
NLA_STRING = 5
NLA_FLAG = 6
NLA_MSECS = 7
NLA_NESTED = 8
NLA_NESTED_COMPAT = 9
NLA_NUL_STRING = 10
NLA_BINARY = 11
NLA_S8 = 12
NLA_S16 = 13
NLA_S32 = 14
NLA_S64 = 15
NLA_STRUCT = 16

MAX_ADDR_LEN = 32
IFNAMSIZ = 16
MAX_PHYS_PORT_ID_LEN = 32


def parse_policy_string(raw):
    return raw.strip("\x00") 

def parse_policy_binary(raw):
    return raw

def parse_policy_u8(raw):
    return struct.unpack("B", raw)[0]

def parse_policy_u16(raw):
    return struct.unpack("H", raw)[0]

def parse_policy_u32(raw):
    return struct.unpack("I", raw)[0]

def parse_policy_u64(raw):
    return struct.unpack("Q", raw)[0] 

#do nothing
def parse_policy_flag(raw):
    return True

#slot
def parse_policy_nested(raw):
    pass

def new_policy_flag(none):
    return ""

def new_policy_binary(binary):
    return binary

def new_policy_string(string):
    return string+"\x00"

def new_policy_u8(num):
    return struct.pack("B", num) 

def new_policy_u16(num):
    return struct.pack("H", num)

def new_policy_u32(num):
    return struct.pack("I", num)

def new_policy_u64(raw):
    return struct.pack("Q", num) 


link_ifmap = (
        ("mem_start", "Q"),
        ("mem_end", "Q"),
        ("base_addr", "Q"),
        ("irq", "H"),
        ("dma", "B"),
        ("port", "B")
        )


def new_ifmap(d):
    return new_struct(d, link_ifmap)


def parse_ifmap(b):
    return parse_struct(b, link_ifmap)


link_stats = (
        ("rx_packets", "I"),
        ("tx_packets", "I"),
        ("rx_bytes", "I"),
        ("tx_bytes", "I"),
        ("rx_errors", "I"),
        ("tx_errors", "I"),
        ("rx_dropped", "I"),
        ("tx_dropped", "I"),
        ("mulicast", "I"),
        ("rx_length_errors", "I"),
        ("rx_over_errors", "I"),
        ("rx_crc_errors", "I"),
        ("rx_frame_errors", "I"),
        ("rx_fifo_errors", "I"),
        ("rx_missed_errors", "I"),
        ("tx_aborted_errors", "I"),
        ("tx_carrier_errors", "I"),
        ("tx_fifo_errors", "I"),
        ("tx_heartbeat_errors", "I"),
        ("tx_window_errors", "I"),
        ("rx_compressed", "I"),
        ("tx_compressed", "I")
        )

def new_stats(d):
    return new_struct(d, link_stats)


def parse_stats(b):
    return parse_struct(b, link_stats)


link_stats64 = (
        ("rx_packets", "Q"),
        ("tx_packets", "Q"),
        ("rx_bytes", "Q"),
        ("tx_bytes", "Q"),
        ("rx_errors", "Q"),
        ("tx_errors", "Q"),
        ("rx_dropped", "Q"),
        ("tx_dropped", "Q"),
        ("mulicast", "Q"),
        ("rx_length_errors", "Q"),
        ("rx_over_errors", "Q"),
        ("rx_crc_errors", "Q"),
        ("rx_frame_errors", "Q"),
        ("rx_fifo_errors", "Q"),
        ("rx_missed_errors", "Q"),
        ("tx_aborted_errors", "Q"),
        ("tx_carrier_errors", "Q"),
        ("tx_fifo_errors", "Q"),
        ("tx_heartbeat_errors", "Q"),
        ("tx_window_errors", "Q"),
        ("rx_compressed", "Q"),
        ("tx_compressed", "Q")
        ) 


def new_stats64(d):
    return new_struct(d, link_stats64)


def parse_stats64(b):
    return parse_struct(b, link_stats64)


#rtnl_link_info_fill->IFLA_INFO_KIND, -> IFLA_INFO_DATA, -> ipip_fill_info
#IFLA_IPTUN_LINK, LOCAL, REMOTE, TTL, TOS, PMTUDISC
#rtnl_link_slave_info_fill

def parse_afspec(attr): 
    b = cStringIO.StringIO(attr["payload"])
    attrs = parse_nested(attr)
    ret = {} 
    for m in attrs:
        if m["type"] == AF_INET: 
            #only one
            m = parse_nested(m)[0]
            x = cStringIO.StringIO(m["payload"])
            conf = parse_ipv4_devconf(b) 
        elif m["type"] == AF_INET6: 
            for x in parse_nested(m):
                name, tp, parser = ipv6_attr_policy[x["type"]]
                if tp == NLA_STRUCT:
                    b = cStringIO.StringIO(x["payload"])
                    ret[name] = parser(b) 
    return ret

ifla_attr_policy = { 
        IFLA_ADDRESS: ("address", NLA_BINARY, parse_policy_binary), 
        IFLA_BROADCAST: ("boradcast", NLA_BINARY, parse_policy_binary),
        IFLA_IFNAME: ("ifname", NLA_STRING, parse_policy_string),
        IFLA_MTU: ("mtu", NLA_U32, parse_policy_u32),
        IFLA_LINK:("link", NLA_U32, parse_policy_u32),
        IFLA_QDISC: ("qdisc", NLA_STRING, parse_policy_string),
        IFLA_STATS: ("stats", NLA_STRUCT, parse_stats),
        #IFLA_COST: (NLA_STRUCT, -1), #
        #IFLA_PRIORITY: (NLA_STRUCT, -1), #
        IFLA_MASTER: ("master", NLA_U32, parse_policy_u32), 
        #IFLA_WIRELESS: (NLA_STRUCT, -1), #
        #IFLA_PROTINFO: (NLA_STRUCT, -1),#
        IFLA_TXQLEN: ("txqlen", NLA_U32, parse_policy_u32),
        IFLA_MAP: ("map", NLA_STRUCT, parse_ifmap),
        IFLA_WEIGHT: ("weight", NLA_U32, parse_policy_u32),
        IFLA_OPERSTATE: ("operstate", NLA_U8, parse_policy_u8),
        IFLA_LINKMODE: ("linkmode", NLA_U8, parse_policy_u8),
        #IFLA_LINKINFO: (NLA_NESTED, -1),
        IFLA_NET_NS_PID: ("net_ns_pid", NLA_U32, parse_policy_u32),
        IFLA_IFALIAS: ("ifalias", NLA_STRING, parse_policy_string),
        IFLA_NUM_VF: ("num_vf", NLA_U32, parse_policy_u32), #
        #IFLA_VFINFO_LIST: (NLA_NESTED, -1),
        IFLA_STATS64: ("stat64", NLA_STRUCT, parse_stats64),
        #IFLA_VF_PORTS: (NLA_NESTED, -1),
        IFLA_PORT_SELF: ("port_self", NLA_NESTED, -1),
        IFLA_AF_SPEC: ("af_spec", NLA_NESTED, parse_afspec),
        IFLA_GROUP: ("group", NLA_U32, parse_policy_u32), #
        IFLA_NET_NS_FD: ("net_ns_fd", NLA_U32, parse_policy_u32),
        IFLA_EXT_MASK: ("ext_mask", NLA_U32, parse_policy_u32),
        IFLA_PROMISCUITY: ("promiscuity", NLA_U32, parse_policy_u32),
        IFLA_NUM_TX_QUEUES: ("tx_queues", NLA_U32, parse_policy_u32),
        IFLA_NUM_RX_QUEUES: ("rx_queues", NLA_U32, parse_policy_u32),
        IFLA_CARRIER: ("carrier", NLA_U8, parse_policy_u8),
        IFLA_PHYS_PORT_ID: ("phys_port_id", NLA_BINARY, parse_policy_binary),
        IFLA_CARRIER_CHANGES: ("carrier_changes", NLA_U32, parse_policy_u32)
        }

IFLA_VF_INFO_UNSPEC = 0
IFLA_VF_INFO = 1

IFLA_VF_UNSPEC = 0
#hardware queue specific attribute
IFLA_VF_MAC = 1 
IFLA_VF_VLAN = 2
#max tx badnwidth allocation
IFLA_VF_TX_RATE = 3
#spoof checking on/off switch
IFLA_VF_SPOOFCHK = 4
#link state enable/disable/auto switch
IFLA_VF_LINK_STATE = 5
#min and max tx badnwidth allocation
IFLA_VF_RATE  = 6


def parse_vf_unspec(b):
    return None

def parse_vf_mac(b):
    d = b.read(36)
    return {
            "vf": struct.unpack("I", d[:4])[0],
            "mac": d[4:] 
            } 

def new_vf_map(d):
    return struct.pack("I", d["vf"]) + d["mac"]


vf_vlan = {
        "vf": "I",
        "vlan": "I",
        "qos": "I"
        }

def new_vf_vlan(d):
    return new_struct(d, vf_vlan)

def parse_vf_vlan(b):
    return parse_struct(b, vf_vlan)


vf_tx_rate = {
        "vf": "I",
        "rate": "I"
        }

def new_vf_tx_rate(d):
    return new_struct(d, vf_tx_rate)


def parse_vf_tx_rate(b):
    return parse_struct(b, vf_tx_rate)


vf_rate = {
        "vf": "I",
        "min_tx_rate": "I",
        "max_tx_rate": "I"
        }

def new_vf_rate(d):
    return new_struct(d, vf_rate)

def parse_vf_rate(b):
    return parse_struct(b, vf_rate)


vf_spoofchk = {
        "vf": "I",
        "setting": "I"
        }

def new_vf_spoofchk(d):
    return new_struct(d, vf_spoofchk)

def parse_vf_spoofchk(b):
    return parse_struct(b, vf_spoofchk)


vf_link_state = {
        "vf": "I",
        "link_state": "I"
        }

def new_vf_link_state(d):
    return new_struct(d, vf_link_state)


def parse_vf_link_state(b):
    return parse_struct(b, vf_link_state) 


ifla_vf = { 
        IFLA_VF_MAC: ("mac", NLA_STRUCT, parse_vf_mac),
        IFLA_VF_VLAN: ("vlan", NLA_STRUCT,  parse_vf_vlan),
        IFLA_VF_TX_RATE: ("tx_rate", NLA_STRUCT, parse_vf_tx_rate),
        IFLA_VF_SPOOFCHK: ("spoofchk", NLA_STRUCT, parse_vf_spoofchk),
        IFLA_VF_LINK_STATE: ("link_state", NLA_STRUCT, parse_vf_link_state),
        IFLA_VF_RATE: ("rate", NLA_STRUCT, parse_vf_rate)
        } 


#for IFLA_AF_SPEC family 2, AF_INET
IPV4_DEVCONF_FORWARDING = 1
IPV4_DEVCONF_MC_FORWARDING  = 2
IPV4_DEVCONF_PROXY_ARP = 3
IPV4_DEVCONF_ACCEPT_REDIRECTS = 4
IPV4_DEVCONF_SECURE_REDIRECTS = 5
IPV4_DEVCONF_SEND_REDIRECTS = 6
IPV4_DEVCONF_SHARED_MEDIA = 7
IPV4_DEVCONF_RP_FILTER = 8
IPV4_DEVCONF_ACCEPT_SOURCE_ROUTE = 9
IPV4_DEVCONF_BOOTP_RELAY = 10
IPV4_DEVCONF_LOG_MARTIANS = 11
IPV4_DEVCONF_TAG = 12
IPV4_DEVCONF_ARPFILTER = 13
IPV4_DEVCONF_MEDIUM_ID = 14
IPV4_DEVCONF_NOXFRM = 15
IPV4_DEVCONF_NOPOLICY = 16
IPV4_DEVCONF_FORCE_IGMP_VERSION = 17
IPV4_DEVCONF_ARP_ANNOUNCE = 18
IPV4_DEVCONF_ARP_IGNORE = 19
IPV4_DEVCONF_PROMOTE_SECONDARIES = 20
IPV4_DEVCONF_ARP_ACCEPT = 21
IPV4_DEVCONF_ARP_NOTIFY = 22
IPV4_DEVCONF_ACCEPT_LOCAL = 23
IPV4_DEVCONF_SRC_VMARK = 24
IPV4_DEVCONF_PROXY_ARP_PVLAN = 25
IPV4_DEVCONF_ROUTE_LOCALNET = 26
#not for 3.11
#IPV4_DEVCONF_IGMPV2_UNSOLICITED_REPORT_INTERVAL = 27 
#IPV4_DEVCONF_IGMPV3_UNSOLICITED_REPORT_INTERVAL = 28 

ipv4_devconf = (
        ("forwarding", "I"),
        ("mc_forwarding", "I"),
        ("proxy_arp", "I"), 
        ("accept_redirects", "I"),
        ("secure_redirects", "I"),
        ("send_redirects", "I"),
        ("shared_media", "I"), 
        ("rp_filter", "I"),
        ("accept_source_route", "I"), 
        ("bootp_relay", "I"),
        ("log_martians", "I"),
        ("tag", "I"),
        ("arpfilter", "I"),
        ("medium_id", "I"), 
        ("noxfrm", "I"),
        ("nopolicy", "I"),
        ("force_igmp_version", "I"), 
        ("arp_announce", "I"), 
        ("arp_ignore", "I"),
        ("promote_secondaries", "I"), 
        ("arp_accept", "I"), 
        ("arp_notify", "I"),
        ("accept_local", "I"), 
        ("src_vmark", "I"), 
        ("proxy_arp_pvlan", "I"), 
        ("route_localnet", "I"), 
        ("empty_slot", "I")
        #("gmpv2_report_interval", "I"), 
        #("gmpv3_report_interval", "I")
        ) 

def parse_ipv4_devconf(b):
    return parse_struct(b, ipv4_devconf)

def new_ipv4_devconf(d):
    return new_struct(d, ipv4_devconf)

#family 10, AF_INET6, NESTED net/ipv6/addrconf.c:4392
IFLA_INET6_UNSPEC = 0
#link flags
IFLA_INET6_FLAGS = 1
#sysctl parameters
IFLA_INET6_CONF = 2
#statistics
IFLA_INET6_STATS = 3
#MC things. What of them?
IFLA_INET6_MCAST = 4
#time values and max reasm size
IFLA_INET6_CACHEINFO = 5
#statistics (icmpv6)
IFLA_INET6_ICMP6STATS = 6
#device token
IFLA_INET6_TOKEN = 7 

#ipstats mib definitions 
IPSTATS_MIB_NUM = 0
#frequently written fields in fast path, kept in same cache line
#InReceives 
IPSTATS_MIB_INPKTS = 1
#InOctets 
IPSTATS_MIB_INOCTETS = 2	
#InDelivers 
IPSTATS_MIB_INDELIVERS = 3
#OutForwDatagrams 
IPSTATS_MIB_OUTFORWDATAGRAMS = 4
#OutRequests 
IPSTATS_MIB_OUTPKTS = 5		
#OutOctets 
IPSTATS_MIB_OUTOCTETS = 6
#other fields
#InHdrErrors 
IPSTATS_MIB_INHDRERRORS = 7
#InTooBigErrors 
IPSTATS_MIB_INTOOBIGERRORS = 8
#InNoRoutes 
IPSTATS_MIB_INNOROUTES = 9		
#InAddrErrors 
IPSTATS_MIB_INADDRERRORS = 10
#InUnknownProtos 
IPSTATS_MIB_INUNKNOWNPROTOS = 11	
#InTruncatedPkts 
IPSTATS_MIB_INTRUNCATEDPKTS = 12	
#InDiscards 
IPSTATS_MIB_INDISCARDS = 13		
#OutDiscards 
IPSTATS_MIB_OUTDISCARDS = 14
#OutNoRoutes 
IPSTATS_MIB_OUTNOROUTES = 15
#ReasmTimeout 
IPSTATS_MIB_REASMTIMEOUT = 16
#ReasmReqds 
IPSTATS_MIB_REASMREQDS = 17	
#ReasmOKs 
IPSTATS_MIB_REASMOKS = 18
#ReasmFails 
IPSTATS_MIB_REASMFAILS = 19	
#FragOKs 
IPSTATS_MIB_FRAGOKS = 20
#FragFails 
IPSTATS_MIB_FRAGFAILS = 21	
#FragCreates 
IPSTATS_MIB_FRAGCREATES = 22		
#InMcastPkts 
IPSTATS_MIB_INMCASTPKTS = 23
#OutMcastPkts 
IPSTATS_MIB_OUTMCASTPKTS = 24
#InBcastPkts 
IPSTATS_MIB_INBCASTPKTS = 25
#OutBcastPkts 
IPSTATS_MIB_OUTBCASTPKTS = 26
#InMcastOctets 
IPSTATS_MIB_INMCASTOCTETS = 27
#OutMcastOctets 
IPSTATS_MIB_OUTMCASTOCTETS = 28
#InBcastOctets 
IPSTATS_MIB_INBCASTOCTETS = 29	
#OutBcastOctets 
IPSTATS_MIB_OUTBCASTOCTETS = 30
#InCsumErrors 
IPSTATS_MIB_CSUMERRORS = 31	
#not for 3.11
#InNoECTPkts 
#IPSTATS_MIB_NOECTPKTS = 32	
#InECT1Pkts 
#IPSTATS_MIB_ECT1PKTS = 33	
#InECT0Pkts 
#IPSTATS_MIB_ECT0PKTS = 34
#InCEPkts 
#IPSTATS_MIB_CEPKTS = 35		

ipstats_mib = (
        ("num", "Q"),
        ("inpkts", "Q"),
        ("inoctets", "Q"),
        ("indelivers", "Q"),
        ("outforwdatagrams", "Q"),
        ("outpkts", "Q"),
        ("outoctets", "Q"),
        ("inhdrerrors", "Q"),
        ("intoobigerrors", "Q"),
        ("innoroutes", "Q"),
        ("inaddrerrors", "Q"),
        ("inunknownprotos", "Q"),
        ("intruncatedpkts", "Q"),
        ("indiscards", "Q"),
        ("outdiscards", "Q"),
        ("outnoroutes", "Q"),
        ("reasmtimeout", "Q"),
        ("reasmreqds", "Q"),
        ("reasmoks", "Q"),
        ("reasmfails", "Q"),
        ("fragoks", "Q"),
        ("fragfails", "Q"),
        ("fragcreates", "Q"),
        ("inmcastpkts", "Q"),
        ("outmcastpkts", "Q"),
        ("inbcastpkts", "Q"),
        ("outbcastpkts", "Q"),
        ("inmcastoctets", "Q"),
        ("outmcastoctets", "Q"),
        ("inbcastoctets", "Q"),
        ("outbcastoctets", "Q"),
        ("csumerrors", "Q"),
        #("noectpkts", "Q"),
        #("ect1pkts", "Q"),
        #("ect0pkts", "Q"),
        #("cepkts", "Q"),
        )


def parse_ipstats_mib(b):
    return parse_struct(b, ipstats_mib)

def new_ipstats_mib(d):
    return new_struct(d, ipstats_mib)


ICMP_MIB_NUM = 0
#InMsgs 
ICMP_MIB_INMSGS	 = 1
#InErrors 
ICMP_MIB_INERRORS = 2		
#InDestUnreachs 
ICMP_MIB_INDESTUNREACHS = 3
#InTimeExcds 
ICMP_MIB_INTIMEEXCDS = 4	
#InParmProbs 
ICMP_MIB_INPARMPROBS = 5
#InSrcQuenchs 
ICMP_MIB_INSRCQUENCHS = 6	
#InRedirects 
ICMP_MIB_INREDIRECTS = 7	
#InEchos 
ICMP_MIB_INECHOS = 8	
#InEchoReps 
ICMP_MIB_INECHOREPS	 = 9
#InTimestamps 
ICMP_MIB_INTIMESTAMPS = 10
#InTimestampReps 
ICMP_MIB_INTIMESTAMPREPS = 11
#InAddrMasks 
ICMP_MIB_INADDRMASKS = 12
#InAddrMaskReps 
ICMP_MIB_INADDRMASKREPS	 = 13
#OutMsgs 
ICMP_MIB_OUTMSGS = 14
#OutErrors 
ICMP_MIB_OUTERRORS	= 15
#OutDestUnreachs 
ICMP_MIB_OUTDESTUNREACHS = 16
#OutTimeExcds 
ICMP_MIB_OUTTIMEEXCDS = 17
#OutParmProbs 
ICMP_MIB_OUTPARMPROBS = 18
#OutSrcQuenchs 
ICMP_MIB_OUTSRCQUENCHS = 19
#OutRedirects 
ICMP_MIB_OUTREDIRECTS = 20	
#OutEchos 
ICMP_MIB_OUTECHOS = 21	
#OutEchoReps 
ICMP_MIB_OUTECHOREPS = 22
#OutTimestamps 
ICMP_MIB_OUTTIMESTAMPS= 23
#OutTimestampReps 
ICMP_MIB_OUTTIMESTAMPREPS = 24
#OutAddrMasks 
ICMP_MIB_OUTADDRMASKS = 25	
#OutAddrMaskReps 
ICMP_MIB_OUTADDRMASKREPS = 26	
#InCsumErrors 
ICMP_MIB_CSUMERRORS = 27

icmp_mib = ( 
        ("num", "Q"),
        ("inmsgs        ", "Q"),
        ("inerrors", "Q"),
        ("indestunreachs", "Q"),
        ("intimeexcds", "Q"),
        ("inparmprobs", "Q"),
        ("insrcquenchs", "Q"),
        ("inredirects", "Q"),
        ("inechos", "Q"),
        ("inechoreps    ", "Q"),
        ("intimestamps", "Q"),
        ("intimestampreps", "Q"),
        ("inaddrmasks", "Q"),
        ("inaddrmaskreps        ", "Q"),
        ("outmsgs", "Q"),
        ("outerrors     ", "Q"),
        ("outdestunreachs", "Q"),
        ("outtimeexcds", "Q"),
        ("outparmprobs", "Q"),
        ("outsrcquenchs", "Q"),
        ("outredirects", "Q"),
        ("outechos", "Q"),
        ("outechoreps", "Q"),
        ("outtimestamps", "Q"),
        ("outtimestampreps", "Q"),
        ("outaddrmasks", "Q"),
        ("outaddrmaskreps", "Q"),
        ("csumerrors", "Q"),
        )

def parse_icmp_mib(b):
    return parse_struct(b, icmp_mib)

def new_icmp_mib(d):
    return new_struct(d, icmp_mib) 


ICMP6_MIB_NUM = 0
#InMsgs
ICMP6_MIB_INMSGS = 1
#InErrors
ICMP6_MIB_INERRORS = 2
#OutMsgs
ICMP6_MIB_OUTMSGS = 3
#OutErrors
ICMP6_MIB_OUTERRORS = 4
#InCsumErrors
ICMP6_MIB_CSUMERRORS = 5

icmp6_mib = (
        ("num", "Q"),
        ("inmsgs", "Q"),
        ("inerrors", "Q"),
        ("outmsgs", "Q"),
        ("outerrors", "Q"),
        ("csumerrors", "Q")
        )

def parse_icmp6_mib(b):
    return parse_struct(b, icmp6_mib)

def new_icmp6_mib(d):
    return new_struct(d, icmp6_mib) 


in6_addr = (
        ("part1", "I"),
        ("part2", "I"),
        ("part3", "I"),
        ("part4", "I")
        )

def parse_in6_addr(b):
    return parse_struct(b, in6_addr)

def new_in6_addr(b):
    return new_struct(d, in6_addr)


DEVCONF_FORWARDING = 0
DEVCONF_HOPLIMIT = 1
DEVCONF_MTU6 = 2
DEVCONF_ACCEPT_RA = 3
DEVCONF_ACCEPT_REDIRECTS = 4
DEVCONF_AUTOCONF = 5
DEVCONF_DAD_TRANSMITS = 6
DEVCONF_RTR_SOLICITS = 7
DEVCONF_RTR_SOLICIT_INTERVAL = 8
DEVCONF_RTR_SOLICIT_DELAY = 9
DEVCONF_USE_TEMPADDR = 10
DEVCONF_TEMP_VALID_LFT = 11
DEVCONF_TEMP_PREFERED_LFT = 12
DEVCONF_REGEN_MAX_RETRY = 13
DEVCONF_MAX_DESYNC_FACTOR = 14
DEVCONF_MAX_ADDRESSES = 15
DEVCONF_FORCE_MLD_VERSION = 16
DEVCONF_ACCEPT_RA_DEFRTR = 17
DEVCONF_ACCEPT_RA_PINFO = 18
DEVCONF_ACCEPT_RA_RTR_PREF = 19
DEVCONF_RTR_PROBE_INTERVAL = 20
DEVCONF_ACCEPT_RA_RT_INFO_MAX_PLEN = 21
DEVCONF_PROXY_NDP = 22
DEVCONF_OPTIMISTIC_DAD = 23
DEVCONF_ACCEPT_SOURCE_ROUTE = 24
DEVCONF_MC_FORWARDING = 25
DEVCONF_DISABLE_IPV6 = 26
DEVCONF_ACCEPT_DAD = 27
DEVCONF_FORCE_TLLAO = 28
DEVCONF_NDISC_NOTIFY = 29
#not for 3.11
#DEVCONF_MLDV1_UNSOLICITED_REPORT_INTERVAL = 30
#DEVCONF_MLDV2_UNSOLICITED_REPORT_INTERVAL = 31
#DEVCONF_SUPPRESS_FRAG_NDISC = 32

ipv6_devconf = (
            ("forwarding", "I"),
            ("hoplimit", "I"),
            ("mtu6", "I"),
            ("accept_ra", "I"),
            ("accept_redirects", "I"),
            ("autoconf", "I"),
            ("dad_transmits", "I"),
            ("rtr_solicits", "I"),
            ("rtr_solicit_interval", "I"),
            ("rtr_solicit_delay", "I"),
            ("use_tempaddr", "I"),
            ("temp_valid_lft", "I"),
            ("temp_prefered_lft", "I"),
            ("regen_max_retry", "I"),
            ("max_desync_factor", "I"),
            ("max_addresses", "I"),
            ("force_mld_version", "I"),
            ("accept_ra_defrtr", "I"),
            ("accept_ra_pinfo", "I"),
            ("accept_ra_rtr_pref", "I"),
            ("rtr_probe_interval", "I"),
            ("accept_ra_rt_info_max_plen", "I"),
            ("proxy_ndp", "I"),
            ("optimistic_dad", "I"),
            ("accept_source_route", "I"),
            ("mc_forwarding", "I"),
            ("disable_ipv6", "I"),
            ("accept_dad", "I"),
            ("force_tllao", "I"),
            ("ndisc_notify", "I"),
            #("mldv1_report_interval", "I"),
            #("mldv2_report_interval", "I"),
            #("suppress_frag_ndisc", "I")
        ) 

def parse_ipv6_devconf(b):
    return parse_struct(b, ipv6_devconf)

def new_ipv6_devconf(d):
    return new_struct(d, ipv6_devconf)

ifla_cache_info = (
        ("max_reasm_len", "I"),
        ("tstamp", "I"),
        ("reachable_time", "I"),
        ("retrans_time", "I")
        )

def parse_cacheinfo(b):
    return parse_struct(b, ifla_cache_info)

def new_cacheinfo(d):
    return new_struct(d, ifla_cache_info)



ipv6_attr_policy = {
        IFLA_INET6_FLAGS: ("flags", NLA_U32, parse_policy_u32), 
        IFLA_INET6_CACHEINFO: ("cacheinfo", NLA_STRUCT, parse_cacheinfo),
        IFLA_INET6_CONF: ("conf", NLA_STRUCT, parse_ipv6_devconf),
        IFLA_INET6_STATS: ("stats", NLA_STRUCT, parse_ipstats_mib),
        IFLA_INET6_ICMP6STATS: ("icmp6stats", NLA_STRUCT, parse_icmp6_mib),
        IFLA_INET6_TOKEN: ("token", NLA_STRUCT, parse_in6_addr)
        } 


#for INET_DIAG, attrs
INET_DIAG_NONE = 0
INET_DIAG_MEMINFO = 1
INET_DIAG_INFO = 2
INET_DIAG_VEGASINFO = 3
INET_DIAG_CONG = 4
INET_DIAG_TOS = 5
INET_DIAG_TCLASS = 6
INET_DIAG_SKMEMINFO = 7
INET_DIAG_SHUTDOWN = 8


"""
Bytecode is sequence of 4 byte commands followed by variable arguments.
All the commands identified by "code" are conditional jumps forward:
to offset cc+"yes" or to offset cc+"no". 
"yes" is supposed to be
length of the command and its arguments.  
"""
diag_bc_op = (
        ("code", "B"),
        ("yes", "B"),
        ("no", "H")
        )

INET_DIAG_BC_NOP = 0
INET_DIAG_BC_JMP = 1
INET_DIAG_BC_S_GE = 2
INET_DIAG_BC_S_LE = 3
INET_DIAG_BC_D_GE = 4
INET_DIAG_BC_D_LE = 5
INET_DIAG_BC_AUTO = 6
INET_DIAG_BC_S_COND = 7
INET_DIAG_BC_D_COND = 8 
"""
diag_hostcond = (
        ("family", "B"),
        ("prefix_len", "B"),
        ("port", "I"), 
        )
followed by _be32 addr[0]
"""

inet_diag_meminfo = (
        ("rmem", "I"),
        ("wmem", "I"),
        ("fmem", "I"),
        ("tmem", "I")
        )

inet_tcpvegas_info = (
        ("enabeld", "I"),
        ("rttcnt", "I"),
        ("rtt", "I"),
        ("minrtt", "I")
        )


#for PACKET_DIAG, padiag_show
PACKET_SHOW_INFO = 0x1
PACKET_SHOW_MCLIST = 0x2
PACKET_SHOW_RING_CFG = 0x4
PACKET_SHOW_FANOUT = 0x8
PACKET_SHOW_MEMINFO = 0x10
PACKET_SHOW_FILTER = 0x20


#for PACKET_DIAG, attrs
PACKET_DIAG_INFO = 0
PACKET_DIAG_MCLIST = 1
PACKET_DIAG_RX_RING = 2
PACKET_DIAG_TX_RING = 3
PACKET_DIAG_FANOUT = 4
PACKET_DIAG_UID = 5
PACKET_DIAG_MEMINFO = 6
PACKET_DIAG_FILTER = 7 

packet_diag_info = (
        ("index", "I"),
        ("version", "I"),
        ("reserve", "I"),
        ("copy_thresh", "I"),
        ("tstamp", "I"),
        ("flags", "I")
        )

PDI_RUNNING = 0x1
PDI_AUXDATA = 0x2
PDI_ORIGDEV = 0x4
PDI_VNETHDR = 0x8
PDI_LOSS = 0x10


packet_diag_mclist = (
        ("block_size", "I"),
        ("block_nr", "I"),
        ("frame_size", "I"),
        ("frame_nr", "I"),
        ("retire_tmo", "I"),
        ("sizeof_priv", "I"),
        ("features", "I")
        )

#for UNIX_DIAG udiag_show
#show name (not path)
UDIAG_SHOW_NAME = 0x1
#show VFS inode info
UDIAG_SHOW_VFS = 0x2
#show peer socket info
UDIAG_SHOW_PEER = 0x4
#show pending connections
UDIAG_SHOW_ICONS = 0x8
#show skb receive queue len
UDIAG_SHOW_RQLEN = 0x10
#show memory info of a socket
UDIAG_SHOW_MEMINFO = 0x20

UNIX_DIAG_NAME = 0
UNIX_DIAG_VFS = 1
UNIX_DIAG_PEER = 2
UNIX_DIAG_ICONS = 3
UNIX_DIAG_RQLEN = 4
UNIX_DIAG_MEMINFO = 5
UNIX_DIAG_SHUTDOWN = 6

unix_diag_vfs = (
        ("vfs_ino", "I"),
        ("vfs_dev", "I")
        )

unix_diag_rqlen = ( 
        ("rqueue", "I"),
        ("wqueue", "I")
        )

def parse_struct(b, fmt): 
    d = {}
    fmts = "".join([x[1] for x in fmt])
    raw = b.read(struct.calcsize(fmts)) 
    raw = struct.unpack(fmts, raw)   
    for i, item in enumerate(fmt):
        d[item[0]]= raw[i]
    return d 


def new_struct(d, fmt): 
    l = []
    fmts = "".join([x[1] for x in fmt]) 
    for i in fmt:    
        l.append(d[i[0]])
    return struct.pack(fmts, *l) 

def new_conn(proto): 
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, proto) 
    s.bind((0, 0))
    return s

nlmsg = ( 
        ("len", "I"),
        ("type", "H"),
        ("flags", "H"),
        ("seq", "I"), 
        ("pid", "I")
    ) 

def new_nlmsg(tp,  payload, seq, flags=F_REQUEST, pid=0):
    return new_struct({
        "len": 16 + len(payload),
        "type": tp,
        "flags": flags,
        "seq": seq,
        "pid": pid
        }, nlmsg) + payload

def parse_nlmsg(b):
    return parse_struct(b, nlmsg) 

nlattr = (
        ("len", "H"),
        ("type", "H")
        )

def newnlattr(tp, payload):
    x = new_struct({
        "len": 4 + len(payload),
        "type": tp
        }, nlattr) + payload 
    l = len(x)
    #padding, align 4
    if l % 4:
        return x + "\x00" * (4 - l % 4)
    return x

def parse_nlattr(b): 
    at = parse_struct(b, nlattr)
    prev = b.tell()
    at["payload"] = b.read(at["len"] - 4)
    mark = b.tell() 
    #align 4 
    if mark % 4:
        b.seek(4 - (mark % 4), io.SEEK_CUR) 
    return at 

def parse_nested(attr):
    b = cStringIO.StringIO(attr["payload"])
    tlen = attr["len"] - 4
    attrs = []
    while b.tell() < tlen:
        attr = parse_nlattr(b) 
        attrs.append(attr)
    b.close()
    return attrs 

def parse_attrs(b, mlen): 
    attrs = [] 
    while b.tell() < mlen:
        attr = parse_nlattr(b) 
        attrs.append(attr)
    return attrs 


def new_route():
    return new_conn(socket.NETLINK_ROUTE) 


ifinfo = ( 
        ("family", "B"),
        ("pad", "B"),
        ("type", "H"),
        ("index", "i"),
        ("flags", "I"),
        ("change", "I")
        ) 

def new_ifinfo(d):
    return new_struct(d, ifinfo)


def parse_ifinfo(b):
    return parse_struct(b, ifinfo)


def route_getlink(index, seq):
    payload = new_ifinfo({
        "family": 0,
        "pad": 0,
        "type": 0,
        "index": index,
        "flags": 0,
        "change": 0
        }) 
    hdr = new_nlmsg(RTM_GETLINK, payload, seq)
    return hdr


#IFA_ADDRESS is prefix address 
IFA_ADDRESS = 1
IFA_LOCAL = 2
IFA_LABEL = 3
IFA_BROADCAST = 4
IFA_ANYCAST = 5
IFA_CACHEINFO = 6
IFA_MULTICAST = 7
IFA_FLAGS = 8

#ifa_flags 
IFA_F_SECONDARY = 0x1
IFA_F_NODAD	= 0x02
IFA_F_OPTIMISTIC = 0x04
IFA_F_DADFAILED	= 0x08
IFA_F_HOMEADDRESS = 0x10
IFA_F_DEPRECATED = 0x20
IFA_F_TENTATIVE	= 0x40
IFA_F_PERMANENT	= 0x80
IFA_F_MANAGETEMPADDR = 0x100
IFA_F_NOPREFIXROUTE	= 0x200

ifa_cacheinfo = (
        ("prefered", "I"),
        ("valid", "I"),
        ("cstamp", "I"),
        ("tstamp", "I")
        ) 

ifaddr = (
        ("family", "B"),
        ("prefixlen", "B"),
        ("flags", "B"),
        ("scope", "B"),
        ("index", "I")
        )

def new_addr(d):
    return new_struct(d, ifaddr)


def parse_ifaddr(b):
    return parse_struct(b, ifaddr)


def route_getaddr(family, seq): 
    hdr = new_nlmsg(RTM_GETADDR, chr(family), seq, flags=F_REQUEST|F_DUMP)
    return hdr 



netlink_diag_req = (
        ("family", "B"),
        ("protocol", "B"),
        ("pad", "H"),
        ("ino", "I"),
        ("show", "I"),
        ("cookie", "Q")
        )

def new_netlink_diag_req(d):
    return new_struct(d, netlink_diag_req)


def parse_netlink_diag_req(b):
    return parse_struct(b, netlink_diag_req)


netlink_diag_msg = (
        ("family", "B"),
        ("type", "B"),
        ("protocol", "B"), 
        ("state", "B"),
        ("portid", "I"),
        ("dst_portid", "I"),
        ("dst_group", "I"),
        ("ino", "I"),
        ("cookie0", "I"),
        ("cookie1", "I")
        )

def new_netlink_diag_msg(d):
    return new_struct(d, netlink_diag_msg)


def parse_netlink_diag_msg(b):
    return parse_struct(b, netlink_diag_msg) 


packet_diag_req = (
        ("family", "B"),
        ("protocol", "B"),
        ("pad", "H"),
        ("ino", "I"), 
        ("show", "I"),
        ("cookie0", "I"),
        ("cookie1", "I")
        )

def new_packet_diag_req(d):
    return new_struct(d, packet_diag_req)

def parse_packet_diag_req(b):
    return parse_struct(b, packet_diag_req)

packet_diag_msg = (
        ("family", "B"),
        ("protocol", "B"),
        ("num", "H"),
        ("ino", "I"),
        ("cookie0", "I"),
        ("cookie1", "I")
        ) 


def new_packet_diag_msg(d):
    return new_struct(d, packet_diag_msg)


def parse_packet_diag_msg(b):
    return parse_struct(b, packet_diag_msg)


diag_req_v2 = ( 
        ("family", "B"),
        ("protocol", "B"),
        ("ext", "B"),
        ("pad", "B"),
        ("states", "I")
        )

def new_inet_diag_req(d):
    return new_struct(d, diag_req_v2) + new_sockid({
        "sport": 0,
        "dport": 0,
        "src": (0, 0, 0, 0),
        "dst": (0, 0, 0, 0),
        "if": 0,
        "cookie": (0, 0)
        })


def parse_diag_req(b): 
    fi = parse_struct(b, diag_req)
    la = parse_sockid(b)
    fi["id"] = la
    return fi 


diag_sockid = (
        ("sport", ">H"),
        ("dport", ">H"),
        ("src", ">IIII"),
        ("dst", ">IIII"),
        ("if", "I"),
        ("cookie", "II") 
        ) 

def new_sockid(d):
    l = []
    l.append(struct.pack(diag_sockid[0][1], d["sport"]))
    l.append(struct.pack(diag_sockid[1][1], d["dport"]))
    l.append(struct.pack(diag_sockid[2][1], *d["src"]))
    l.append(struct.pack(diag_sockid[3][1], *d["dst"]))
    l.append(struct.pack(diag_sockid[4][1], d["if"]))
    l.append(struct.pack(diag_sockid[5][1], *d["cookie"])) 
    return "".join(l)
        

def parse_sockid(b):
    sport = struct.unpack(">H", b.read(2))[0]
    dport = struct.unpack(">H", b.read(2))[0]
    src = struct.unpack(">IIII", b.read(16))
    dst = struct.unpack(">IIII", b.read(16))
    if_ = struct.unpack("I", b.read(4))[0]
    cookie = struct.unpack("II", b.read(8))
    return {
        "sport": sport,
        "dport": dport,
        "src": src,
        "dst": dst,
        "if": if_,
        "cookie": cookie,
            } 
    


inet_diag_msg_top_half = (
        ("family", "B"),
        ("state", "B"),
        ("timer", "B"),
        ("retrans", "B")
        )

inet_diag_msg_bottom_half = (
        ("expires", "I"),
        ("rqueue", "I"),
        ("wqueue", "I"),
        ("uid", "I"),
        ("inode", "I")
        ) 


def new_inet_diag_msg(d):
    return new_struct(d, inet_diag_msg_top_half) + new_sockid(d) + new_struct(d, inet_diag_msg_bottom_half)


def parse_inet_diag_msg(b): 
    d = {}
    d.update(parse_struct(b, inet_diag_msg_top_half))
    d.update(parse_sockid(b))
    d.update(parse_struct(b, inet_diag_msg_bottom_half))
    return d


unix_diag_req = (
        ("family", "B"),
        ("protocol", "B"),
        ("pad", "H"),
        ("states", "I"),
        ("ino", "I"),
        ("show", "I"),
        ("cookie0", "I"),
        ("cookie1", "I")
        )

def new_unix_diag_req(d):
    return new_struct(d, unix_diag_req)

def parse_unix_diag_req(b):
    return parse_struct(b, unix_diag_req)

unix_diag_msg = (
        ("family", "B"),
        ("type", "B"),
        ("state", "B"),
        ("pad", "B"),
        ("ino", "I"),
        ("cookie0", "I"),
        ("cookie1", "I")
        )

def new_unix_diag_msg(d):
    return new_struct(d, unix_diag_msg)

def parse_unix_diag_msg(b):
    return parse_struct(b, unix_diag_msg) 

def new_sock_diag():
    return new_conn(NETLINK_SOCK_DIAG)

def sock_diag(payload, seq): 
    hdr = new_nlmsg(SOCK_DIAG_BY_FAMILY, payload, seq, flags=F_REQUEST|F_DUMP) 
    return hdr 

#list of reserved static generic netlink identifiers
GENL_ID_GENERATE = 0
GENL_ID_CTRL =  MIN_TYPE
GENL_ID_VFS_DQUOT = MIN_TYPE + 1
GENL_ID_PMCRAID = MIN_TYPE + 2

def new_generic():
    return new_conn(NETLINK_GENERIC)

def generic_id_ctrl(payload, seq):
    hdr = new_nlmsg(GENL_ID_CTRL, payload, seq, flags=F_REQUEST|F_DUMP)
    return hdr

#tmp, 25 for nl80211
def generic_wireless(payload, seq):
    hdr = new_nlmsg(25, payload, seq, flags=F_REQUEST|F_DUMP)
    return hdr

def atod(msgs, policy):
    ret = {}
    for m in msgs: 
        name, tp, parser = policy[m["type"]] 
        if tp == NLA_NESTED: 
            ret[name] = parser(m)
        elif tp == NLA_STRUCT:
            b = cStringIO.StringIO(m["payload"])
            result = parser(b) 
            ret[name] = result
        else: 
            ret[name] = parser(m["payload"])
    return ret


CTRL_CMD_UNSPEC = 0
CTRL_CMD_NEWFAMILY = 1
CTRL_CMD_DELFAMILY = 2
CTRL_CMD_GETFAMILY = 3
CTRL_CMD_NEWOPS = 4
CTRL_CMD_DELOPS = 5
CTRL_CMD_GETOPS = 6
CTRL_CMD_NEWMCAST_GRP = 7
CTRL_CMD_DELMCAST_GRP = 8
CTRL_CMD_GETMCAST_GRP = 9


CTRL_ATTR_UNSPEC = 0
CTRL_ATTR_FAMILY_ID = 1
CTRL_ATTR_FAMILY_NAME = 2
CTRL_ATTR_VERSION = 3
CTRL_ATTR_HDRSIZE = 4
CTRL_ATTR_MAXATTR = 5
CTRL_ATTR_OPS = 6
CTRL_ATTR_MCAST_GROUPS = 7


def parse_genl_ops(attr):
    attrs = parse_nested(attr)
    ret = []
    for m in attrs:
        x = {}
        op_id, op_flags = parse_nested(m) 
        name1, _, parser1 = ctrl_attr_op_policy[op_id["type"]]  
        name2, _, parser2 = ctrl_attr_op_policy[op_flags["type"]]
        x["op_id"] = parser1(op_id["payload"])
        x["op_flags"] = parser2(op_id["payload"])
        ret.append(x) 
    return ret

def parse_mcast_groups(attr): 
    attrs = parse_nested(attr)
    ret = []
    for m in attrs:
        x = {}
        grp_id, grp_name = parse_nested(m)
        name1, _, parser1 = ctrl_attr_mcast_policy[grp_id["type"]]
        name2, _, parser2 = ctrl_attr_mcast_policy[grp_name["type"]]
        x["grp_id"] = parser1(grp_id["payload"])
        x["grp_name"] = parser2(grp_name["payload"])
        ret.append(x)
    return ret

ctrl_attr_policy = {
        CTRL_ATTR_FAMILY_NAME: ("family_name", NLA_STRING, parse_policy_string),        
        CTRL_ATTR_FAMILY_ID: ("family_id", NLA_U16, parse_policy_u16),
        CTRL_ATTR_VERSION: ("version", NLA_U32, parse_policy_u32),
        CTRL_ATTR_HDRSIZE: ("hdrsize", NLA_U32, parse_policy_u32),
        CTRL_ATTR_MAXATTR: ("maxattr", NLA_U32, parse_policy_u32),
        CTRL_ATTR_OPS: ("ops", NLA_NESTED, parse_genl_ops),
        CTRL_ATTR_MCAST_GROUPS: ("mcast_groups", NLA_NESTED, parse_mcast_groups)
        } 

#all avaible ops -> cmd
CTRL_ATTR_OP_ID = 1
CTRL_ATTR_OP_FLAGS = 2

ctrl_attr_op_policy = {
        CTRL_ATTR_OP_ID: ("op_id", NLA_U32, parse_policy_u32),
        CTRL_ATTR_OP_FLAGS: ("op_flags", NLA_U32, parse_policy_u32)
        }

CTRL_ATTR_MCAST_GRP_NAME = 1
CTRL_ATTR_MCAST_GRP_ID = 2

ctrl_attr_mcast_policy = {
        CTRL_ATTR_MCAST_GRP_ID: ("grp_id", NLA_U32, parse_policy_u32),
        CTRL_ATTR_MCAST_GRP_NAME: ("grp_name", NLA_STRING, parse_policy_string)
        }

#op flags
GENL_ADMIN_PERM = 0x01
GENL_CMD_CAP_DO = 0x02
GENL_CMD_CAP_DUMP = 0x04
GENL_CMD_CAP_HASPOL = 0x08

genlmsg = (
        ("cmd", "B"),
        ("version", "B"),
        ("reserved", "H")
        )

def parse_genlmsg(b):
    return parse_struct(b, genlmsg)

def new_genlmsg(d):
    return new_struct(d, genlmsg) 

#nl80211.h
#for wireless, ABI, don't change this 
NL80211_CMD_UNSPEC = 0
#can dump
NL80211_CMD_GET_WIPHY = 1
NL80211_CMD_SET_WIPHY = 2
NL80211_CMD_NEW_WIPHY = 3
NL80211_CMD_DEL_WIPHY = 4
#can dump
NL80211_CMD_GET_INTERFACE = 5
NL80211_CMD_SET_INTERFACE = 6
NL80211_CMD_NEW_INTERFACE = 7
NL80211_CMD_DEL_INTERFACE = 8

NL80211_CMD_GET_KEY = 9
NL80211_CMD_SET_KEY = 10
NL80211_CMD_NEW_KEY = 11
NL80211_CMD_DEL_KEY = 12

NL80211_CMD_GET_BEACON = 13
NL80211_CMD_SET_BEACON = 14
NL80211_CMD_START_AP = 15
NL80211_CMD_STOP_AP = 16

NL80211_CMD_GET_STATION = 17
NL80211_CMD_SET_STATION = 18
NL80211_CMD_NEW_STATION = 19
NL80211_CMD_DEL_STATION = 20

NL80211_CMD_GET_MPATH = 21
NL80211_CMD_SET_MPATH = 22
NL80211_CMD_NEW_MPATH = 23
NL80211_CMD_DEL_MPATH = 24

NL80211_CMD_SET_BSS = 25
NL80211_CMD_SET_REG = 26
NL80211_CMD_REQ_SET_REG = 27

NL80211_CMD_GET_MESH_CONFIG = 28
NL80211_CMD_SET_MESH_CONFIG = 29
#reserved; not used
NL80211_CMD_SET_MGMT_EXTRA_IE = 30

NL80211_CMD_GET_REG = 31

NL80211_CMD_GET_SCAN = 32
NL80211_CMD_TRIGGER_SCAN = 33
NL80211_CMD_NEW_SCAN_RESULTS = 34
NL80211_CMD_SCAN_ABORTED = 35

NL80211_CMD_REG_CHANGE = 36

NL80211_CMD_AUTHENTICATE = 37
NL80211_CMD_ASSOCIATE = 38
NL80211_CMD_DEAUTHENTICATE = 39
NL80211_CMD_DISASSOCIATE = 40

NL80211_CMD_MICHAEL_MIC_FAILURE = 41

NL80211_CMD_REG_BEACON_HINT = 42

NL80211_CMD_JOIN_IBSS = 43
NL80211_CMD_LEAVE_IBSS = 44

NL80211_CMD_TESTMODE = 45

NL80211_CMD_CONNECT = 46
NL80211_CMD_ROAM = 47
NL80211_CMD_DISCONNECT = 48

NL80211_CMD_SET_WIPHY_NETNS = 49

NL80211_CMD_GET_SURVEY = 50
NL80211_CMD_NEW_SURVEY_RESULTS = 51

NL80211_CMD_SET_PMKSA = 52
NL80211_CMD_DEL_PMKSA = 53
NL80211_CMD_FLUSH_PMKSA = 54

NL80211_CMD_REMAIN_ON_CHANNEL = 55 
NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL = 56

NL80211_CMD_SET_TX_BITRATE_MASK = 57

NL80211_CMD_REGISTER_FRAME = 58
NL80211_CMD_FRAME = 59
NL80211_CMD_FRAME_TX_STATUS = 60

NL80211_CMD_SET_POWER_SAVE = 61
NL80211_CMD_GET_POWER_SAVE = 62

NL80211_CMD_SET_CQM = 63
NL80211_CMD_NOTIFY_CQM = 64

NL80211_CMD_SET_CHANNEL = 65
NL80211_CMD_SET_WDS_PEER = 66

NL80211_CMD_FRAME_WAIT_CANCEL = 67

NL80211_CMD_JOIN_MESH = 68
NL80211_CMD_LEAVE_MESH = 69

NL80211_CMD_UNPROT_DEAUTHENTICATE = 70
NL80211_CMD_UNPROT_DISASSOCIATE = 71

NL80211_CMD_NEW_PEER_CANDIDATE = 72

NL80211_CMD_GET_WOWLAN = 73
NL80211_CMD_SET_WOWLAN = 74

NL80211_CMD_START_SCHED_SCAN = 75
NL80211_CMD_STOP_SCHED_SCAN = 76
NL80211_CMD_SCHED_SCAN_RESULTS = 77
NL80211_CMD_SCHED_SCAN_STOPPED = 78

NL80211_CMD_SET_REKEY_OFFLOAD = 79

NL80211_CMD_PMKSA_CANDIDATE = 80

NL80211_CMD_TDLS_OPER = 81
NL80211_CMD_TDLS_MGMT = 82

NL80211_CMD_UNEXPECTED_FRAME = 83

NL80211_CMD_PROBE_CLIENT = 84

NL80211_CMD_REGISTER_BEACONS = 85

NL80211_CMD_UNEXPECTED_4ADDR_FRAME = 86

NL80211_CMD_SET_NOACK_MAP = 87

NL80211_CMD_CH_SWITCH_NOTIFY = 88

NL80211_CMD_START_P2P_DEVICE = 89
NL80211_CMD_STOP_P2P_DEVICE = 90

NL80211_CMD_CONN_FAILED = 91

NL80211_CMD_SET_MCAST_RATE = 92

NL80211_CMD_SET_MAC_ACL = 93

NL80211_CMD_RADAR_DETECT = 94

NL80211_CMD_GET_PROTOCOL_FEATURES = 95

NL80211_CMD_UPDATE_FT_IES = 96 
NL80211_CMD_FT_EVENT = 97

NL80211_CMD_CRIT_PROTOCOL_START = 98
NL80211_CMD_CRIT_PROTOCOL_STOP = 99

NL80211_CMD_GET_COALESCE = 100
NL80211_CMD_SET_COALESCE = 101

NL80211_CMD_CHANNEL_SWITCH = 102

NL80211_CMD_VENDOR = 103

NL80211_CMD_SET_QOS_MAP = 104 

#attrs 
NL80211_ATTR_UNSPEC = 0
NL80211_ATTR_WIPHY = 1
NL80211_ATTR_WIPHY_NAME = 2
NL80211_ATTR_IFINDEX = 3
NL80211_ATTR_IFNAME = 4
NL80211_ATTR_IFTYPE = 5
NL80211_ATTR_MAC = 6
NL80211_ATTR_KEY_DATA = 7
NL80211_ATTR_KEY_IDX = 8
NL80211_ATTR_KEY_CIPHER = 9
NL80211_ATTR_KEY_SEQ = 10
NL80211_ATTR_KEY_DEFAULT = 11
NL80211_ATTR_BEACON_INTERVAL = 12
NL80211_ATTR_DTIM_PERIOD = 13
NL80211_ATTR_BEACON_HEAD = 14
NL80211_ATTR_BEACON_TAIL = 15
NL80211_ATTR_STA_AID = 16
NL80211_ATTR_STA_FLAGS = 17
NL80211_ATTR_STA_LISTEN_INTERVAL = 18
NL80211_ATTR_STA_SUPPORTED_RATES = 19
NL80211_ATTR_STA_VLAN = 20
NL80211_ATTR_STA_INFO = 21
NL80211_ATTR_WIPHY_BANDS = 22
NL80211_ATTR_MNTR_FLAGS = 23
NL80211_ATTR_MESH_ID = 24
NL80211_ATTR_STA_PLINK_ACTION = 25
NL80211_ATTR_MPATH_NEXT_HOP = 26
NL80211_ATTR_MPATH_INFO = 27
NL80211_ATTR_BSS_CTS_PROT = 28
NL80211_ATTR_BSS_SHORT_PREAMBLE = 29                                                                             
NL80211_ATTR_BSS_SHORT_SLOT_TIME = 30                                                                            
NL80211_ATTR_HT_CAPABILITY = 31                                                                                  
NL80211_ATTR_SUPPORTED_IFTYPES = 32                                                                              
NL80211_ATTR_REG_ALPHA2 = 33                                                                                     
NL80211_ATTR_REG_RULES = 34                                                                                      
NL80211_ATTR_MESH_CONFIG = 35                                                                                    
NL80211_ATTR_BSS_BASIC_RATES = 36                                                                                
NL80211_ATTR_WIPHY_TXQ_PARAMS = 37                                                                               
NL80211_ATTR_WIPHY_FREQ = 38                                                                                     
NL80211_ATTR_WIPHY_CHANNEL_TYPE = 39
NL80211_ATTR_KEY_DEFAULT_MGMT = 40
NL80211_ATTR_MGMT_SUBTYPE = 41
NL80211_ATTR_IE = 42
NL80211_ATTR_MAX_NUM_SCAN_SSIDS = 43
NL80211_ATTR_SCAN_FREQUENCIES = 44
NL80211_ATTR_SCAN_SSIDS = 45
NL80211_ATTR_GENERATION = 46
NL80211_ATTR_BSS = 47
NL80211_ATTR_REG_INITIATOR = 48
NL80211_ATTR_REG_TYPE = 49
NL80211_ATTR_SUPPORTED_COMMANDS = 50
NL80211_ATTR_FRAME = 51
NL80211_ATTR_SSID = 52
NL80211_ATTR_AUTH_TYPE = 53
NL80211_ATTR_REASON_CODE = 54
NL80211_ATTR_KEY_TYPE = 55
NL80211_ATTR_MAX_SCAN_IE_LEN = 56
NL80211_ATTR_CIPHER_SUITES = 57
NL80211_ATTR_FREQ_BEFORE = 58
NL80211_ATTR_FREQ_AFTER = 59
NL80211_ATTR_FREQ_FIXED = 60
NL80211_ATTR_WIPHY_RETRY_SHORT = 61
NL80211_ATTR_WIPHY_RETRY_LONG = 62
NL80211_ATTR_WIPHY_FRAG_THRESHOLD = 63
NL80211_ATTR_WIPHY_RTS_THRESHOLD = 64
NL80211_ATTR_TIMED_OUT = 65
NL80211_ATTR_USE_MFP = 66
NL80211_ATTR_STA_FLAGS2 = 67
NL80211_ATTR_CONTROL_PORT = 68
NL80211_ATTR_TESTDATA = 69
NL80211_ATTR_PRIVACY = 70
NL80211_ATTR_DISCONNECTED_BY_AP = 71
NL80211_ATTR_STATUS_CODE = 72
NL80211_ATTR_CIPHER_SUITES_PAIRWISE = 73
NL80211_ATTR_CIPHER_SUITE_GROUP = 74
NL80211_ATTR_WPA_VERSIONS = 75
NL80211_ATTR_AKM_SUITES = 76
NL80211_ATTR_REQ_IE = 77
NL80211_ATTR_RESP_IE = 78
NL80211_ATTR_PREV_BSSID = 79
NL80211_ATTR_KEY = 80
NL80211_ATTR_KEYS = 81
NL80211_ATTR_PID = 82
NL80211_ATTR_4ADDR = 83
NL80211_ATTR_SURVEY_INFO = 84
NL80211_ATTR_PMKID = 85
NL80211_ATTR_MAX_NUM_PMKIDS = 86
NL80211_ATTR_DURATION = 87
NL80211_ATTR_COOKIE = 88
NL80211_ATTR_WIPHY_COVERAGE_CLASS = 89
NL80211_ATTR_TX_RATES = 90
NL80211_ATTR_FRAME_MATCH = 91
NL80211_ATTR_ACK = 92
NL80211_ATTR_PS_STATE = 93
NL80211_ATTR_CQM = 94
NL80211_ATTR_LOCAL_STATE_CHANGE = 95
NL80211_ATTR_AP_ISOLATE = 96
NL80211_ATTR_WIPHY_TX_POWER_SETTING = 97
NL80211_ATTR_WIPHY_TX_POWER_LEVEL = 98
NL80211_ATTR_TX_FRAME_TYPES = 99
NL80211_ATTR_RX_FRAME_TYPES = 100
NL80211_ATTR_FRAME_TYPE = 101
NL80211_ATTR_CONTROL_PORT_ETHERTYPE = 102
NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT = 103
NL80211_ATTR_SUPPORT_IBSS_RSN = 104
NL80211_ATTR_WIPHY_ANTENNA_TX = 105
NL80211_ATTR_WIPHY_ANTENNA_RX = 106
NL80211_ATTR_MCAST_RATE = 107
NL80211_ATTR_OFFCHANNEL_TX_OK = 108
NL80211_ATTR_BSS_HT_OPMODE = 109
NL80211_ATTR_KEY_DEFAULT_TYPES = 110
NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION = 111
NL80211_ATTR_MESH_SETUP = 112
NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX = 113
NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX = 114
NL80211_ATTR_SUPPORT_MESH_AUTH = 115
NL80211_ATTR_STA_PLINK_STATE = 116
NL80211_ATTR_WOWLAN_TRIGGERS = 117
NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED = 118
NL80211_ATTR_SCHED_SCAN_INTERVAL = 119
NL80211_ATTR_INTERFACE_COMBINATIONS = 120
NL80211_ATTR_SOFTWARE_IFTYPES = 121
NL80211_ATTR_REKEY_DATA = 122
NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS = 123
NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN = 124
NL80211_ATTR_SCAN_SUPP_RATES = 125
NL80211_ATTR_HIDDEN_SSID = 126
NL80211_ATTR_IE_PROBE_RESP = 127
NL80211_ATTR_IE_ASSOC_RESP = 128
NL80211_ATTR_STA_WME = 129
NL80211_ATTR_SUPPORT_AP_UAPSD = 130
NL80211_ATTR_ROAM_SUPPORT = 131
NL80211_ATTR_SCHED_SCAN_MATCH = 132
NL80211_ATTR_MAX_MATCH_SETS = 133
NL80211_ATTR_PMKSA_CANDIDATE = 134
NL80211_ATTR_TX_NO_CCK_RATE = 135
NL80211_ATTR_TDLS_ACTION = 136
NL80211_ATTR_TDLS_DIALOG_TOKEN = 137
NL80211_ATTR_TDLS_OPERATION = 138
NL80211_ATTR_TDLS_SUPPORT = 139
NL80211_ATTR_TDLS_EXTERNAL_SETUP = 140
NL80211_ATTR_DEVICE_AP_SME = 141
NL80211_ATTR_DONT_WAIT_FOR_ACK = 142
NL80211_ATTR_FEATURE_FLAGS = 143
NL80211_ATTR_PROBE_RESP_OFFLOAD = 144
NL80211_ATTR_PROBE_RESP = 145
NL80211_ATTR_DFS_REGION = 146
NL80211_ATTR_DISABLE_HT = 147
NL80211_ATTR_HT_CAPABILITY_MASK = 148
NL80211_ATTR_NOACK_MAP = 149
NL80211_ATTR_INACTIVITY_TIMEOUT = 150
NL80211_ATTR_RX_SIGNAL_DBM = 151
NL80211_ATTR_BG_SCAN_PERIOD = 152
NL80211_ATTR_WDEV = 153
NL80211_ATTR_USER_REG_HINT_TYPE = 154
NL80211_ATTR_CONN_FAILED_REASON = 155
NL80211_ATTR_SAE_DATA = 156
NL80211_ATTR_VHT_CAPABILITY = 157
NL80211_ATTR_SCAN_FLAGS = 158
NL80211_ATTR_CHANNEL_WIDTH = 159
NL80211_ATTR_CENTER_FREQ1 = 160
NL80211_ATTR_CENTER_FREQ2 = 161
NL80211_ATTR_P2P_CTWINDOW = 162
NL80211_ATTR_P2P_OPPPS = 163
NL80211_ATTR_LOCAL_MESH_POWER_MODE = 164
NL80211_ATTR_ACL_POLICY = 165
NL80211_ATTR_MAC_ADDRS = 166
NL80211_ATTR_MAC_ACL_MAX = 167
NL80211_ATTR_RADAR_EVENT = 168
NL80211_ATTR_EXT_CAPA = 169
NL80211_ATTR_EXT_CAPA_MASK = 170
NL80211_ATTR_STA_CAPABILITY = 171
NL80211_ATTR_STA_EXT_CAPABILITY = 172
NL80211_ATTR_PROTOCOL_FEATURES = 173
NL80211_ATTR_SPLIT_WIPHY_DUMP = 174
NL80211_ATTR_DISABLE_VHT = 175
NL80211_ATTR_VHT_CAPABILITY_MASK = 176
NL80211_ATTR_MDID = 177
NL80211_ATTR_IE_RIC = 178
NL80211_ATTR_CRIT_PROT_ID = 179
NL80211_ATTR_MAX_CRIT_PROT_DURATION = 180
NL80211_ATTR_PEER_AID = 181
NL80211_ATTR_COALESCE_RULE = 182
NL80211_ATTR_CH_SWITCH_COUNT = 183
NL80211_ATTR_CH_SWITCH_BLOCK_TX = 184
NL80211_ATTR_CSA_IES = 185
NL80211_ATTR_CSA_C_OFF_BEACON = 186
NL80211_ATTR_CSA_C_OFF_PRESP = 187
NL80211_ATTR_RXMGMT_FLAGS = 188
NL80211_ATTR_STA_SUPPORTED_CHANNELS = 189
NL80211_ATTR_STA_SUPPORTED_OPER_CLASSES = 190
NL80211_ATTR_HANDLE_DFS = 191
NL80211_ATTR_SUPPORT_5_MHZ = 192
NL80211_ATTR_SUPPORT_10_MHZ = 193
NL80211_ATTR_OPMODE_NOTIF = 194
NL80211_ATTR_VENDOR_ID = 195
NL80211_ATTR_VENDOR_SUBCMD = 196
NL80211_ATTR_VENDOR_DATA = 197
NL80211_ATTR_VENDOR_EVENTS = 198
NL80211_ATTR_QOS_MAP = 199
NL80211_ATTR_MAC_HINT = 200
NL80211_ATTR_WIPHY_FREQ_HINT = 201
NL80211_ATTR_MAX_AP_ASSOC_STA = 202
NL80211_ATTR_TDLS_PEER_CAPABILITY = 203
NL80211_ATTR_IFACE_SOCKET_OWNER = 204
NL80211_ATTR_CSA_C_OFFSETS_TX = 205
NL80211_ATTR_MAX_CSA_COUNTERS = 206

#to-do flags
nl802_attr_policy = {
    NL80211_ATTR_WIPHY: ("wiphy", NLA_U32, parse_policy_u32),
    NL80211_ATTR_WIPHY_NAME: ("wiphy_name", NLA_STRING, parse_policy_string),
    NL80211_ATTR_WIPHY_TXQ_PARAMS: ("wiphy_txq_params", NLA_NESTED, parse_policy_nested),
    NL80211_ATTR_WIPHY_FREQ: ("wiphy_freq", NLA_U32, parse_policy_u32),
    NL80211_ATTR_WIPHY_CHANNEL_TYPE: ("wiphy_channel_type", NLA_U32, parse_policy_u32),
    NL80211_ATTR_CHANNEL_WIDTH: ("channel_width", NLA_U32, parse_policy_u32),
    NL80211_ATTR_CENTER_FREQ1: ("center_freq1", NLA_U32, parse_policy_u32),
    NL80211_ATTR_CENTER_FREQ2: ("center_freq2", NLA_U32, parse_policy_u32),
    NL80211_ATTR_WIPHY_RETRY_SHORT: ("wiphy_retry_short", NLA_U8, parse_policy_u8),
    NL80211_ATTR_WIPHY_RETRY_LONG: ("wiphy_retry_long", NLA_U8, parse_policy_u8),
    NL80211_ATTR_WIPHY_FRAG_THRESHOLD: ("wiphy_frag_threshold", NLA_U32, parse_policy_u32),
    NL80211_ATTR_WIPHY_RTS_THRESHOLD: ("wiphy_rts_threshold", NLA_U32, parse_policy_u32),
    NL80211_ATTR_WIPHY_COVERAGE_CLASS: ("wiphy_coverage_class", NLA_U8, parse_policy_u8),
    NL80211_ATTR_IFTYPE: ("iftype", NLA_U32, parse_policy_u32),
    NL80211_ATTR_IFINDEX: ("ifindex", NLA_U32, parse_policy_u32),
    NL80211_ATTR_IFNAME: ("ifname", NLA_STRING, parse_policy_string),
    NL80211_ATTR_KEY: ("key", NLA_NESTED, parse_policy_nested),
    NL80211_ATTR_KEY_DATA: ("key_data", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_KEY_IDX: ("key_idx", NLA_U8, parse_policy_u8),
    NL80211_ATTR_KEY_CIPHER: ("key_cipher", NLA_U32, parse_policy_u32),
    NL80211_ATTR_KEY_DEFAULT: ("key_default", NLA_FLAG, parse_policy_flag),
    NL80211_ATTR_KEY_SEQ: ("key_seq", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_KEY_TYPE: ("key_type", NLA_U32, parse_policy_u32),
    NL80211_ATTR_BEACON_INTERVAL: ("beacon_interval", NLA_U32, parse_policy_u32),
    NL80211_ATTR_DTIM_PERIOD: ("dtim_period", NLA_U32, parse_policy_u32),
    NL80211_ATTR_BEACON_HEAD: ("beacon_head", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_BEACON_TAIL: ("beacon_tail", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_STA_AID: ("sta_aid", NLA_U16, parse_policy_u16),
    NL80211_ATTR_STA_FLAGS: ("sta_flags", NLA_NESTED, parse_policy_nested),
    NL80211_ATTR_STA_LISTEN_INTERVAL: ("sta_listen_interval", NLA_U16, parse_policy_u16),
    NL80211_ATTR_STA_SUPPORTED_RATES: ("sta_supported_rates", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_STA_PLINK_ACTION: ("sta_plink_action", NLA_U8, parse_policy_u8),
    NL80211_ATTR_STA_VLAN: ("sta_vlan", NLA_U32, parse_policy_u32),
    NL80211_ATTR_MESH_ID: ("mesh_id", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_MPATH_NEXT_HOP: ("mpath_next_hop", NLA_U32, parse_policy_u32),
    NL80211_ATTR_REG_ALPHA2: ("reg_alpha2", NLA_STRING, parse_policy_string),
    NL80211_ATTR_REG_RULES: ("reg_rules", NLA_NESTED, parse_policy_nested),
    NL80211_ATTR_BSS_CTS_PROT: ("bss_cts_prot", NLA_U8, parse_policy_u8),
    NL80211_ATTR_BSS_SHORT_PREAMBLE: ("bss_short_preamble", NLA_U8, parse_policy_u8),
    NL80211_ATTR_BSS_SHORT_SLOT_TIME: ("bss_short_slot_time", NLA_U8, parse_policy_u8),
    NL80211_ATTR_BSS_BASIC_RATES: ("bss_basic_rates", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_BSS_HT_OPMODE: ("bss_ht_opmode", NLA_U16, parse_policy_u16),
    NL80211_ATTR_MESH_CONFIG: ("mesh_config", NLA_NESTED, parse_policy_nested),
    NL80211_ATTR_SUPPORT_MESH_AUTH: ("support_mesh_auth", NLA_FLAG, parse_policy_flag),
    NL80211_ATTR_MGMT_SUBTYPE: ("mgmt_subtype", NLA_U8, parse_policy_u8),
    NL80211_ATTR_IE: ("ie", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_SCAN_FREQUENCIES: ("scan_frequencies", NLA_NESTED, parse_policy_nested),
    NL80211_ATTR_SCAN_SSIDS: ("scan_ssids", NLA_NESTED, parse_policy_nested),
    NL80211_ATTR_SSID: ("ssid", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_AUTH_TYPE: ("auth_type", NLA_U32, parse_policy_u32),
    NL80211_ATTR_REASON_CODE: ("reason_code", NLA_U16, parse_policy_u16),
    NL80211_ATTR_FREQ_FIXED: ("freq_fixed", NLA_FLAG, parse_policy_flag),
    NL80211_ATTR_TIMED_OUT: ("timed_out", NLA_FLAG, parse_policy_flag),
    NL80211_ATTR_USE_MFP: ("use_mfp", NLA_U32, parse_policy_u32),
    NL80211_ATTR_CONTROL_PORT: ("control_port", NLA_FLAG, parse_policy_flag),
    NL80211_ATTR_CONTROL_PORT_ETHERTYPE: ("control_port_ethertype", NLA_U16, parse_policy_u16),
    NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT: ("control_port_no_encrypt", NLA_FLAG, parse_policy_flag),
    NL80211_ATTR_PRIVACY: ("privacy", NLA_FLAG, parse_policy_flag),
    NL80211_ATTR_CIPHER_SUITE_GROUP: ("cipher_suite_group", NLA_U32, parse_policy_u32),
    NL80211_ATTR_WPA_VERSIONS: ("wpa_versions", NLA_U32, parse_policy_u32),
    NL80211_ATTR_PID: ("pid", NLA_U32, parse_policy_u32),
    NL80211_ATTR_4ADDR: ("4addr", NLA_U8, parse_policy_u8),
    NL80211_ATTR_PMKID: ("pmkid", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_DURATION: ("duration", NLA_U32, parse_policy_u32),
    NL80211_ATTR_COOKIE: ("cookie", NLA_U64, parse_policy_u64),
    NL80211_ATTR_TX_RATES: ("tx_rates", NLA_NESTED, parse_policy_nested),
    NL80211_ATTR_FRAME: ("frame", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_FRAME_MATCH: ("frame_match", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_PS_STATE: ("ps_state", NLA_U32, parse_policy_u32),
    NL80211_ATTR_CQM: ("cqm", NLA_NESTED, parse_policy_nested),
    NL80211_ATTR_LOCAL_STATE_CHANGE: ("local_state_change", NLA_FLAG, parse_policy_flag),
    NL80211_ATTR_AP_ISOLATE: ("ap_isolate", NLA_U8, parse_policy_u8),
    NL80211_ATTR_WIPHY_TX_POWER_SETTING: ("wiphy_tx_power_setting", NLA_U32, parse_policy_u32),
    NL80211_ATTR_WIPHY_TX_POWER_LEVEL: ("wiphy_tx_power_level", NLA_U32, parse_policy_u32),
    NL80211_ATTR_FRAME_TYPE: ("frame_type", NLA_U16, parse_policy_u16),
    NL80211_ATTR_WIPHY_ANTENNA_TX: ("wiphy_antenna_tx", NLA_U32, parse_policy_u32),
    NL80211_ATTR_WIPHY_ANTENNA_RX: ("wiphy_antenna_rx", NLA_U32, parse_policy_u32),
    NL80211_ATTR_MCAST_RATE: ("mcast_rate", NLA_U32, parse_policy_u32),
    NL80211_ATTR_OFFCHANNEL_TX_OK: ("offchannel_tx_ok", NLA_FLAG, parse_policy_flag),
    NL80211_ATTR_KEY_DEFAULT_TYPES: ("key_default_types", NLA_NESTED, parse_policy_nested),
    NL80211_ATTR_WOWLAN_TRIGGERS: ("wowlan_triggers", NLA_NESTED, parse_policy_nested),
    NL80211_ATTR_STA_PLINK_STATE: ("sta_plink_state", NLA_U8, parse_policy_u8),
    NL80211_ATTR_SCHED_SCAN_INTERVAL: ("sched_scan_interval", NLA_U32, parse_policy_u32),
    NL80211_ATTR_REKEY_DATA: ("rekey_data", NLA_NESTED, parse_policy_nested),
    NL80211_ATTR_SCAN_SUPP_RATES: ("scan_supp_rates", NLA_NESTED, parse_policy_nested),
    NL80211_ATTR_HIDDEN_SSID: ("hidden_ssid", NLA_U32, parse_policy_u32),
    NL80211_ATTR_IE_PROBE_RESP: ("ie_probe_resp", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_IE_ASSOC_RESP: ("ie_assoc_resp", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_ROAM_SUPPORT: ("roam_support", NLA_FLAG, parse_policy_flag),
    NL80211_ATTR_SCHED_SCAN_MATCH: ("sched_scan_match", NLA_NESTED, parse_policy_nested),
    NL80211_ATTR_TX_NO_CCK_RATE: ("tx_no_cck_rate", NLA_FLAG, parse_policy_flag),
    NL80211_ATTR_TDLS_ACTION: ("tdls_action", NLA_U8, parse_policy_u8),
    NL80211_ATTR_TDLS_DIALOG_TOKEN: ("tdls_dialog_token", NLA_U8, parse_policy_u8),
    NL80211_ATTR_TDLS_OPERATION: ("tdls_operation", NLA_U8, parse_policy_u8),
    NL80211_ATTR_TDLS_SUPPORT: ("tdls_support", NLA_FLAG, parse_policy_flag),
    NL80211_ATTR_TDLS_EXTERNAL_SETUP: ("tdls_external_setup", NLA_FLAG, parse_policy_flag),
    NL80211_ATTR_DONT_WAIT_FOR_ACK: ("dont_wait_for_ack", NLA_FLAG, parse_policy_flag),
    NL80211_ATTR_PROBE_RESP: ("probe_resp", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_DFS_REGION: ("dfs_region", NLA_U8, parse_policy_u8),
    NL80211_ATTR_DISABLE_HT: ("disable_ht", NLA_FLAG, parse_policy_flag),
    NL80211_ATTR_NOACK_MAP: ("noack_map", NLA_U16, parse_policy_u16),
    NL80211_ATTR_INACTIVITY_TIMEOUT: ("inactivity_timeout", NLA_U16, parse_policy_u16),
    NL80211_ATTR_BG_SCAN_PERIOD: ("bg_scan_period", NLA_U16, parse_policy_u16),
    NL80211_ATTR_WDEV: ("wdev", NLA_U64, parse_policy_u64),
    NL80211_ATTR_USER_REG_HINT_TYPE: ("user_reg_hint_type", NLA_U32, parse_policy_u32),
    NL80211_ATTR_SAE_DATA: ("sae_data", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_SCAN_FLAGS: ("scan_flags", NLA_U32, parse_policy_u32),
    NL80211_ATTR_P2P_CTWINDOW: ("p2p_ctwindow", NLA_U8, parse_policy_u8),
    NL80211_ATTR_P2P_OPPPS: ("p2p_oppps", NLA_U8, parse_policy_u8),
    NL80211_ATTR_ACL_POLICY: ("acl_policy", NLA_U32, parse_policy_u32),
    NL80211_ATTR_MAC_ADDRS: ("mac_addrs", NLA_NESTED, parse_policy_nested),
    NL80211_ATTR_STA_CAPABILITY: ("sta_capability", NLA_U16, parse_policy_u16),
    NL80211_ATTR_STA_EXT_CAPABILITY: ("sta_ext_capability", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_SPLIT_WIPHY_DUMP: ("split_wiphy_dump", NLA_FLAG, parse_policy_flag),
    NL80211_ATTR_DISABLE_VHT: ("disable_vht", NLA_FLAG, parse_policy_flag),
    NL80211_ATTR_MDID: ("mdid", NLA_U16, parse_policy_u16),
    NL80211_ATTR_IE_RIC: ("ie_ric", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_PEER_AID: ("peer_aid", NLA_U16, parse_policy_u16),
    NL80211_ATTR_CH_SWITCH_COUNT: ("ch_switch_count", NLA_U32, parse_policy_u32),
    NL80211_ATTR_CH_SWITCH_BLOCK_TX: ("ch_switch_block_tx", NLA_FLAG, parse_policy_flag),
    NL80211_ATTR_CSA_IES: ("csa_ies", NLA_NESTED, parse_policy_nested),
    NL80211_ATTR_CSA_C_OFF_BEACON: ("csa_c_off_beacon", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_CSA_C_OFF_PRESP: ("csa_c_off_presp", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_STA_SUPPORTED_CHANNELS: ("sta_supported_channels", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_STA_SUPPORTED_OPER_CLASSES: ("sta_supported_oper_classes", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_HANDLE_DFS: ("handle_dfs", NLA_FLAG, parse_policy_flag),
    NL80211_ATTR_OPMODE_NOTIF: ("opmode_notif", NLA_U8, parse_policy_u8),
    NL80211_ATTR_VENDOR_ID: ("vendor_id", NLA_U32, parse_policy_u32),
    NL80211_ATTR_VENDOR_SUBCMD: ("vendor_subcmd", NLA_U32, parse_policy_u32),
    NL80211_ATTR_VENDOR_DATA: ("vendor_data", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_QOS_MAP: ("qos_map", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_WIPHY_FREQ_HINT: ("wiphy_freq_hint", NLA_U32, parse_policy_u32),
    NL80211_ATTR_TDLS_PEER_CAPABILITY: ("tdls_peer_capability", NLA_U32, parse_policy_u32),
    NL80211_ATTR_IFACE_SOCKET_OWNER: ("iface_socket_owner", NLA_FLAG, parse_policy_flag),
    NL80211_ATTR_CSA_C_OFFSETS_TX: ("csa_c_offsets_tx", NLA_BINARY, parse_policy_binary), 
    NL80211_ATTR_MAC: ("mac", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_PREV_BSSID: ("prev_bssid", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_MNTR_FLAGS: ("mntr_flags", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_HT_CAPABILITY: ("ht_capability", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_STA_FLAGS2: ("sta_flags2", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_HT_CAPABILITY_MASK: ("ht_capability_mask", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_VHT_CAPABILITY: ("vht_capability", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_VHT_CAPABILITY_MASK: ("vht_capability_mask", NLA_BINARY, parse_policy_binary),
    NL80211_ATTR_MAC_HINT: ("mac_hint", NLA_BINARY, parse_policy_binary)
    }

#6 octets, bssid
NL80211_BSS_BSSID = 1
#u32 MHz
NL80211_BSS_FREQUENCY = 2
#TSF, u64
NL80211_BSS_TSF = 3
#u16
NL80211_BSS_BEACON_INTERVAL = 4
#CPU order, u16
NL80211_BSS_CAPABILITY = 5
#info
NL80211_BSS_INFORMATION_ELEMENTS = 6
#singal strength s32
NL80211_BSS_SIGNAL_MBM = 7
#unspecified units, u8
NL80211_BSS_SIGNAL_UNSPEC = 8
#BSS used
NL80211_BSS_STATUS = 9
#age of this BSS in ms
NL80211_BSS_SEEN_MS_AGO = 10
#beacon frame
NL80211_BSS_BEACON_IES = 11
#channel width, u32
NL80211_BSS_CHAN_WIDTH = 12

#control channel width for a BSS 
NL80211_BSS_CHAN_WIDTH_20 = 0
NL80211_BSS_CHAN_WIDTH_10 = 1
NL80211_BSS_CHAN_WIDTH_5 = 2


