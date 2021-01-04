#!/usr/bin/env python
import sys
import struct
import os
from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.fields import *
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR, DestIPField
from scapy.data import IP_PROTOS, TCP_SERVICES
def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class ins_header(Packet):
    name = "Instruction header "	
    fields_desc=[ XByteField("num_instructions",0),
                 XByteField("data_length",0) ]

class Instruction (Packet):
    name = "Instruction "
    fields_desc=[ 	BitField("reserved", 0, 4),
			BitField("error_mode", 0, 1),
			BitField("res_mode", 0, 1),
			BitField("op2_mode", 0, 1),
			BitField("op1_mode", 0, 1),
			BitField("opcode", 0, 8),
			ShortField("op1",0),
			ShortField("op2",0),
			ShortField("res",0),
			ShortField("error_code",0) ]

class OffsetData(Packet):
        name = "OffsetData"
        fields_desc=[ ShortField("data",0) ]

class StrData(Packet):
        name = "StrData"
        fields_desc=[ StrFixedLenField("data", "x", 1)]


def handle_pkt(pkt):
	print "got a packet"        
	hexdump(pkt)
        sys.stdout.flush()


def main():
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
