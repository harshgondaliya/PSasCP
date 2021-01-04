#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
from scapy.fields import *
from scapy.all import sendp, send, get_if_list, get_if_hwaddr,hexdump
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from time import sleep

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

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def main():
    iface = get_if()

    print "sending on interface %s" % (iface)
    pkt1 = ins_header(num_instructions=2, data_length=2)/Instruction(opcode=1, op1=20, op2=10, res=0)/Instruction(opcode=1, op1=20, op2=10, res=0)/Instruction(opcode=1, op1=20, op2=10, res=0)/Instruction(opcode=1, op1=20, op2=10, res=0)/Instruction(opcode=1, op1=20, op2=10, res=0)/Instruction(opcode=1, op1=20, op2=10, res=0)/Instruction(op1_mode=1, op2_mode=1, opcode=1, res_mode=1, op1=0, op2=1, res=0)/Instruction(opcode=3, op1=1, op2=0, res=0)/OffsetData(data=20)/OffsetData(data=10)/OffsetData()/OffsetData()/OffsetData()/OffsetData()/OffsetData()/OffsetData()/StrData(data="a")/StrData(data="a")/StrData(data="a")/StrData(data="b")

    sendp(pkt1, iface=iface, verbose=False)
    pkt1.show2()
    hexdump(pkt1)	

if __name__ == '__main__':
    main()
