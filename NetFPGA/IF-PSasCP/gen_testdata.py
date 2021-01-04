#!/usr/bin/env python

#
# Copyright (c) 2017 Stephen Ibanez
# All rights reserved.
#
# This software was developed by Stanford University and the University of Cambridge Computer Laboratory 
# under National Science Foundation under Grant No. CNS-0855268,
# the University of Cambridge Computer Laboratory under EPSRC INTERNET Project EP/H040536/1 and
# by the University of Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-11-C-0249 ("MRC2"), 
# as part of the DARPA MRC research programme.
#
# @NETFPGA_LICENSE_HEADER_START@
#
# Licensed to NetFPGA C.I.C. (NetFPGA) under one or more contributor
# license agreements.  See the NOTICE file distributed with this work for
# additional information regarding copyright ownership.  NetFPGA licenses this
# file to you under the NetFPGA Hardware-Software License, Version 1.0 (the
# "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at:
#
#   http://www.netfpga-cic.org
#
# Unless required by applicable law or agreed to in writing, Work distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations under the License.
#
# @NETFPGA_LICENSE_HEADER_END@
#


from nf_sim_tools import *
import random
from collections import OrderedDict
import sss_sdnet_tuples

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
class Data(Packet):
	name = "Data"
	fields_desc=[ ShortField("data",0) ]

###########
# pkt generation tools
###########

pktsApplied = []
pktsExpected = []

# Pkt lists for SUME simulations
nf_applied = OrderedDict()
nf_applied[0] = []
nf_applied[1] = []
nf_applied[2] = []
nf_applied[3] = []
nf_expected = OrderedDict()
nf_expected[0] = []
nf_expected[1] = []
nf_expected[2] = []
nf_expected[3] = []

nf_port_map = {"nf0":0b00000001, "nf1":0b00000100, "nf2":0b00010000, "nf3":0b01000000, "dma0":0b00000010}
nf_id_map = {"nf0":0, "nf1":1, "nf2":2, "nf3":3}

sss_sdnet_tuples.clear_tuple_files()

def applyPkt(pkt, ingress, time):
    pktsApplied.append(pkt)
    sss_sdnet_tuples.sume_tuple_in['pkt_len'] = len(pkt) 
    sss_sdnet_tuples.sume_tuple_in['src_port'] = nf_port_map[ingress]
    sss_sdnet_tuples.sume_tuple_expect['pkt_len'] = len(pkt) 
    sss_sdnet_tuples.sume_tuple_expect['src_port'] = nf_port_map[ingress]
    pkt.time = time
    nf_applied[nf_id_map[ingress]].append(pkt)

def expPkt(pkt, egress):
    pktsExpected.append(pkt)
    sss_sdnet_tuples.sume_tuple_expect['dst_port'] = nf_port_map[egress]
    sss_sdnet_tuples.write_tuples()
    if egress in ["nf0","nf1","nf2","nf3"]:
        nf_expected[nf_id_map[egress]].append(pkt)
    elif egress == 'bcast':
        nf_expected[0].append(pkt)
        nf_expected[1].append(pkt)
        nf_expected[2].append(pkt)
        nf_expected[3].append(pkt)

def write_pcap_files():
    wrpcap("src.pcap", pktsApplied)
    wrpcap("dst.pcap", pktsExpected)

    for i in nf_applied.keys():
        if (len(nf_applied[i]) > 0):
            wrpcap('nf{0}_applied.pcap'.format(i), nf_applied[i])

    for i in nf_expected.keys():
        if (len(nf_expected[i]) > 0):
            wrpcap('nf{0}_expected.pcap'.format(i), nf_expected[i])

    for i in nf_applied.keys():
        print "nf{0}_applied times: ".format(i), [p.time for p in nf_applied[i]]

#####################
# generate testdata #
#####################
MAC_SRC = "01:01:01:01:01:01"
MAC_DST = "02:02:02:02:02:02"

pktCnt = 0
## embed + iparse
pkt1 = Ether(dst=MAC_DST, src=MAC_SRC)/ins_header(num_instructions=2, data_length=2)/Instruction(opcode=1, op1=20, op2=10, res=0)/Instruction(opcode=3, op1=1, op2=0, res=0)/Data()/Data()/"ab"

pkt2 = Ether(dst=MAC_DST, src=MAC_SRC)/ins_header(num_instructions=2, data_length=2)/Instruction(opcode=1, op1=20, op2=10, res=30)/Instruction(opcode=3, op1=1, op2=0, res=2)/Data()/Data()/"ab"

pkt1 = pad_pkt(pkt1, 64)
pkt2 = pad_pkt(pkt2, 64)

applyPkt(pkt1, 'nf0', pktCnt)
pktCnt += 1
expPkt(pkt2, 'nf1')

## offset + iparse
pkt1 = Ether(dst=MAC_DST, src=MAC_SRC)/ins_header(num_instructions=2, data_length=2)/Instruction(op1_mode=1, op2_mode=1, opcode=1, op1=0, op2=1, res=0)/Instruction(opcode=3, op1=1, op2=0, res=0)/Data(data=20)/Data(data=10)/"ab"

pkt2 = Ether(dst=MAC_DST, src=MAC_SRC)/ins_header(num_instructions=2, data_length=2)/Instruction(op1_mode=1, op2_mode=1, opcode=1, op1=0, op2=1, res=30)/Instruction(opcode=3, op1=1, op2=0, res=2)/Data(data=20)/Data(data=10)/"ab"

pkt1 = pad_pkt(pkt1, 64)
pkt2 = pad_pkt(pkt2, 64)

applyPkt(pkt1, 'nf0', pktCnt)
pktCnt += 1
expPkt(pkt2, 'nf1')

## only iparse
pkt1 = Ether(dst=MAC_DST, src=MAC_SRC)/ins_header(num_instructions=2, data_length=2)/Instruction(opcode=7)/Instruction(opcode=3, op1=1, op2=0, res=0)/Data()/Data()/"ab"

pkt2 = Ether(dst=MAC_DST, src=MAC_SRC)/ins_header(num_instructions=2, data_length=2)/Instruction(opcode=7)/Instruction(opcode=3, op1=1, op2=0, res=2)/Data()/Data()/"ab"

pkt1 = pad_pkt(pkt1, 64)
pkt2 = pad_pkt(pkt2, 64)

applyPkt(pkt1, 'nf0', pktCnt)
pktCnt += 1
expPkt(pkt2, 'nf1')

# 1 instruction : 100% embed #
pkt1 = Ether(dst=MAC_DST, src=MAC_SRC)/ins_header(num_instructions=2, data_length=2)/Instruction(opcode=1, op1=20, op2=10, res=0)/Instruction(opcode=7)

pkt2 = Ether(dst=MAC_DST, src=MAC_SRC)/ins_header(num_instructions=2, data_length=2)/Instruction(opcode=1, op1=20, op2=10, res=30)/Instruction(opcode=7)

pkt1 = pad_pkt(pkt1, 64)
pkt2 = pad_pkt(pkt2, 64)

applyPkt(pkt1, 'nf0', pktCnt)
pktCnt += 1
expPkt(pkt2, 'nf1')

# 1 instruction : 100% offset #
pkt1 = Ether(dst=MAC_DST, src=MAC_SRC)/ins_header(num_instructions=2, data_length=2)/Instruction(op1_mode=1, op2_mode=1, opcode=1, op1=0, op2=1, res=0)/Instruction(opcode=7)/Data(data=20)/Data(data=10)

pkt2 = Ether(dst=MAC_DST, src=MAC_SRC)/ins_header(num_instructions=2, data_length=2)/Instruction(op1_mode=1, op2_mode=1, opcode=1, op1=0, op2=1, res=30)/Instruction(opcode=7)/Data(data=20)/Data(data=10)

pkt1 = pad_pkt(pkt1, 64)
pkt2 = pad_pkt(pkt2, 64)

applyPkt(pkt1, 'nf0', pktCnt)
pktCnt += 1
expPkt(pkt2, 'nf1')

# 2 instruction : 100% embed #
pkt1 = Ether(dst=MAC_DST, src=MAC_SRC)/ins_header(num_instructions=2, data_length=2)/Instruction(opcode=1, op1=20, op2=10, res=0)/Instruction(opcode=2, op1=20, op2=10, res=0)

pkt2 = Ether(dst=MAC_DST, src=MAC_SRC)/ins_header(num_instructions=2, data_length=2)/Instruction(opcode=1, op1=20, op2=10, res=30)/Instruction(opcode=2, op1=20, op2=10, res=10)

pkt1 = pad_pkt(pkt1, 64)
pkt2 = pad_pkt(pkt2, 64)

applyPkt(pkt1, 'nf0', pktCnt)
pktCnt += 1
expPkt(pkt2, 'nf1')

# 2 instruction : 100% offset #
pkt1 = Ether(dst=MAC_DST, src=MAC_SRC)/ins_header(num_instructions=2, data_length=2)/Instruction(op1_mode=1, op2_mode=1, opcode=1, op1=0, op2=1, res=0)/Instruction(op1_mode=1, op2_mode=1, opcode=2, op1=0, op2=1, res=0)/Data(data=20)/Data(data=10)

pkt2 = Ether(dst=MAC_DST, src=MAC_SRC)/ins_header(num_instructions=2, data_length=2)/Instruction(op1_mode=1, op2_mode=1, opcode=1, op1=0, op2=1, res=30)/Instruction(op1_mode=1, op2_mode=1, opcode=2, op1=0, op2=1, res=10)/Data(data=20)/Data(data=10)

pkt1 = pad_pkt(pkt1, 64)
pkt2 = pad_pkt(pkt2, 64)

applyPkt(pkt1, 'nf0', pktCnt)
pktCnt += 1
expPkt(pkt2, 'nf1')

# 2 instruction : hybrid#
pkt1 = Ether(dst=MAC_DST, src=MAC_SRC)/ins_header(num_instructions=2, data_length=2)/Instruction(op1_mode=1, op2_mode=1, opcode=1, op1=0, op2=1, res=0)/Instruction(opcode=2, op1=20, op2=10, res=0)/Data(data=20)/Data(data=10)

pkt2 = Ether(dst=MAC_DST, src=MAC_SRC)/ins_header(num_instructions=2, data_length=2)/Instruction(op1_mode=1, op2_mode=1, opcode=1, op1=0, op2=1, res=30)/Instruction(opcode=2, op1=20, op2=10, res=10)/Data(data=20)/Data(data=10)

pkt1 = pad_pkt(pkt1, 64)
pkt2 = pad_pkt(pkt2, 64)

applyPkt(pkt1, 'nf0', pktCnt)
pktCnt += 1
expPkt(pkt2, 'nf1')


write_pcap_files()
