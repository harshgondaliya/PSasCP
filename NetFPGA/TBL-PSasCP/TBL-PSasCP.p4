//
// Copyright (c) 2017 Stephen Ibanez
// All rights reserved.
//
// This software was developed by Stanford University and the University of Cambridge Computer Laboratory 
// under National Science Foundation under Grant No. CNS-0855268,
// the University of Cambridge Computer Laboratory under EPSRC INTERNET Project EP/H040536/1 and
// by the University of Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-11-C-0249 ("MRC2"), 
// as part of the DARPA MRC research programme.
//
// @NETFPGA_LICENSE_HEADER_START@
//
// Licensed to NetFPGA C.I.C. (NetFPGA) under one or more contributor
// license agreements.  See the NOTICE file distributed with this work for
// additional information regarding copyright ownership.  NetFPGA licenses this
// file to you under the NetFPGA Hardware-Software License, Version 1.0 (the
// "License"); you may not use this file except in compliance with the
// License.  You may obtain a copy of the License at:
//
//   http://www.netfpga-cic.org
//
// Unless required by applicable law or agreed to in writing, Work distributed
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations under the License.
//
// @NETFPGA_LICENSE_HEADER_END@
//

#include <core.p4>
#include <sume_switch.p4>

const bit<8> OPCODE_ADD = 1;
const bit<8> OPCODE_SUB = 2;
const bit<8> OPCODE_REGEX = 3;
const bit<8> OPCODE_NO_OPR = 7;
typedef bit<48> EthAddr_t; 

#define NUM_INSTRUCTIONS 2
#define NUM_OFFSETS 2
#define CHR_A 0x61
#define CHR_B 0x62
#define CHR_C 0x63
#define ASTARB 0x1
#define BSTARC 0x2

header Ethernet_h {  
    EthAddr_t dstAddr; 
    EthAddr_t srcAddr; 
    bit<16> etherType;
}

header ins_header_t { // instruction header
    bit<8> num_instructions;
    bit<8> data_length;
}

header instruction_t { // instruction
    bit<4>    reserved_instruction_flags; 
    bit<1>    error_mode;			
	bit<1>    res_mode;
	bit<1>    op2_mode;
	bit<1>    op1_mode;
    bit<8>    instruction;
	bit<16>   op1; // for now all operands, result, error are assumed to be of 16 bit length;
	bit<16>   op2; //  for simplicity it is assumed that it starts at 16-bit boundary
	bit<16>   res;
	bit<16>   error_code;
}

header offset_t {  // offset data holder
	bit<16> data;
}

header string_t { // string character holder
	bit<8> data;
}

struct Parsed_packet {  // List of all recognized headers
    Ethernet_h ethernet;
    ins_header_t   ih;
    instruction_t[NUM_INSTRUCTIONS]  ins;
    offset_t[NUM_OFFSETS] off;
	string_t[4] str; 
}

struct user_metadata_t {
    bit<8> pc; 	// user defined metadata: can be used to shared information between 
    bit<8> instruction;           // TopParser, TopPipe, and TopDeparser 
	bit<16> op1; 
	bit<16> op2;
	bit<16> res;
	bit<16> err;
	bit<16> current_off;
	bit<16> current_val;
	bit<16> regex_count;
}

struct digest_data_t {
    bit<256>  unused;	// digest data to be sent to CPU if desired. MUST be 256 bits!
}

@Xilinx_MaxPacketRegion(16384) // Parser Implementation
parser TopParser(packet_in b, 
                 out Parsed_packet hdr, 
                 out user_metadata_t meta,
                 out digest_data_t digest_data,
                 inout sume_metadata_t sume_metadata) {
    state start {
		meta.pc = 0;
		meta.instruction = 0;
		meta.op1 = 0;
		meta.op2 = 0;
		meta.res = 0;
		meta.err = 0;
		meta.current_off = 0;
		meta.current_val = 0;
		meta.regex_count = 0;
       	digest_data.unused = 0;

		b.extract(hdr.ethernet);
		b.extract(hdr.ih);
		b.extract(hdr.ins[0]);
		b.extract(hdr.ins[1]); // 2 instructions are extracted and then the 
		b.extract(hdr.off[0]);  // data stored at offsets come up
		b.extract(hdr.off[1]);
		
		transition select(hdr.ins[1].instruction) { // only instruction 1 can have regular expression operation
			OPCODE_REGEX: regex_start;
			default: accept;
		}
    }
	state regex_start { 
		transition select(hdr.ins[1].op1) { 
			ASTARB: parse_astarb;
			BSTARC: parse_bstarc;
			default: accept;
		}
	}
	state parse_astarb {
		transition select(b.lookahead<bit<8>>()) {
			CHR_B : look_forB;
			CHR_A : continue_astarb_parse;
			default: accept;
		}
	}
	state continue_astarb_parse {
		meta.regex_count = meta.regex_count + (bit<16>)1;
		b.extract(hdr.str[0]);
		transition select (b.lookahead<bit<8>>()) {
			CHR_B : look_forB;
			CHR_A : continue_astarb_parse;
			default: accept;
		}
	}	
	state look_forB {
		meta.regex_count = meta.regex_count + (bit<16>)1;
		b.extract(hdr.str[1]);
		transition select (b.lookahead<bit<8>>()) {
			CHR_B : parse_end;
			default: accept;
		}
	}
	state parse_bstarc {
		transition select (b.lookahead<bit<8>>()) {
			CHR_C : look_forC;
			CHR_B: continue_bstarc_parse;
			default : accept;
		}
	}
	state continue_bstarc_parse {
		meta.regex_count = meta.regex_count + (bit<16>)1;
		b.extract(hdr.str[2]);
		transition select (b.lookahead<bit<8>>()) {
			CHR_C : look_forC;
			CHR_B: continue_bstarc_parse;
			default : accept;
		}
	}	
	state look_forC {
		meta.regex_count = meta.regex_count + (bit<16>)1;
		b.extract(hdr.str[3]);
		transition select (b.lookahead<bit<8>>()) {
			CHR_C : parse_end;
			default: accept;
		}
	}	
	state parse_end {	
		transition accept;
	}

}
#define FETCH(X) \
	if (hdr.ins[X].op1_mode == 0) { \
		meta.op1 = hdr.ins[X].op1; \
	} else { \
		meta.current_off = hdr.ins[X].op1; \
		fetch1##X.apply(); \
		meta.op1 = meta.current_val; \
	} \
	if (hdr.ins[X].op2_mode == 0) { \
		meta.op2 = hdr.ins[X].op2; \
	} else { \
		meta.current_off = hdr.ins[X].op2; \
		fetch2##X.apply(); \
		meta.op2 = meta.current_val; \
	} \

#define SAVE(X)	\
	if (hdr.ins[X].res_mode == 0) { \
		hdr.ins[X].res = meta.res; \
	} else { \
		meta.current_off = hdr.ins[X].res; \
		meta.current_val = meta.res; \
		store1##X.apply(); \
	} \
	if (hdr.ins[X].error_mode == 0) { \
		hdr.ins[X].error_code = meta.err; \
	} else { \
		meta.current_off = hdr.ins[X].error_code; \
		meta.current_val = meta.err; \
		store2##X.apply(); \
	} \

#define EXEC() \
	if(meta.instruction == 1){ \
		add(); \
	} \
	else if(meta.instruction == 2){ \
		sub(); \
	}

control TopPipe(inout Parsed_packet hdr,   // match-action pipeline
                inout user_metadata_t meta, 
                inout digest_data_t digest_data, 
                inout sume_metadata_t sume_metadata) {
	
	action add(){
		meta.res = meta.op1 + meta.op2;
	}
	action sub(){
		meta.res = meta.op1 - meta.op2;
	}
	action save_regex_count(){
		hdr.ins[1].res = meta.regex_count;
	}
	action fetch0(){ // fetch value from offset 0
		meta.current_val = hdr.off[0].data;
	}
	action fetch1(){ // fetch value from offset 1
		meta.current_val = hdr.off[1].data;
	}
	action store0(){ // store value at offset 0
		hdr.off[0].data = meta.current_val;
	}
	action store1(){ // store value at offset 1
		hdr.off[1].data = meta.current_val;
	}
	action mac_forward(bit<8> port){
		sume_metadata.dst_port = port;
	}
	
	// table fetchXY : X determines op1 (1) or op2 (2); Y denotes instruction 0 or 1
	
	table fetch10{    // fetch value of op1 of instruction 0
        key = { meta.current_off: exact; }
        actions = {
            fetch0;
			fetch1;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }
	table fetch20{    // fetch value of op2 of instruction 0
        key = { meta.current_off: exact; }
        actions = {
            fetch0;
			fetch1;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }
	table fetch11{    // fetch value of op1 of instruction 1
        key = { meta.current_off: exact; }
        actions = {
            fetch0;
			fetch1;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }
	table fetch21{    // fetch value of op2 of instruction 1
        key = { meta.current_off: exact; }
        actions = {
            fetch0;
			fetch1;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }
	
	// table storeXY : X determines result (1) or error (2); Y denotes instruction 0 or 1
	
	table store10{    // store value of result for instruction 0
        key = { meta.current_off: exact; }
        actions = {
            store0;
			store1;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }
	table store20{    // store value of error for instruction 0
        key = { meta.current_off: exact; }
        actions = {
            store0;
			store1;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }
	table store11{    // store value of result for instruction 1
        key = { meta.current_off: exact; }
        actions = {
            store0;
			store1;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }
	table store21{    // store value of error for instruction 1
        key = { meta.current_off: exact; }
        actions = {
            store0;
			store1;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }
	table mac_exact{
        key = { hdr.ethernet.dstAddr: exact; }
        actions = {
            mac_forward;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }
	apply {
		mac_exact.apply();

		meta.pc = 0;
		meta.instruction = hdr.ins[meta.pc].instruction;
		if(meta.instruction != OPCODE_NO_OPR){
			FETCH(0)
			EXEC()
			SAVE(0)
		}
		
		meta.pc = 1;
		meta.instruction = hdr.ins[meta.pc].instruction;
		if(meta.instruction != OPCODE_NO_OPR){
			if(meta.instruction == OPCODE_REGEX){
				save_regex_count();
			}else {
				FETCH(1)
				EXEC()
				SAVE(1)
			}
		}
	}
}

// Deparser Implementation
@Xilinx_MaxPacketRegion(16384)
control TopDeparser(packet_out b,
                    in Parsed_packet hdr,
                    in user_metadata_t meta,
                    inout digest_data_t digest_data, 
                    inout sume_metadata_t sume_metadata) { 
    apply {
        b.emit(hdr.ethernet);
		b.emit(hdr.ih);
		b.emit(hdr.ins[0]);
		b.emit(hdr.ins[1]);
		b.emit(hdr.off[0]);
		b.emit(hdr.off[1]);
		b.emit(hdr.str[0]);
		b.emit(hdr.str[1]);
		b.emit(hdr.str[2]);
		b.emit(hdr.str[3]);
    }
}

// Instantiate the switch
SimpleSumeSwitch(TopParser(), TopPipe(), TopDeparser()) main;

