#include <core.p4>
#include <v1model.p4>

const bit<8> OPCODE_ADD = 0x01;
const bit<8> OPCODE_SUB = 0x02;
const bit<8> OPCODE_REGEX = 0x03;
const bit<8> OPCODE_END = 0x07;

/* There are two addressing modes
bit 0 indicates that the value is embedded in the instruction - this must be 16 bits 
bit 1 indicates that the value is available in the 16 bit offset field specified

Similarly for result and error, when this bit is set, the result/error is available in this offset
*/

#define CHR_A 0x61
#define CHR_B 0x62
#define CHR_C 0x63

#define NUM_INSTRUCTIONS 8
#define NUM_DATA_BLOCKS 8
#define NUM_CHAR 8

#define BITS_PER_BYTE 8
#define ASTARB 0x1
#define BSTARC 0x2
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/


header instruction_t {
    bit<4>    reserved_instruction_flags; 
    bit<1>    error_mode;
    bit<1>    res_mode;
    bit<1>    op2_mode;
    bit<1>    op1_mode;
    bit<8>    instruction;
    bit<16>   op1;
    bit<16>   op2;
    bit<16>   res;
    bit<16>   error_code;
}

header offset_t {
    bit<16> data;
}

struct metadata {
    bit<8> pc;
    bit<8> instruction;
    bit<16> op1;
    bit<16> op2;
    bit<16> res;
    bit<16> err;
    bit<16> current_off;
    bit<16> current_val;
    bit<16> count;
}

header ins_header_t {
    bit<8> num_instructions;
    bit<8> data_length;
}

struct headers {
    ins_header_t   ih;
    instruction_t[NUM_INSTRUCTIONS]  ins;
    offset_t[NUM_DATA_BLOCKS] data;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
		packet.extract(hdr.ih);
		packet.extract(hdr.ins[0]);
		packet.extract(hdr.ins[1]);
		packet.extract(hdr.ins[2]);
		packet.extract(hdr.ins[3]);
		packet.extract(hdr.ins[4]);
		packet.extract(hdr.ins[5]);
		packet.extract(hdr.ins[6]);
		packet.extract(hdr.ins[7]);

		packet.extract(hdr.data[0]);
		packet.extract(hdr.data[1]);
		packet.extract(hdr.data[2]);
		packet.extract(hdr.data[3]);
		packet.extract(hdr.data[4]);
		packet.extract(hdr.data[5]);
		packet.extract(hdr.data[6]);
		packet.extract(hdr.data[7]);
	
	        transition select(hdr.ins[7].instruction){
			OPCODE_REGEX: regex_start;
			default: accept;
		}
    }
    state regex_start{
	transition select(hdr.ins[7].op1){
		ASTARB: parse_astarb;
		BSTARC: parse_bstarc;
		default: accept;
	}
    }
    state parse_astarb {
	transition select (packet.lookahead<bit<8>>()) {
		CHR_B : look_forB;
		CHR_A : parse_astarb1;
		default: accept;
	}
    }
    state parse_astarb1 {
	meta.count = meta.count + (bit<16>)1;
	packet.advance(BITS_PER_BYTE);
	transition select (packet.lookahead<bit<8>>()) {
		CHR_B : look_forB;
		CHR_A : parse_astarb1;
		default: accept;
	}
    }	
    state look_forB {
		packet.advance(BITS_PER_BYTE);
		meta.count = meta.count + (bit<16>)1;
		transition select (packet.lookahead<bit<8>>()) {
			CHR_B : parse_end;
			default: accept;
		}
	}

    state parse_bstarc {
		transition select (packet.lookahead<bit<8>>()) {
			CHR_C : look_forC;
			CHR_B: parse_bstarc1;
			default : accept;
		}
	}
    state parse_bstarc1 {
		packet.advance(BITS_PER_BYTE);
		meta.count = meta.count + (bit<16>)1;
		transition select (packet.lookahead<bit<8>>()) {
			CHR_C : look_forC;
			CHR_B: parse_bstarc1;
			default : accept;
		}
	}	
	state look_forC {
		packet.advance(BITS_PER_BYTE);
		meta.count = meta.count + (bit<16>)1;
		transition select (packet.lookahead<bit<8>>()) {
			CHR_C : parse_end;
			default: accept;
		}
	}	
	state parse_end {	
		transition accept;
	}
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
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

#define EXEC(X) \
	opcode##X.apply(); 

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

	action action_noAction(){
	}
	/* action_add, action_tbl, action_save, meta.pc */
	action action_add () {
	   	meta.res = meta.op1 + meta.op2;
	}
	action action_sub () {
		meta.res = meta.op1 - meta.op2;
	}

	/* instruction by instruction retreive and save */

	// inserted from perl gen_code.pl
	action action_fetch0 () {
		meta.current_val = hdr.data[0].data;
	}
	action action_store0 () {
		hdr.data[0].data = meta.current_val;
	}
	action action_fetch1 () {
		meta.current_val = hdr.data[1].data;
	}
	action action_store1 () {
		hdr.data[1].data = meta.current_val;
	}
	action action_fetch2 () {
		meta.current_val = hdr.data[2].data;
	}
	action action_store2 () {
		hdr.data[2].data = meta.current_val;
	}
	action action_fetch3 () {
		meta.current_val = hdr.data[3].data;
	}
	action action_store3 () {
		hdr.data[3].data = meta.current_val;
	}
	action action_fetch4 () {
		meta.current_val = hdr.data[4].data;
	}
	action action_store4 () {
		hdr.data[4].data = meta.current_val;
	}
	action action_fetch5 () {
		meta.current_val = hdr.data[5].data;
	}
	action action_store5 () {
		hdr.data[5].data = meta.current_val;
	}
	action action_fetch6 () {
		meta.current_val = hdr.data[6].data;
	}
	action action_store6 () {
		hdr.data[6].data = meta.current_val;
	}
	action action_fetch7 () {
		meta.current_val = hdr.data[7].data;
	}
	action action_store7 () {
		hdr.data[7].data = meta.current_val;
	}
	table fetch10 {
		key = {
			meta.current_off: exact;
		}

		actions = {
			action_fetch0;
			action_fetch1;        // 10 series is for op1
			action_fetch2;
			action_fetch3;
			action_fetch4;
			action_fetch5;
			action_fetch6;
			action_fetch7;
			action_noAction;
		}
	}
	table fetch20 {
		key = {
			meta.current_off: exact;
		}
					// 20 series is for op2
		actions = {
			action_fetch0;
			action_fetch1;
			action_fetch2;
			action_fetch3;
			action_fetch4;
			action_fetch5;
			action_fetch6;
			action_fetch7;
			action_noAction;
		}
	}
	table store10 {
		key = {
			meta.current_off: exact;
		}

		actions = {
			action_store0;
			action_store1;
			action_store2;
			action_store3;
			action_store4;
			action_store5;
			action_store6;
			action_store7;
			action_noAction;
		}
	}
	table store20 {
		key = {
			meta.current_off: exact;
		}

		actions = {
			action_store0;
			action_store1;
			action_store2;
			action_store3;
			action_store4;
			action_store5;
			action_store6;
			action_store7;
			action_noAction;
		}
	}
	table opcode0 {
		key = {
		    meta.instruction: exact;
		}
		actions = {
		    action_add;
		    action_sub;
		    action_noAction;
		}
		const default_action = action_noAction();
		const entries = {
            		OPCODE_ADD : action_add();
            		OPCODE_SUB : action_sub();
        	}
	}
	table fetch11 {
		key = {
			meta.current_off: exact;
		}

		actions = {
			action_fetch0;
			action_fetch1;
			action_fetch2;
			action_fetch3;
			action_fetch4;
			action_fetch5;
			action_fetch6;
			action_fetch7;
			action_noAction;
		}
	}
	table fetch21 {
		key = {
			meta.current_off: exact;
		}

		actions = {
			action_fetch0;
			action_fetch1;
			action_fetch2;
			action_fetch3;
			action_fetch4;
			action_fetch5;
			action_fetch6;
			action_fetch7;
			action_noAction;
		}
	}
	table store11 {
		key = {
			meta.current_off: exact;
		}

		actions = {
			action_store0;
			action_store1;
			action_store2;
			action_store3;
			action_store4;
			action_store5;
			action_store6;
			action_store7;
			action_noAction;
		}
	}
	table store21 {
		key = {
			meta.current_off: exact;
		}

		actions = {
			action_store0;
			action_store1;
			action_store2;
			action_store3;
			action_store4;
			action_store5;
			action_store6;
			action_store7;
			action_noAction;
		}
	}
	table opcode1 {
		key = {
		    meta.instruction: exact;
		}
		actions = {
		    action_add;
		    action_sub;
		    action_noAction;
		}
		const default_action = action_noAction();
		const entries = {
            		OPCODE_ADD : action_add();
            		OPCODE_SUB : action_sub();
        	}
	}
	table fetch12 {
		key = {
			meta.current_off: exact;
		}

		actions = {
			action_fetch0;
			action_fetch1;
			action_fetch2;
			action_fetch3;
			action_fetch4;
			action_fetch5;
			action_fetch6;
			action_fetch7;
			action_noAction;
		}
	}
	table fetch22 {
		key = {
			meta.current_off: exact;
		}

		actions = {
			action_fetch0;
			action_fetch1;
			action_fetch2;
			action_fetch3;
			action_fetch4;
			action_fetch5;
			action_fetch6;
			action_fetch7;
			action_noAction;
		}
	}
	table store12 {
		key = {
			meta.current_off: exact;
		}

		actions = {
			action_store0;
			action_store1;
			action_store2;
			action_store3;
			action_store4;
			action_store5;
			action_store6;
			action_store7;
			action_noAction;
		}
	}
	table store22 {
		key = {
			meta.current_off: exact;
		}

		actions = {
			action_store0;
			action_store1;
			action_store2;
			action_store3;
			action_store4;
			action_store5;
			action_store6;
			action_store7;
			action_noAction;
		}
	}
	table opcode2 {
		key = {
		    meta.instruction: exact;
		}
		actions = {
		    action_add;
		    action_sub;
		    action_noAction;
		}
		const default_action = action_noAction();
		const entries = {
            		OPCODE_ADD : action_add();
            		OPCODE_SUB : action_sub();
        	}
	}
	table fetch13 {
		key = {
			meta.current_off: exact;
		}

		actions = {
			action_fetch0;
			action_fetch1;
			action_fetch2;
			action_fetch3;
			action_fetch4;
			action_fetch5;
			action_fetch6;
			action_fetch7;
			action_noAction;
		}
	}
	table fetch23 {
		key = {
			meta.current_off: exact;
		}

		actions = {
			action_fetch0;
			action_fetch1;
			action_fetch2;
			action_fetch3;
			action_fetch4;
			action_fetch5;
			action_fetch6;
			action_fetch7;
			action_noAction;
		}
	}
	table store13 {
		key = {
			meta.current_off: exact;
		}

		actions = {
			action_store0;
			action_store1;
			action_store2;
			action_store3;
			action_store4;
			action_store5;
			action_store6;
			action_store7;
			action_noAction;
		}
	}
	table store23 {
		key = {
			meta.current_off: exact;
		}

		actions = {
			action_store0;
			action_store1;
			action_store2;
			action_store3;
			action_store4;
			action_store5;
			action_store6;
			action_store7;
			action_noAction;
		}
	}
	table opcode3 {
		key = {
		    meta.instruction: exact;
		}
		actions = {
		    action_add;
		    action_sub;
		    action_noAction;
		}
		const default_action = action_noAction();
		const entries = {
            		OPCODE_ADD : action_add();
            		OPCODE_SUB : action_sub();
        	}
	}
	table fetch14 {
		key = {
			meta.current_off: exact;
		}

		actions = {
			action_fetch0;
			action_fetch1;
			action_fetch2;
			action_fetch3;
			action_fetch4;
			action_fetch5;
			action_fetch6;
			action_fetch7;
			action_noAction;
		}
	}
	table fetch24 {
		key = {
			meta.current_off: exact;
		}

		actions = {
			action_fetch0;
			action_fetch1;
			action_fetch2;
			action_fetch3;
			action_fetch4;
			action_fetch5;
			action_fetch6;
			action_fetch7;
			action_noAction;
		}
	}
	table store14 {
		key = {
			meta.current_off: exact;
		}

		actions = {
			action_store0;
			action_store1;
			action_store2;
			action_store3;
			action_store4;
			action_store5;
			action_store6;
			action_store7;
			action_noAction;
		}
	}
	table store24 {
		key = {
			meta.current_off: exact;
		}

		actions = {
			action_store0;
			action_store1;
			action_store2;
			action_store3;
			action_store4;
			action_store5;
			action_store6;
			action_store7;
			action_noAction;
		}
	}
	table opcode4 {
		key = {
		    meta.instruction: exact;
		}
		actions = {
		    action_add;
		    action_sub;
		    action_noAction;
		}
		const default_action = action_noAction();
		const entries = {
            		OPCODE_ADD : action_add();
            		OPCODE_SUB : action_sub();
        	}
	}

	table fetch15 {
		key = {
			meta.current_off: exact;
		}

		actions = {
			action_fetch0;
			action_fetch1;
			action_fetch2;
			action_fetch3;
			action_fetch4;
			action_fetch5;
			action_fetch6;
			action_fetch7;
			action_noAction;
		}
	}
	table fetch25 {
		key = {
			meta.current_off: exact;
		}

		actions = {
			action_fetch0;
			action_fetch1;
			action_fetch2;
			action_fetch3;
			action_fetch4;
			action_fetch5;
			action_fetch6;
			action_fetch7;
			action_noAction;
		}
	}
	table store15 {
		key = {
			meta.current_off: exact;
		}

		actions = {
			action_store0;
			action_store1;
			action_store2;
			action_store3;
			action_store4;
			action_store5;
			action_store6;
			action_store7;
			action_noAction;
		}
	}
	table store25 {
		key = {
			meta.current_off: exact;
		}

		actions = {
			action_store0;
			action_store1;
			action_store2;
			action_store3;
			action_store4;
			action_store5;
			action_store6;
			action_store7;	
			action_noAction;
		}
	}
	table opcode5 {
		key = {
		    meta.instruction: exact;
		}
		actions = {
		    action_add;
		    action_sub;
		    action_noAction;
		}
		const default_action = action_noAction();
		const entries = {
            		OPCODE_ADD : action_add();
            		OPCODE_SUB : action_sub();
        	}
	}

	table fetch16 {
		key = {
			meta.current_off: exact;
		}

		actions = {
			action_fetch0;
			action_fetch1;
			action_fetch2;
			action_fetch3;
			action_fetch4;
			action_fetch5;
			action_fetch6;
			action_fetch7;
			action_noAction;
		}
	}
	table fetch26 {
		key = {
			meta.current_off: exact;
		}

		actions = {
			action_fetch0;
			action_fetch1;
			action_fetch2;
			action_fetch3;
			action_fetch4;
			action_fetch5;
			action_fetch6;
			action_fetch7;
			action_noAction;
		}
	}
	table store16 {
		key = {
			meta.current_off: exact;
		}

		actions = {
			action_store0;
			action_store1;
			action_store2;
			action_store3;
			action_store4;
			action_store5;
			action_store6;
			action_store7;
			action_noAction;
		}
	}
	table store26 {
		key = {
			meta.current_off: exact;
		}

		actions = {
			action_store0;
			action_store1;
			action_store2;
			action_store3;
			action_store4;
			action_store5;
			action_store6;
			action_store7;
			action_noAction;
		}
	}
	table opcode6 {
		key = {
		    meta.instruction: exact;
		}
		actions = {
		    action_add;
		    action_sub;
		    action_noAction;
		}
		const default_action = action_noAction();
		const entries = {
            		OPCODE_ADD : action_add();
            		OPCODE_SUB : action_sub();
        	}
	}

    apply {
		// every instruction checks whether it is not the end
		standard_metadata.egress_spec = (bit<9>)2;
		meta.pc =0;
		meta.instruction = hdr.ins[meta.pc].instruction;
		if (meta.instruction != OPCODE_END) {
			FETCH(0)
			EXEC(0)
			SAVE(0)
			meta.pc =1;
			meta.instruction = hdr.ins[meta.pc].instruction;
			if (meta.instruction != OPCODE_END) {
				FETCH(1);
				EXEC(1)
				SAVE(1)
				meta.pc =2;
				meta.instruction = hdr.ins[meta.pc].instruction;
				if (meta.instruction != OPCODE_END) {
					FETCH(2)
					EXEC(2)
					SAVE(2)

					meta.pc =3;
					meta.instruction = hdr.ins[meta.pc].instruction;
					if (meta.instruction != OPCODE_END) {
						FETCH(3)
						EXEC(3)
						SAVE(3)

						meta.pc =4;
						meta.instruction = hdr.ins[meta.pc].instruction;
						if (meta.instruction != OPCODE_END) {
							FETCH(4)
							EXEC(4)
							SAVE(4)

							meta.pc =5;
							meta.instruction = hdr.ins[meta.pc].instruction;
							if (meta.instruction != OPCODE_END) {
								FETCH(5)
								EXEC(5)
								SAVE(5)

								meta.pc =6;
								meta.instruction = hdr.ins[meta.pc].instruction;
								if (meta.instruction != OPCODE_END) {
									FETCH(6)
									EXEC(6)
									SAVE(6)

									meta.pc =7;
									meta.instruction = hdr.ins[meta.pc].instruction;
									if (meta.instruction != OPCODE_END) {
										hdr.ins[7].res = meta.count;
									}
								}
							}
						}
					}
				}
			}
		}
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        	packet.emit(hdr.ih);
        	packet.emit(hdr.ins[0]);
		packet.emit(hdr.ins[1]);
		packet.emit(hdr.ins[2]);
		packet.emit(hdr.ins[3]);
		packet.emit(hdr.ins[4]);
		packet.emit(hdr.ins[5]);
		packet.emit(hdr.ins[6]);
		packet.emit(hdr.ins[7]);

		packet.emit(hdr.data[0]);
		packet.emit(hdr.data[1]);
		packet.emit(hdr.data[2]);
		packet.emit(hdr.data[3]);
		packet.emit(hdr.data[4]);
		packet.emit(hdr.data[5]);
		packet.emit(hdr.data[6]);
		packet.emit(hdr.data[7]);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
