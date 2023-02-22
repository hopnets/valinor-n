
#include <core.p4>
#include <tna.p4>

#include "common/headers.p4"

const ReplicationId_t L2_MCAST_RID = 0xFFFF;
const bit<16> payload_slack_mirror = 68;
const bit<16> timestamp_hdr_length = 46;
const bit<16> offset = 0x4;

const pkt_type_t PKT_TYPE_NORMAL = 0x0;
const pkt_type_t PKT_TYPE_MIRROR = 0x1;

typedef bit<3> mirror_type_t;
const mirror_type_t MIRROR_TYPE_I2E = 0x1;
const mirror_type_t MIRROR_TYPE_E2E = 0x2;

const int METER_INDEX_WIDTH = 1;
typedef bit<(METER_INDEX_WIDTH)> meter_index_t;
#define VALINOR_TIMESTAMPED_PKTS_IDX_WIDTH 15
#define VALINOR_TIMESTAMPED_PACKETS_COUNTER_SIZE 1<<VALINOR_TIMESTAMPED_PKTS_IDX_WIDTH
typedef bit<VALINOR_TIMESTAMPED_PKTS_IDX_WIDTH> valinor_timestamped_pkts_idx_t;


//##########################
// Ingress Parser ##########
//##########################

parser SwitchIngressParser(
        packet_in pkt,
        out headers_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        ig_md.port_properties = port_metadata_unpack<port_metadata_t>(pkt);
        ig_md.ingress_port   = ig_intr_md.ingress_port;
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            default : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }

    state parse_ipv6 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }

}

//##########################
// Ingress Control ##########
//##########################

control SwitchIngress(
        inout headers_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    bool routed;
    bool valinor_setup;
    bool rl_drop;
	bit<2> color;
	DirectMeter(MeterType_t.BYTES)	rate_limit_meter;

    action set_color() {
	color = (bit<2>) rate_limit_meter.execute();
    }

    action set_output_port(PortId_t dest_port, bit<1> ing_mir, MirrorId_t ing_ses, bit<1> egr_mir, MirrorId_t egr_ses) {
        ig_intr_tm_md.ucast_egress_port = dest_port;
        // ig_intr_tm_md.bypass_egress = 1w1;
        ig_md.do_ing_mirroring = ing_mir;
        ig_md.ing_mir_ses = ing_ses;
        hdr.bridged_md.setValid();
        hdr.bridged_md.pkt_type = PKT_TYPE_NORMAL;
        routed = true;
		set_color();
    }

    action set_output_port_l2(PortId_t dest_port, bit<1> ing_mir, MirrorId_t ing_ses, bit<1> egr_mir, MirrorId_t egr_ses) {
        ig_intr_tm_md.ucast_egress_port = dest_port;
        // ig_intr_tm_md.bypass_egress = 1w1;
        ig_md.do_ing_mirroring = ing_mir;
        ig_md.ing_mir_ses = ing_ses;
        hdr.bridged_md.setValid();
        hdr.bridged_md.pkt_type = PKT_TYPE_NORMAL;
        routed = true;
    }   

    action broadcast() {
        ig_intr_tm_md.mcast_grp_a = 1;
        ig_intr_tm_md.rid = L2_MCAST_RID;
        ig_intr_tm_md.level2_exclusion_id = ig_md.port_properties.l2_xid;
        ig_intr_tm_md.bypass_egress = 1w1;
    }

    action drop() {
        ig_intr_dprsr_md.drop_ctl = 1;
        routed = true;
		set_color();
    }

	action drop_l2() {
		ig_intr_dprsr_md.drop_ctl = 1;
		routed = true;
	}

    action set_mirror_type() {
        ig_intr_dprsr_md.mirror_type = MIRROR_TYPE_I2E;
        ig_md.pkt_type = PKT_TYPE_MIRROR;
    }

    action set_mirror_status(bit<1> ing_mir, MirrorId_t ing_ses, bit<1> egr_mir, MirrorId_t egr_ses) {
        ig_md.do_ing_mirroring = ing_mir;
        ig_md.ing_mir_ses = ing_ses;
        hdr.bridged_md.do_egr_mirroring = egr_mir;
        hdr.bridged_md.egr_mir_ses = egr_ses;
        valinor_setup = true;
    }

	action meter_permit() {}
	action meter_deny() { ig_intr_dprsr_md.drop_ctl = 1; rl_drop = true; }

	table meter_action {
		key =  {color: exact;}
		actions = {meter_permit; meter_deny;}
		const default_action = meter_permit;
		size = 4;
	}

    table vswitch_l3 {
        key = {
            hdr.ipv4.dst_addr : exact;
        }

        actions = {
            set_output_port;
            drop;
        }
		meters = rate_limit_meter;
        size = 256;
    }

    table vswitch_l2 {
        key = {
            hdr.ethernet.dst_addr : exact;
        }

        actions = {
            set_output_port_l2;
            drop_l2;
            broadcast;
        }

        size = 128;
        default_action = broadcast();
    }

    table mirror_source_l2 {
        key = {
            hdr.ethernet.src_addr : exact;
        }

        actions = {
            set_mirror_status;
        }

        size = 256;
    }

    table mirror_source_l3 {
        key = {
            hdr.ipv4.src_addr : exact;
        }

        actions = {
            set_mirror_status;
        }

        size = 256;
    }

    apply {
        routed = false;
        valinor_setup = false;
	rl_drop = false;

        ig_md.tna_timestamps_hdr.ingress_mac = ig_intr_md.ingress_mac_tstamp;
        ig_md.tna_timestamps_hdr.ingress_global = ig_intr_prsr_md.global_tstamp;

        if(hdr.ipv4.isValid()){
            vswitch_l3.apply();
        }
        if(!routed){
            vswitch_l2.apply();
        }
	meter_action.apply();	
	if(!rl_drop) {
        	mirror_source_l3.apply();
        	if(!valinor_setup) {
           	 mirror_source_l2.apply();
        	}
        	if(ig_md.do_ing_mirroring == 1) {
            		set_mirror_type();
        	}
        	else {
            	hdr.bridged_md.ingress_mac = ig_md.tna_timestamps_hdr.ingress_mac;
            	hdr.bridged_md.ingress_global = ig_md.tna_timestamps_hdr.ingress_global;
        	}
	}

    }
}

//##########################
// Ingress Deparser ##########
//##########################

control SwitchIngressDeparser(
    packet_out pkt,
    inout headers_t hdr,
    in metadata_t ig_md,
    in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

    Mirror() mirror;

    apply {
        if(ig_intr_dprsr_md.mirror_type == MIRROR_TYPE_I2E) {
            mirror.emit<mirror_h>(ig_md.ing_mir_ses, {
                ig_md.pkt_type,
                ig_md.tna_timestamps_hdr.ingress_global,
                0, 0
            });
        }
        pkt.emit(hdr);
    }
}

//##########################
// Egress Parser ##########
//##########################

parser SwitchEgressParser(
    packet_in pkt,
    out headers_t hdr,
    out egr_metadata_t eg_md,
    out egress_intrinsic_metadata_t eg_intr_md) {
	
    state start {
        pkt.extract(eg_intr_md);
        transition parse_metadata;
    }    

    state parse_metadata {
        mirror_h mirror_md = pkt.lookahead<mirror_h>();
        eg_md.flag = PKT_TYPE_NORMAL;
        transition select(mirror_md.pkt_type) {
            PKT_TYPE_MIRROR: parse_mirror_md;
            PKT_TYPE_NORMAL: parse_bridged_md;
            default: accept;
        }
    }

    state parse_bridged_md {
        pkt.extract(hdr.bridged_md);
        //eg_md.ingress_mac = hdr.bridged_md.ingress_mac;
        eg_md.ingress_global = hdr.bridged_md.ingress_global;
        transition parse_ethernet;
    }

    state parse_mirror_md {
        mirror_h mirror_md;
        pkt.extract(mirror_md);
        eg_md.flag = PKT_TYPE_MIRROR;
        //eg_md.ingress_mac = mirror_md.ingress_mac;
        eg_md.ingress_global = mirror_md.ingress_global;
        eg_md.pkt_length = mirror_md.pkt_length;
	eg_md.qdelta = mirror_md.qdelta;
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            default : accept;
        }
    }

    // not used here. we support ipv4 options too!
    state parse_ipv4_basic {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.frag_offset, hdr.ipv4.protocol, hdr.ipv4.ihl) {
            (0, IP_PROTOCOLS_ICMP, 5) : parse_common_l4;
            (0, IP_PROTOCOLS_IGMP, 5) : parse_common_l4;
            (0, IP_PROTOCOLS_TCP, 5) : parse_tcp;
            (0, IP_PROTOCOLS_UDP, 5) : parse_udp;
            (0, _, 5) : parse_common_l4;
            default: accept;
        }
    }

    state parse_ipv4_options_1 {
        pkt.extract(hdr.ipv4_options[0]);
        transition parse_ipv4_no_options;
    }

    state parse_ipv4_options_2 {
        pkt.extract(hdr.ipv4_options[0]);
        pkt.extract(hdr.ipv4_options[1]);
        transition parse_ipv4_no_options;
    }

    state parse_ipv4_options_3 {
        pkt.extract(hdr.ipv4_options[0]);
        pkt.extract(hdr.ipv4_options[1]);
        pkt.extract(hdr.ipv4_options[2]);
        transition parse_ipv4_no_options;
    }

    state parse_ipv4_options_4 {
        pkt.extract(hdr.ipv4_options[0]);
        pkt.extract(hdr.ipv4_options[1]);
        pkt.extract(hdr.ipv4_options[2]);
        pkt.extract(hdr.ipv4_options[3]);
        transition parse_ipv4_no_options;
    }

    state parse_ipv4_options_5 {
        pkt.extract(hdr.ipv4_options[0]);
        pkt.extract(hdr.ipv4_options[1]);
        pkt.extract(hdr.ipv4_options[2]);
        pkt.extract(hdr.ipv4_options[3]);
        pkt.extract(hdr.ipv4_options[4]);
        transition parse_ipv4_no_options;
    }

    state parse_ipv4_options_6 {
        pkt.extract(hdr.ipv4_options[0]);
        pkt.extract(hdr.ipv4_options[1]);
        pkt.extract(hdr.ipv4_options[2]);
        pkt.extract(hdr.ipv4_options[3]);
        pkt.extract(hdr.ipv4_options[4]);
        pkt.extract(hdr.ipv4_options[5]);
        transition parse_ipv4_no_options;
    }

    state parse_ipv4_options_7 {
        pkt.extract(hdr.ipv4_options[0]);
        pkt.extract(hdr.ipv4_options[1]);
        pkt.extract(hdr.ipv4_options[2]);
        pkt.extract(hdr.ipv4_options[3]);
        pkt.extract(hdr.ipv4_options[4]);
        pkt.extract(hdr.ipv4_options[5]);
        pkt.extract(hdr.ipv4_options[6]);
        transition parse_ipv4_no_options;
    }

    state parse_ipv4_options_8 {
        pkt.extract(hdr.ipv4_options[0]);
        pkt.extract(hdr.ipv4_options[1]);
        pkt.extract(hdr.ipv4_options[2]);
        pkt.extract(hdr.ipv4_options[3]);
        pkt.extract(hdr.ipv4_options[4]);
        pkt.extract(hdr.ipv4_options[5]);
        pkt.extract(hdr.ipv4_options[6]);
        pkt.extract(hdr.ipv4_options[7]);
        transition parse_ipv4_no_options;
    }

    state parse_ipv4_options_9 {
        pkt.extract(hdr.ipv4_options[0]);
        pkt.extract(hdr.ipv4_options[1]);
        pkt.extract(hdr.ipv4_options[2]);
        pkt.extract(hdr.ipv4_options[3]);
        pkt.extract(hdr.ipv4_options[4]);
        pkt.extract(hdr.ipv4_options[5]);
        pkt.extract(hdr.ipv4_options[6]);
        pkt.extract(hdr.ipv4_options[7]);
        pkt.extract(hdr.ipv4_options[8]);
        transition parse_ipv4_no_options;
    }

    state parse_ipv4_options_10 {
        pkt.extract(hdr.ipv4_options[0]);
        pkt.extract(hdr.ipv4_options[1]);
        pkt.extract(hdr.ipv4_options[2]);
        pkt.extract(hdr.ipv4_options[3]);
        pkt.extract(hdr.ipv4_options[4]);
        pkt.extract(hdr.ipv4_options[5]);
        pkt.extract(hdr.ipv4_options[6]);
        pkt.extract(hdr.ipv4_options[7]);
        pkt.extract(hdr.ipv4_options[8]);
        pkt.extract(hdr.ipv4_options[9]);
        transition parse_ipv4_no_options;
    }

    state parse_ipv4_no_options {
        transition select(hdr.ipv4.frag_offset, eg_md.tna_timestamps_hdr.protocol) {
            (0, IP_PROTOCOLS_ICMP) : parse_common_l4;
            (0, IP_PROTOCOLS_IGMP) : parse_common_l4;
            (0, IP_PROTOCOLS_TCP) : parse_tcp;
            (0, IP_PROTOCOLS_UDP) : parse_udp;
            (0, _) : parse_common_l4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        eg_md.tna_timestamps_hdr.protocol = hdr.ipv4.protocol;
        #hdr.ipv4.protocol = 0xFD;
        transition select(hdr.ipv4.ihl) {
            5: parse_ipv4_no_options;
            6: parse_ipv4_options_1;
            7: parse_ipv4_options_2;
            8: parse_ipv4_options_3;
            9: parse_ipv4_options_4;
            10: parse_ipv4_options_5;
            11: parse_ipv4_options_6;
            12: parse_ipv4_options_7;
            13: parse_ipv4_options_8;
            14: parse_ipv4_options_9;
            15: parse_ipv4_options_10;
        }
    }

    state parse_ipv6 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }

    state parse_common_l4 {
        pkt.extract(hdr.l4);
        transition accept;
    }

    state parse_tcp {
        pkt.extract(hdr.l4);
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.l4);
        pkt.extract(hdr.udp);
        transition accept;
    }

}

//##########################
// Egress Control ##########
//##########################

control SwitchEgress(
        inout headers_t hdr,
        inout egr_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {

    valinor_timestamped_pkts_idx_t valinor_timestamped_pkts_idx = 0;
    Counter<bit<64>, valinor_timestamped_pkts_idx_t>(VALINOR_TIMESTAMPED_PACKETS_COUNTER_SIZE, CounterType_t.PACKETS_AND_BYTES) valinor_counter;

    action set_mirror() {
        eg_md.egr_mir_ses = hdr.bridged_md.egr_mir_ses;
        eg_md.pkt_type = PKT_TYPE_MIRROR;
        eg_intr_md_for_dprsr.mirror_type = MIRROR_TYPE_E2E;
        eg_md.pkt_length = eg_intr_md.pkt_length;
	eg_md.qdelta = (bit<32>)  eg_intr_md.deq_timedelta;
    }

    action set_protocol() {
        eg_md.tna_timestamps_hdr.protocol = hdr.ipv4.protocol;
        // hdr.ipv4.protocol = 0xFD;
    }

    action update_timestamp_header() {
	hdr.ipv4.protocol = 0xFD;
        eg_md.tna_timestamps_hdr.setValid();
        eg_md.tna_timestamps_hdr.ingress_mac = 0;
        eg_md.tna_timestamps_hdr.ingress_global = eg_md.ingress_global;
        eg_md.tna_timestamps_hdr.enqueue = eg_intr_md.enq_tstamp;
        eg_md.tna_timestamps_hdr.dequeue_delta =  eg_md.qdelta;
        //eg_md.tna_timestamps_hdr.egress_global = eg_intr_from_prsr.global_tstamp;
        eg_md.tna_timestamps_hdr.pkt_length = eg_md.pkt_length - offset; // - 0xD - length of intrinsic metadata
        valinor_counter.count(valinor_timestamped_pkts_idx);
    }
    

    apply {
        if(eg_md.flag == PKT_TYPE_MIRROR) {
            update_timestamp_header();
        }
        else if (hdr.bridged_md.do_egr_mirroring == 1) {
             set_mirror();
        }
    }
}

//##########################
// Egress Deparser ##########
//##########################

control SwitchEgressDeparser(
        packet_out pkt,
        inout headers_t hdr,
        in egr_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_dprsr_md) {

        Checksum() ipv4_checksum;
        Mirror() mirror;
    
    apply {

        if(hdr.ipv4.isValid()) {
             hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                 hdr.ipv4.version,
                 hdr.ipv4.ihl,
                 hdr.ipv4.dscp,
		 hdr.ipv4.ecn,
                 hdr.ipv4.total_len,
                 hdr.ipv4.identification,
                 hdr.ipv4.flags,
                 hdr.ipv4.frag_offset,
                 hdr.ipv4.ttl,
                 hdr.ipv4.protocol,
                 hdr.ipv4.src_addr,
                 hdr.ipv4.dst_addr,
                 hdr.ipv4_options[0].data,
                 hdr.ipv4_options[1].data,
                 hdr.ipv4_options[2].data,
                 hdr.ipv4_options[3].data,
                 hdr.ipv4_options[4].data,
                 hdr.ipv4_options[5].data,
                 hdr.ipv4_options[6].data,
                 hdr.ipv4_options[7].data,
                 hdr.ipv4_options[8].data,
                 hdr.ipv4_options[9].data
             });
        }

        if (eg_intr_dprsr_md.mirror_type == MIRROR_TYPE_E2E) {
            mirror.emit<mirror_h>(eg_md.egr_mir_ses, {eg_md.pkt_type,
                    eg_md.ingress_global, eg_md.pkt_length, eg_md.qdelta});
        }

        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.ipv4_options);
        pkt.emit(hdr.ipv6);
        pkt.emit(eg_md.tna_timestamps_hdr);
        pkt.emit(hdr.l4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);

    }
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser())
         pipe;

Switch(pipe) main;
