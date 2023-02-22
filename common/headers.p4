#ifndef _HEADERS_
#define _HEADERS_

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<128> ipv6_addr_t;

typedef bit<8> pkt_type_t;


typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_IPV6 = 16w0x86dd;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_IGMP = 2;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<6> dscp;
    bit<2> ecn;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header ipv4_options_h {
    bit<32> data;
}

typedef ipv4_options_h[10] ipv4_options_t;

header ipv6_h {
    bit<4> version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_len;
    bit<8> next_hdr;
    bit<8> hop_limit;
    ipv6_addr_t src_addr;
    ipv6_addr_t dst_addr;
}

header common_l4_h {
    bit<16> src_port;
    bit<16> dst_port;
}

header tcp_h {
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> hdr_length;
    bit<16> checksum;
}

header icmp_h {
    bit<8> type_;
    bit<8> code;
    bit<16> hdr_checksum;
}

header tna_timestamps_h {
    bit<8> protocol;
    bit<8> pad_1;
    bit<48> ingress_mac;
    bit<16> pad_2;
    bit<48> ingress_global;
    bit<14> pad_3;
    bit<18> enqueue;
//    bit<14> pad_4;
    bit<32> dequeue_delta;
    bit<16> pad_5;
    bit<48> egress_global;
    bit<16> pad_6;
    bit<48> egress_tx;
    bit<16> pkt_length;
    bit<32> pad_7;
}

@flexible
header mirror_bridged_metadata_h {
    pkt_type_t pkt_type;
    bit<1> do_egr_mirroring;
    MirrorId_t egr_mir_ses;
    bit<48> ingress_mac;
    bit<48> ingress_global;
}


struct headers_t {
    mirror_bridged_metadata_h bridged_md;
    ethernet_h ethernet;
    ipv4_h ipv4;
    ipv4_options_t ipv4_options;
    ipv6_h ipv6;
    common_l4_h l4;
    tcp_h tcp;
    udp_h udp;
}

struct port_metadata_t {
    bit<3> port_pcp;
    bit<12> port_vid;
    bit<9> l2_xid;
}


header mirror_h {
    pkt_type_t  pkt_type;
    bit<48> ingress_global;
    bit<16> pkt_length;
    bit<32> qdelta;
}

struct metadata_t {
    port_metadata_t port_properties;
    PortId_t ingress_port;
    tna_timestamps_h tna_timestamps_hdr;
    ptp_metadata_t tx_ptp_md_hdr;
    bit<1> do_ing_mirroring;
    bit<1> do_egr_mirroring;
    MirrorId_t ing_mir_ses;
    MirrorId_t egr_mir_ses;
    pkt_type_t pkt_type;
    pkt_type_t flag;
    bit<48> ingress_mac;
    bit<48> ingress_global;
}

struct egr_metadata_t {
    tna_timestamps_h tna_timestamps_hdr;
    ptp_metadata_t tx_ptp_md_hdr;
    pkt_type_t pkt_type;
    pkt_type_t flag;
    MirrorId_t egr_mir_ses;
    bit<48> ingress_global;
    bit<16> new_ipv4_len;
    bit<16> pkt_length;
    bit<32> qdelta;
}

struct empty_header_t {}

struct empty_metadata_t {}

#endif /* _HEADERS_ */
