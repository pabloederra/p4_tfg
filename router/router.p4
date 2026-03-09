// Version con ARP
/* -*- P4_16 -*- */

#include <core.p4>
#include <v1model.p4>


typedef bit<9>  egressSpec_t;
typedef bit<9>  PortId_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

const macAddr_t BROADCAST_ADDR = 0xffffffffffff;

typedef bit<16> PortIdToController_t;

const int CPU_PORT_CLONE_SESSION_ID = 67;

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_ARP = 0x806;
const bit<16> TYPE_IPV6 = 0x86dd;
const bit<8> ICMP = 1;
const bit<8> IGMP = 2;
const bit<8> TCP = 6;
const bit<8> UDP = 17;
const bit<8> GRE = 47;

const int FL_PACKET_IN = 1;

const bit<32> NUMBER_OF_HOSTS = 3; //Pongo 3 pq pilla el ultimo digito de la IP [0, 1, 2] (son 3)

#define CPU_PORT 510

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_h {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header arp_h {
    bit<16>     hType;
    bit<16>     pType;
    bit<8>      hLen;
    bit<8>      pLen;
    bit<16>     op;
    macAddr_t   sha;
    ip4Addr_t   spa;
    macAddr_t   tha;
    ip4Addr_t   tpa;
}

header ipv4_h {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header gre_h {
    bit<2>  reserved0;
    bit<1>  key_flag;
    bit<13> reserved1;
    bit<16> protocol_type;
    bit<32> key;
}

// Note on the names of the controller_header header types:

// packet_out and packet_in are named here from the perspective of the
// controller, and that is how these messages are named in the
// P4Runtime API specification as well.

// Thus packet_out is a packet sent out of the controller to the
// switch, which becomes a packet received by the switch on port
// CPU_PORT.

// A packet sent by the switch to port CPU_PORT becomes a PacketIn
// message to the controller.

// When running with simple_switch_grpc, you must provide the
// following command line option to enable the ability for the
// software switch to receive and send such messages: --cpu-port 510

enum bit<8> ControllerOpcode_t {
    NO_OP                    = 0,
    SEND_TO_PORT_IN_OPERAND0 = 1,
    OP_FLOOD = 2,
    ARP_REPLY = 3
}

enum bit<8> PuntReason_t {
    FLOW_UNKNOWN        = 1,
    UNRECOGNIZED_OPCODE = 2
}

enum bit<6> dscp_t {
    ICMP = 17,
    IGMP = 4,
    TCP = 8,
    UDP = 12
}
// The packet_in header should contain three fields: input_port,
//punt_reason, and opcode. The packet_out header should include: opcode, reserved1, and operand0 (which represents the egress port in this case). 
@controller_header("packet_out")
header packet_out_header_h {
    /* TODO: Add packet-out fields */
    ControllerOpcode_t   opcode;
    bit<8>               reserved1;
    bit<48>              operand0;

}

@controller_header("packet_in")
header packet_in_header_h {
    /* TODO: Add packet-in fields */
    PortIdToController_t input_port;
    ControllerOpcode_t   opcode;
    PuntReason_t         punt_reason;
}

struct metadata_t {
    @field_list(FL_PACKET_IN)
    PortId_t             ingress_port;
    @field_list(FL_PACKET_IN)
    PuntReason_t         punt_reason;
    @field_list(FL_PACKET_IN)
    ControllerOpcode_t   opcode;

    PortId_t             input_port;

    @field_list(FL_PACKET_IN)
    bit<1>               flag_tunnel;
}

struct headers_t {
    packet_in_header_h  packet_in;
    packet_out_header_h packet_out;
    ethernet_h ethernet;
    ethernet_h inner_ethernet;
    arp_h      arp;
    ipv4_h     ipv4;
    ipv4_h     inner_ipv4;
    gre_h      gre;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                  out headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata)
{
    state start {
        transition check_for_cpu_port;
    }
    state check_for_cpu_port {
        transition select (standard_metadata.ingress_port) {
            CPU_PORT: parse_controller_packet_out_header;
            default: parse_ethernet;
        }
    }
    state parse_controller_packet_out_header {
        packet.extract(hdr.packet_out);
        transition accept;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        verify(hdr.ethernet.etherType != TYPE_IPV6, error.ParserInvalidArgument);
        transition select (hdr.ethernet.etherType) {
            TYPE_IPV4:  parse_ipv4;
            default:    accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select (hdr.ipv4.protocol) {
            GRE:        parse_gre;
            default:    accept;
        }
    }

    state parse_gre {
        packet.extract(hdr.gre);
        transition parse_inner_ethernet; // hay que hacer algun array de cabeceras o algo
    }

    state parse_inner_ethernet {
        packet.extract(hdr.inner_ethernet);
        verify(hdr.inner_ethernet.etherType != TYPE_IPV6, error.ParserInvalidArgument);
        transition select (hdr.inner_ethernet.etherType) {
            TYPE_IPV4:  parse_inner_ipv4;
            TYPE_ARP:   parse_arp;
            default:    accept;
        }
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        transition accept;
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/
control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata){

    counter(NUMBER_OF_HOSTS, CounterType.packets_and_bytes) ingressPktOutCounter;

    action send_to_controller_with_details(
        PuntReason_t       punt_reason,
        ControllerOpcode_t opcode)
    {
        standard_metadata.egress_spec = CPU_PORT;
        meta.ingress_port = standard_metadata.ingress_port;
        meta.punt_reason = punt_reason;
        meta.opcode = opcode;
    }
    action send_copy_to_controller(
        PuntReason_t       punt_reason,
        ControllerOpcode_t opcode,
        bit<1>             flag_tunnel)
    {
        clone_preserving_field_list(CloneType.I2E, CPU_PORT_CLONE_SESSION_ID, FL_PACKET_IN);
        meta.ingress_port = standard_metadata.ingress_port;
        meta.punt_reason = punt_reason;
        meta.opcode = opcode;
        meta.flag_tunnel = flag_tunnel;
    }
    action drop_packet() {
        mark_to_drop(standard_metadata);
    }
    action mac_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }
    action flooding () {
        standard_metadata.mcast_grp = 10;
    }
    action flow_unknown () {
        send_copy_to_controller(PuntReason_t.FLOW_UNKNOWN,
            ControllerOpcode_t.NO_OP, meta.flag_tunnel);
        drop_packet();
    }

    action detunneling ()
    {
        if (hdr.inner_ethernet.isValid()) {
            hdr.ethernet = hdr.inner_ethernet;
            hdr.inner_ethernet.setInvalid();
        }

        if (hdr.inner_ipv4.isValid()) {
            hdr.ipv4 = hdr.inner_ipv4;
            hdr.inner_ipv4.setInvalid();
        } else{
            hdr.ipv4.setInvalid();
        }
        hdr.gre.setInvalid();
        meta.flag_tunnel=1;
    }

    action arp_reply(macAddr_t switch_mac) {
        // Ethernet
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = switch_mac;

        // ARP
        hdr.arp.hType = 1; // Ethernet
        hdr.arp.pType = TYPE_IPV4;
        hdr.arp.hLen = 6;
        hdr.arp.pLen = 4;
        hdr.arp.op = 2; // Reply
        hdr.arp.sha  = switch_mac;
        hdr.arp.spa  = hdr.arp.tpa;
        hdr.arp.tha  = hdr.arp.sha;
        hdr.arp.tpa  = hdr.arp.spa;
    }


    table flow_eth {
        key = {
            hdr.ethernet.srcAddr : exact;
            hdr.ethernet.dstAddr : exact;
        }
        actions = {
            mac_forward;
            drop_packet;
            flow_unknown;
        }
        default_action = flow_unknown();
        size = 65536;
    }

    table tunnel {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            detunneling;
            NoAction;
        }
        default_action = NoAction();
        size = 65536;
    }

    // table arp_spoofing {
    //     key = {
    //         hdr.arp.tpa : exact
    //     }
    //     actions = {
    //         arp_reply;
    //         flooding;
    //     }
    //     default_action = flooding();
    //     size = 32;  // Tamaño de entradas de la tabla
    // }

    apply {
        if (standard_metadata.parser_error != error.NoError) {
            drop_packet();
            exit;
        }
        if (hdr.gre.isValid()){
            tunnel.apply();
        }


        if (hdr.packet_out.isValid()) {
            // Process packet from controller
            ingressPktOutCounter.count((bit<32>)hdr.ipv4.dstAddr[5:0]);
            switch (hdr.packet_out.opcode) {
                ControllerOpcode_t.SEND_TO_PORT_IN_OPERAND0: {
                    standard_metadata.egress_spec = (PortId_t) hdr.packet_out.operand0;
                    hdr.packet_out.setInvalid();
                }
                ControllerOpcode_t.OP_FLOOD: {
                    flooding();
                    meta.input_port = (PortId_t) hdr.packet_out.operand0;
                    hdr.packet_out.setInvalid();
                }
                ControllerOpcode_t.ARP_REPLY: {
                    macAddr_t switch_mac = (macAddr_t) hdr.packet_out.operand0;
                    arp_reply(switch_mac);
                    standard_metadata.egress_spec = (PortId_t) hdr.packet_out.reserved1;
                    hdr.packet_out.setInvalid();
                }
                default: {
                    send_to_controller_with_details(
                        PuntReason_t.UNRECOGNIZED_OPCODE,
                        hdr.packet_out.opcode);
                    hdr.packet_out.setInvalid();
                }
            }
        } else {
            flow_eth.apply();  
        }

        
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata){

    counter(NUMBER_OF_HOSTS, CounterType.packets_and_bytes) egressPktInCounter;

    action drop_packet() {
        mark_to_drop(standard_metadata);
    }

    action prepend_packet_in_hdr (
        PuntReason_t punt_reason,
        PortId_t ingress_port)
    {
        hdr.packet_in.setValid();
        hdr.packet_in.input_port = (PortIdToController_t) ingress_port;
        hdr.packet_in.punt_reason = punt_reason;
        hdr.packet_in.opcode = ControllerOpcode_t.NO_OP;
        egressPktInCounter.count((bit<32>)hdr.ipv4.dstAddr[5:0]);
    }

    action detunneling ()
    {
        if (hdr.inner_ethernet.isValid()) {
            hdr.ethernet = hdr.inner_ethernet;
            hdr.inner_ethernet.setInvalid();
        }

        if (hdr.inner_ipv4.isValid()) {
            hdr.ipv4 = hdr.inner_ipv4;
            hdr.inner_ipv4.setInvalid();
        } else{
            hdr.ipv4.setInvalid();
        }
        hdr.gre.setInvalid();
    }

    action tunneling (
        macAddr_t srcMac,
        macAddr_t dstMac,
        ip4Addr_t srcIp,
        ip4Addr_t dstIp) 
    {
        // Cabecera eth nueva
        hdr.inner_ethernet.setValid(); //Pongo inner pero luego va a ir delante, para un hacer inner = no_inner y luego modif no_inner

        hdr.inner_ethernet.srcAddr   = srcMac;
        hdr.inner_ethernet.dstAddr   = dstMac;
        hdr.inner_ethernet.etherType = TYPE_IPV4;

        // Cabecera ipv4 nueva
        hdr.inner_ipv4.setValid();  // Lo mismo para inner_ipv4, luego ademas con detunneling nos sirve el razonamiento

        hdr.inner_ipv4.version        = 4;
        hdr.inner_ipv4.ihl            = 5; // Longitud mínima (5 palabras de 32 bits = 20 bytes)
        hdr.inner_ipv4.dscp           = 0;
        hdr.inner_ipv4.ecn            = 0;
        if(hdr.ipv4.isValid()){
            hdr.inner_ipv4.totalLen       = 42 + hdr.ipv4.totalLen;  // total_len = 20 (IPv4) + 8 (GRE) + 14 (ETH) + IPv4.totalLen
        } else{
            hdr.inner_ipv4.totalLen       = 70;  // total_len = 8 (GRE) + 14 (ETH) + 28 (ARP)
        }
        hdr.inner_ipv4.identification = hdr.ipv4.identification; // Asi me quito de lios de de tener un contador
        hdr.inner_ipv4.flags          = 2; // Marco 1 en dont fragment (capturas Ram)
        hdr.inner_ipv4.fragOffset     = 0;
        hdr.inner_ipv4.ttl            = 64; // Valor por defecto común
        hdr.inner_ipv4.protocol       = GRE;
        hdr.inner_ipv4.hdrChecksum    = 0;  // El switch suele recalcularlo en el ChecksumVerify/Compute
        hdr.inner_ipv4.srcAddr        = srcIp;
        hdr.inner_ipv4.dstAddr        = dstIp;

        // Cabecera gre
        hdr.gre.setValid();

        hdr.gre.reserved0       = 0;
        hdr.gre.key_flag        = 1;
        hdr.gre.reserved1       = 0;
        hdr.gre.protocol_type   = 0x6558;
        hdr.gre.key             = 0;    // La definiré después segun me diga ram

    }

    // Lo hago en table y no directamente para poder pasarle los parametros por controller
    table tunnel {
        key = {
            standard_metadata.egress_port : exact;
        }
        actions = {
            tunneling;
            NoAction;
        }
        default_action = NoAction();
        size = 65536;
    }

    apply {
        if (standard_metadata.egress_port == standard_metadata.ingress_port
        ||  standard_metadata.egress_port == meta.input_port) {     // input_port supongo q sera cero si no viene de packet out
            drop_packet();
            exit; // Es una especie de break del apply
        }

        if (standard_metadata.egress_port == CPU_PORT) {
            if(meta.flag_tunnel == 1){
                detunneling();
            }
            prepend_packet_in_hdr(meta.punt_reason, meta.ingress_port);
            exit;
        } else if (hdr.ipv4.isValid() &&
                    (standard_metadata.ingress_port == 1 || meta.input_port == 1)){ // Solo lo marca si viene de fuera (port 1)
            switch (hdr.ipv4.protocol) {
                ICMP: {
                    hdr.ipv4.dscp = dscp_t.ICMP;
                }
                IGMP: {
                    hdr.ipv4.dscp = dscp_t.IGMP;
                }
                TCP: {
                    hdr.ipv4.dscp = dscp_t.TCP;
                }
                UDP: {
                    hdr.ipv4.dscp = dscp_t.UDP;
                }
                default: {
                    hdr.ipv4.dscp = 0;
                }
            }
        }
        else{}
        tunnel.apply();
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        update_checksum(
        hdr.ipv4.isValid(),
            {   hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp,
                hdr.ipv4.ecn,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
        
        update_checksum(
        hdr.inner_ipv4.isValid(),
            {   hdr.inner_ipv4.version,
                hdr.inner_ipv4.ihl,
                hdr.inner_ipv4.dscp,
                hdr.inner_ipv4.ecn,
                hdr.inner_ipv4.totalLen,
                hdr.inner_ipv4.identification,
                hdr.inner_ipv4.flags,
                hdr.inner_ipv4.fragOffset,
                hdr.inner_ipv4.ttl,
                hdr.inner_ipv4.protocol,
                hdr.inner_ipv4.srcAddr,
                hdr.inner_ipv4.dstAddr },
            hdr.inner_ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.packet_in);
        packet.emit(hdr.inner_ethernet);
        packet.emit(hdr.inner_ipv4);
        packet.emit(hdr.gre);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
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
