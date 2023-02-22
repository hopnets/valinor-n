import sys

############### User-defined config ##########################################
def main():
    """
    The below section must be filled based on your testbed setup. *Marked items are required by default
    hw_activeports_l2: maps destination mac addresses to devports. example entry: {(124, "ab:ab:ab:ab:ab:ab", 0), ()}
    hw_activeports_l3*: maps destination IPv4 addresses to devports. This is the default forwarding table to fill. example entry: {(124, "10.1.1.3", 0), ()}
    hw_devports_enabled*: list of devports to be enabled. eg [124, 128, 132]
    hw_mirror_source_ports_l3*: list of destination IPv4 addresses that will be captured by Valinor framework. e.g., ["10.1.1.3", "10.1.1.4"]
    MIRROR_SESSION*: harcoded to 11
    MIRROR_DESTINATION_HW*: devport to send Valinor timestamp packets to
    MAX_PKT_LEN*: mirrored packets will be trimmed to this size 
    """
    import socket
    hw_activeports_l2 = {}
    hw_activeports_l3 = {}
    hw_devports_enabled= []
    hw_mirror_source_ports_l3 = []
    model_mirror_source_ports_l3 = []
    model_activeports_l2 = {}
    model_activeports_l3 = {}
    MIRROR_SESSION = 11
    MIRROR_DESTINATION_MODEL = 5
    MIRROR_DESTINATION_HW = 168
    MAX_PKT_LEN = 160
##############################################################################


    def devport(pipe, port):
        return ((pipe & 3) << 7) | (port & 0x7F)

    def pipeport(dp):
        return ((dp & 0x180) >> 7), (dp & 0x7F)

    def mcport(pipe, port):
        return pipe * 72 + port

    p4 = bfrt.vswitch.pipe

    def retrieve_ports():
        """
        Retrieves all ports from the hardware port config tables.
        Be sure to setup_ports first before running this function!
        """
        allports = {
                    dp.key[b'$DEV_PORT']
                    for dp in bfrt.port.port.get(regex=1, return_ents=True, print_ents=False)
                }
        print("retrieved all ports:")
        print(allports)
        print("================================")
        return allports

    def setup_ports():
        """
        Used to access fixed-function APIs and enable hardware ports.
        """
        print("Setting up ports")
        for dp in hw_devports_enabled:
            bfrt.port.port.add(DEV_PORT=dp, AUTO_NEGOTIATION="PM_AN_FORCE_DISABLE", SPEED="BF_SPEED_40G", FEC="BF_FEC_TYP_NONE", PORT_ENABLE=True)
        print("================================")


    def setup_bcast(allports):
        """
        Used to setup broadcast support.
        Broadcast will be enable for bcast MAC addresses and all packets with unknown destination ports.
        Source port pruning is also configured here.
        """
        bfrt.pre.node.entry(MULTICAST_NODE_ID=1, MULTICAST_RID=0xFFFF,
                            MULTICAST_LAG_ID=[], DEV_PORT=allports).push()
        bfrt.pre.mgid.entry(MGID=1,
                            MULTICAST_NODE_ID=[1],
                            MULTICAST_NODE_L1_XID_VALID=[False],
                            MULTICAST_NODE_L1_XID=[0]).push()
        print("Multicast domain 1 configured")
        for dp in allports:
            print("Configuring port {} metadata".format(dp))
            l2_xid = mcport(*pipeport(dp))
            p4.SwitchIngressParser.PORT_METADATA.entry(ingress_port=dp, port_pcp=0, port_vid=0, l2_xid=l2_xid).push()
            print("Configuring port {} for broadcast pruning".format(dp))
            bfrt.pre.prune.entry(MULTICAST_L2_XID=l2_xid, DEV_PORT=[dp]).push()
        print("================================")


    def setup_forwarding(hwmode):
        """ 
            Used to setup forwarding tables and optionally destination-based timestamping.
            Populate activeports_l2 or activeports_l3 tables to populate these tables.
        """
        print("Initializing forwarding tables")
        if hwmode:
            for dp, mac in hw_activeports_l2.items():
                p4.SwitchIngress.vswitch_l2.add_with_set_output_port(dest_port=dp, dst_addr=mac, ing_mir=1, ing_ses=MIRROR_SESSION)
                print("entry added")

            for item in hw_activeports_l3:
                p4.SwitchIngress.vswitch_l3.add_with_set_output_port(dest_port=item[0], dst_addr=item[1], ing_mir=item[2], ing_ses=MIRROR_SESSION)
                print("entry added")
            for i in range(30, 250):
                p4.SwitchIngress.vswitch_l3.add_with_set_output_port(dest_port=180, dst_addr="10.1.1.{}".format(i), ing_mir=0, ing_ses=MIRROR_SESSION)
                print("entry added")

        else:
            for dp, mac in model_activeports_l2.items():
                p4.SwitchIngress.vswitch_l2.add_with_set_output_port(dest_port=dp, dst_addr=mac, ing_mir=1, ing_ses=MIRROR_SESSION)
                print("entry added")

            for dp, ip in model_activeports_l3.items():
                p4.SwitchIngress.vswitch_l3.add_with_set_output_port(dest_port=dp, dst_addr=ip, egr_mir=1, egr_ses=MIRROR_SESSION)
                print("entry added")
        print("================================")


    def setup_mirror(mir_dest):
        """ 
            Used to setup mirror cfg table in Tofino
        """
        print("Setting up mirroring for timestamper ...")
        bfrt.mirror.cfg.add_with_normal(sid=MIRROR_SESSION, direction="EGRESS", ucast_egress_port=mir_dest, ucast_egress_port_valid=True, session_enable=True, max_pkt_len=MAX_PKT_LEN)


    def setup_source_mirroring(hw_mode=True):
        """ 
            Used to setup timestamping based on source IP address.
            Add source IP entries in "hw_mirror_source_ports_l3" list .
        """
        print("Setting up mirring+timestamping based on source IP")
        if hw_mode:
            for item in hw_mirror_source_ports_l3:
                p4.SwitchIngress.mirror_source_l3.add_with_set_mirror_status(src_addr=item, egr_mir=1, egr_ses=MIRROR_SESSION)
            for i in range(30, 250):
                p4.SwitchIngress.mirror_source_l3.add_with_set_mirror_status(src_addr="10.1.1.{}".format(i), egr_mir=1, egr_ses=MIRROR_SESSION)
        else:
            for item in model_mirror_source_ports_l3:
                p4.SwitchIngress.mirror_source_l3.add_with_set_mirror_status(src_addr=item, egr_mir=1, egr_ses=MIRROR_SESSION)

    
    def display_help():
        """ Display help message """
        print("Valinor measurement framework - Tofino control-plane setup")
        print("Usage: `$SDE/run_bfshell.sh -b THIS_SCRIPT [help] [setup_mirror] [setup_ports] [setup_bcast] [setup_forwarding] [setup_source_mirroring]`")
        print("If you don't provide a flag, all setup scripts will be executed.")
        print("Otherwise, prove the list of flags you want to execute.")
        print("Refer to the script for configuration items and function descriptions.")

    hostname = socket.gethostname()
    hw_mode = hostname == "localhost"
    display_help()
    if hw_mode:
        setup_ports()
        setup_mirror(MIRROR_DESTINATION_HW)
    else:
        setup_mirror(MIRROR_DESTINATION_MODEL)
    allports = retrieve_ports()
    setup_bcast(allports)
    setup_forwarding(hw_mode)
    setup_source_mirroring(hw_mode)

main()
