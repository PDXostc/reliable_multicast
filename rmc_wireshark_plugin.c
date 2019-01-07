// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)


#define HAVE_PLUGINS
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/to_str.h>
#include <epan/column-utils.h>
#include <epan/address.h>
#include <epan/dissectors/packet-tcp.h>
#include <ws_attributes.h>
#include <stdio.h>
#include "rmc_protocol.h"

#define RMC_UDP_PORT 4723
#define RMC_TCP_PORT 4723

const gchar plugin_version[] = "2.0";
const gchar plugin_release[] = "2.6";

static dissector_handle_t handle_rmc_multicast;
static dissector_handle_t handle_rmc_tcp;

static int proto_rmc = -1;
static int proto_rmc_packet = -1;
static int proto_rmc_resend = -1;
static int proto_rmc_ack_intv = -1;
static int proto_rmc_control = -1;

static int hf_rmc_node_id = -1;
static int hf_rmc_payload_len = -1;
static int hf_rmc_control_ip = -1;
static int hf_rmc_control_port = -1;
static int hf_rmc_packet_id = -1;
static int hf_rmc_packet_payload_len = -1;
static int hf_rmc_packet_payload = -1;
static int hf_rmc_control_command = -1;
static int hf_rmc_ack_intv_first_pid = -1;
static int hf_rmc_ack_intv_last_pid = -1;

void plugin_register(void);

static int ett_rmc = -1;
static int ett_rmc_control = -1;
static int ett_rmc_packet = -1;
static int ett_rmc_ack_intv = -1;
static int ett_rmc_resend = -1;

static void hex_dump(tvbuff_t* tvb, int start, int stop)
{
    int offset = 0;
    for(offset = start; offset <= stop; ++offset)
    {
        u_int8_t byte = tvb_get_guint8(tvb, offset);

        printf("  Offset[%d], Val[%.2X] [%.3d] ",
               offset, 
               byte & 0xFF,
               byte & 0xFF);

        if (byte > 31 && byte < 127)
            printf("[%c]\n", byte);
        else
            putchar('\n');
    }

}

static gint dissect_rmc_ack_interval(proto_tree* tree, tvbuff_t *tvb, gint offset,
                                     u_int64_t* first_pid, u_int64_t* last_pid)
{
    proto_item *ti = 0;
    proto_tree *rmc_ack_intv_tree = 0;

    ti = proto_tree_add_item(tree, proto_rmc_ack_intv, tvb, offset, -1, ENC_NA);
    rmc_ack_intv_tree = proto_item_add_subtree(ti, ett_rmc_ack_intv);

    // Do we have header data?
    if (tvb_captured_length_remaining(tvb, 0) < 16) {
//        printf("Partial ack interval. Wanted [16]. Got [%d]\n", tvb_captured_length_remaining(tvb, offset));
        return 0;
    }

    *first_pid = tvb_get_guint64(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(rmc_ack_intv_tree, hf_rmc_ack_intv_first_pid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    *last_pid = tvb_get_guint64(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(rmc_ack_intv_tree, hf_rmc_ack_intv_last_pid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return 16;
}

static guint get_rmc_packet_len(packet_info *pinfo, tvbuff_t *tvb,  int offset, void *data)
{
    return tvb_get_guint16(tvb, offset+13, ENC_LITTLE_ENDIAN) + 21;
}


static int dissect_packet_offset(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_, gint offset)
{
    proto_item *ti = 0;
    proto_tree *rmc_tree = 0;
    u_int16_t payload_len = 0;
    u_int64_t pid = 0;
    u_int32_t node_id = 0;
    gchar* ip = 0;
    char src_addr[64];
    u_int32_t ip_numeric = 0;
    u_int16_t port = 0;
     u_int64_t max_pid = 0;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RMC Packet");

 
    ti = proto_tree_add_item(tree, proto_rmc, tvb, 0, -1, ENC_NA);
    rmc_tree =  proto_item_add_subtree(ti, ett_rmc);


    // Packet ID
    pid = tvb_get_guint64(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(rmc_tree, hf_rmc_packet_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    // Context - ID
    node_id = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(rmc_tree, hf_rmc_node_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    // Payload len
    payload_len = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(rmc_tree, hf_rmc_payload_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    
    // Listen IP (little endian)
    ip_numeric = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);

    // If we have a blanc address, then substitute it with the source address IP
    if (!ip_numeric) {
        src_addr[0] = '*';
        address_to_str_buf(&pinfo->src, src_addr + 1, sizeof(src_addr)-2);
        ip = src_addr;
    } else
        ip = tvb_ip_to_str(tvb, offset);
    
    proto_tree_add_item(rmc_tree, hf_rmc_control_ip, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    // Listen port (little endian)
    port = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(rmc_tree, hf_rmc_control_port, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(rmc_tree, hf_rmc_packet_payload, tvb, offset, payload_len, ENC_NA);

    col_clear(pinfo->cinfo, COL_INFO);
    if (!pid)
        col_add_fstr(pinfo->cinfo,
                     COL_INFO,
                     "Pub ctx_id[0x%.8X] ctl_addr[%s:%d] len[%d] - announce",
                     node_id, ip, port, payload_len);
    else
        col_add_fstr(pinfo->cinfo,
                     COL_INFO,
                     "Pub ctx_id[0x%.8X] ctl_addr[%s:%d] len[%d] pid[%lu]",
                     node_id, ip, port, payload_len, pid);

    return offset;
}

static int dissect_packet_multicast(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return dissect_packet_offset(tvb, pinfo, tree, data, 0);
}

static int dissect_rmc_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree_add_item(tree, hf_rmc_control_command, tvb, 0, 1, ENC_NA);

    dissect_packet_offset(tvb, pinfo, tree, data, 1);
    ++*((int*) data);
    return tvb_captured_length(tvb);
}


static int dissect_rmc_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint offset = 0;
    proto_item *ti = 0;
    proto_tree *rmc_tree = 0;
    u_int8_t command = 0;
    u_int16_t payload_len = 0;
    u_int64_t pid = 0;
    u_int64_t first_pid = 0;
    u_int64_t last_pid = 0;
    gint res = 0;
    int rem = 0;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RMC Control Channel");
    int resend_count = 0;
    const gchar* cval = 0;

    ti = proto_tree_add_item(tree, proto_rmc_control, tvb, 0, -1, ENC_NA);
    rmc_tree = proto_item_add_subtree(ti, ett_rmc_control);

    rem =tvb_captured_length_remaining(tvb, 0) ;
    col_clear(pinfo->cinfo, COL_INFO);

    while(1) {
        if (tvb_captured_length_remaining(tvb, offset) < 1) 
            return offset;

        command = tvb_get_guint8(tvb, offset);
        switch(command) {
        case RMC_CMD_ACK_INTERVAL:
            proto_tree_add_item(rmc_tree, hf_rmc_control_command, tvb, offset, 1, ENC_NA);
            res = dissect_rmc_ack_interval(rmc_tree, tvb, offset + 1, &first_pid, &last_pid);
            cval = col_get_text(pinfo->cinfo, COL_INFO);
            if (!cval || !*cval)
                col_add_fstr(pinfo->cinfo,
                         COL_INFO,
                         "SUB->PUB ack [%lu-%lu] ",
                         first_pid, last_pid);
            else
                col_append_fstr(pinfo->cinfo,
                                COL_INFO,
                                "[%lu-%lu] ",
                                first_pid, last_pid);
                
            break;

        case RMC_CMD_PACKET:
            tcp_dissect_pdus(tvb, pinfo, rmc_tree, 1, 15, get_rmc_packet_len, dissect_rmc_packet, &resend_count);
            break;

        default:
            printf("UNKNOWN COMMAND: %d\n", command);
            return 0;
        }


        // Did we get a partial packet?
        if (res == 0) {
            break;
        }

        offset += 1 + res;
    }

    if (resend_count) 
        col_add_fstr(pinfo->cinfo, COL_INFO, "PUB->SUB resend %d packets", resend_count);


    return tvb_captured_length(tvb);
//    return offset;
}



void plugin_register_rmc(void)
{
    static const value_string command_names[] = {
        { 1, "Resend packet" },
        { 2, "Ack" },
        { 0, NULL}
    };
    
    static hf_register_info hf[] = {
        { &hf_rmc_node_id,
          { "node id", "rmc.node_id",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            "Node ID of the pubisher sending the packet", HFILL }
        },
        { &hf_rmc_payload_len,
          { "payload length", "rmc.payload_len",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            "Total payload length of the packet",  HFILL }
        },
        { &hf_rmc_control_ip,
          { "publisher control listen ip", "rmc.control_ip",
            FT_IPv4, BASE_NONE,
            NULL, 0x0,
            "Publisher control tcp socket to be connected to by subscribers", HFILL }
        },
        { &hf_rmc_control_port,
          { "publisher control listen port", "rmc.control_port",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            "Publisher control tcp socket port to be connected to by subscribers", HFILL }
        },
    };

    static hf_register_info hf_packet[] = {
        { &hf_rmc_packet_id,
          { "packet id", "rmc.packet.pid",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            "Packet ID", HFILL }
        },
        { &hf_rmc_packet_payload_len,
          { "packet payload len", "rmc.packet.payload_len",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            "Packet payload length", HFILL }
        },
        { &hf_rmc_packet_payload,
          { "packet payload", "rmc.packet.payload",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            "Packet payload", HFILL }
        },
    };

    static hf_register_info hf_control[] = {
        { &hf_rmc_control_command,
          { "command id", "rmc.control.command",
            FT_UINT8, BASE_HEX,
            VALS(command_names), 0x0,
            "Command", HFILL }
        },
    };

    static hf_register_info hf_ack_interval[] = {
        { &hf_rmc_ack_intv_first_pid,
          { "first pid", "rmc.ack.first_pid",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            "Last PID", HFILL }
        },
        { &hf_rmc_ack_intv_last_pid,
          { "last pid", "rmc.ack.last_pid",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            "Last PID", HFILL }
        },

    };
    

   /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_rmc,
        &ett_rmc_packet,
        &ett_rmc_ack_intv,
        &ett_rmc_control
    };

    
    proto_rmc = proto_register_protocol("Reliable Multicast - Data", "RMC", "rmc");
    proto_register_field_array(proto_rmc, hf, array_length(hf));
    handle_rmc_multicast = create_dissector_handle(dissect_packet_multicast, proto_rmc);

    proto_rmc_packet = proto_register_protocol("Packet", "RMC packet", "rmc.packet");
    proto_register_field_array(proto_rmc_packet, hf_packet, array_length(hf_packet));


    dissector_add_uint("udp.port", RMC_UDP_PORT, handle_rmc_multicast);


    proto_rmc_control = proto_register_protocol("Reliable Multicast - Control", "RMC Control", "rmc.control");
    proto_register_field_array(proto_rmc_control, hf_control, array_length(hf_control));
    handle_rmc_tcp = create_dissector_handle(dissect_rmc_tcp, proto_rmc_control);

//    proto_rmc_resend = proto_register_protocol("Packet resend", "Resend UDP packets via tcp", "rmc.control.resend");

    proto_rmc_ack_intv = proto_register_protocol("Interval Acknowledgement", "Interval Ack", "rmc.control.ack_interval");
    proto_register_field_array(proto_rmc_ack_intv, hf_ack_interval, array_length(hf_ack_interval));

    dissector_add_uint("tcp.port", RMC_TCP_PORT, handle_rmc_tcp);

    proto_register_subtree_array(ett, array_length(ett));
}

static void proto_reg_handoff_rmc(void)
{
}
 
void plugin_register(void)
{
    static proto_plugin plug;
 
    plug.register_protoinfo = plugin_register_rmc;
    plug.register_handoff = proto_reg_handoff_rmc; /* or NULL */
    proto_register_plugin(&plug);
}
