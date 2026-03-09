#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import argparse
import os
import sys
import asyncio
import traceback
import time
import ipaddress
import pprint

from pathlib import Path
from collections import Counter
from datetime import datetime, timedelta
from scapy.all import *

import grpc

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_sh.p4runtime as shp4rt

NSEC_PER_SEC = 1000 * 1000 * 1000

global_data = {}

global_data['CPU_PORT'] = 510
global_data['CPU_PORT_CLONE_SESSION_ID'] = 67
global_data['NUM_PORTS'] = 2
global_data['index'] = 0
global_data['mach1'] = "08:00:00:00:01:11"
global_data['mach2'] = "08:00:00:00:02:22"
global_data['mach3'] = "08:00:00:00:03:33"
global_data['mach4'] = "08:00:00:00:04:44"
global_data['mach5'] = "08:00:00:00:05:55"
global_data['mach6'] = "08:00:00:00:06:66"
global_data['mach5_2'] = "18:00:00:00:05:55"
global_data['mach6_2'] = "18:00:00:00:06:66"

## The notification database keeps track of the received idle notifications and triggers the deletion of stale flow rules.
notif_db = {}

# The lookup table is defined to simplify reachability and provide connectivity
# among hosts. In a real-world scenario, however, you should use an algorithm
# to solve this problem more effectively.

lookup_table = {}
broadcast_mcast = set()
tabla_id = {}


def get_p4_filename():
    try:
        p4_file = next(Path('.').glob('*.p4')) 
        return p4_file.stem
    except StopIteration:
        print("Error: No se encontró ningún archivo .p4 en el directorio.")
        sys.exit(1)

def ipv4ToInt(addr):
    """Take an argument 'addr' containing an IPv4 address written as a
    string in dotted decimal notation, e.g. '10.1.2.3', and convert it
    to an integer."""
    bytes_ = [int(b, 10) for b in addr.split('.')]
    assert len(bytes_) == 4
    # Note: The bytes() call below will throw exception if any
    # elements of bytes_ is outside of the range [0, 255]], so no need
    # to add a separate check for that here.
    return int.from_bytes(bytes(bytes_), byteorder='big')

def intToIpv4(n):
    """Take an argument 'n' containing a 32-bit IPv4 address as an
    integer in the range [0, 2^32-1], and return a string in dotted
    decimal notation."""
    return "%d.%d.%d.%d" % ((n >> 24) & 0xff,
                            (n >> 16) & 0xff,
                            (n >> 8) & 0xff,
                            n & 0xff)

def flowCacheEntryToDebugStr(table_entry, include_action=False):
    # TODO: The match fields are hardcoded to specific indices to retrieve specific parameters, such as hdr.ipv4.srcAddr and its value.
    src_ip = intToIpv4(int.from_bytes(table_entry.match[1].exact.value, byteorder='big'))
    dst_ip = intToIpv4(int.from_bytes(table_entry.match[2].exact.value, byteorder='big'))
    proto = int.from_bytes(table_entry.match[0].exact.value, byteorder='big')
    return ("(SA=%s, DA=%s, proto=%d)"
            "" % (src_ip, dst_ip, proto))

def decodePacketInMetadata(pktin_info, packet):
    pktin_field_to_val = {}
    for md in packet.metadata:                                  # mira cada campo de la cabecera packet in
        md_id_int = md.metadata_id                              # pilla el id (a ver si existe ese campo)
        md_val_int = int.from_bytes(md.value, byteorder='big')  # pilla el valor (no pone 'sw', 'name', es un numerito)
        assert md_id_int in pktin_info                          # se asegura que exista ese campo
        md_field_info = pktin_info[md_id_int]                   # mira en el diccionario traductor (pktin_info) q significa ese id
        pktin_field_to_val[md_field_info['name']] = md_val_int  # rellena el campo de la metadata correspondiente con el valor q sea
    ret = {'metadata': pktin_field_to_val,
           'payload': packet.payload}
    print("decodePacketInMetadata: ret=%s" % (ret))
    return ret

def serializableEnumDict(p4info_data, name):
    type_info = p4info_data.type_info   # type info es donde se guardan los enums y structs y demas dentro de p4info
    name_to_int = {}
    int_to_name = {}

    # 3. Itera sobre cada opción del Enum (ej: FLOW_UNKNOWN)
    # 'name' aquí sería "PuntReason_t" que le pasas como argumento
    for member in type_info.serializable_enums[name].members:
        name = member.name
        int_val = int.from_bytes(member.value, byteorder='big')
        name_to_int[name] = int_val
        int_to_name[int_val] = name
    print("serializableEnumDict: name='%s' name_to_int=%s int_to_name=%s"
                  "" % (name, name_to_int, int_to_name))
    # Devuelve diccionarios para hacer las conversiones esas
    return name_to_int, int_to_name

#funciones para hacer legible el p4info

# le pides el objeto del diccionario gigante y el tipo y el nombre de lo q quieres buscar (e.g. ("tables", "flow_cache"))
def getObj(p4info_obj_map, obj_type, name):
    key = (obj_type, name)
    return p4info_obj_map.get(key, None)

def controllerPacketMetadataDictKeyId(p4info_obj_map, name):
    # Busca el bloque de metadatos específico en el mapa global.
    # Normalmente 'name' será "packet_in" (el nombre que pusiste en @controller_header).
    # 'cpm' significa Controller Packet Metadata.
    cpm_info = getObj(p4info_obj_map, "controller_packet_metadata", name)
    assert cpm_info != None
    ret = {}
    for md in cpm_info.metadata:
        id = md.id
        ret[md.id] = {'id': md.id, 'name': md.name, 'bitwidth': md.bitwidth}
    return ret

# Convierte un diccionario gigante donde puedes buscar cosas por su nombre corto o largo.
# Escribes getObj(..., "flow_cache") en lugar de getObj(..., "MyIngress.flow_cache")
# (o únicamente por el larga si hay nombres cortos que puedan hacer referencia a dos cosas,
# e.g. MyIngress.tabla1 y MyEgress.tabla1)
def makeP4infoObjMap(p4info_data):
    
    p4info_obj_map = {}
    suffix_count = Counter()
    for obj_type in ["tables", "action_profiles", "actions", "counters",
                     "direct_counters", "controller_packet_metadata"]:
        for obj in getattr(p4info_data, obj_type):
            pre = obj.preamble
            suffix = None
            for s in reversed(pre.name.split(".")):
                suffix = s if suffix is None else s + "." + suffix
                key = (obj_type, suffix)
                p4info_obj_map[key] = obj
                suffix_count[key] += 1 # para control de ambiguedad
    for key, c in list(suffix_count.items()):
        if c > 1:
            del p4info_obj_map[key]
    return p4info_obj_map

def writeCloneSession(sw, clone_session_id, replicas):
    # Size 0 bmv2 does not support truncation for clones, issue behavioral-model #996
    # 1. Construye el mensaje de configuración (la orden)
    # - clone_session_id: 67
    # - replicas: Es una lista de puertos destino junto a instancias (como una especie de IDs para diferenciar replicas).
    # - 0: Esto es la "truncación". Un 0 significa "copia el paquete entero".
    #   (El comentario dice que BMv2 falla si intentas cortar el paquete, así que ponemos 0 por seguridad).
    clone_entry = global_data['p4info_helper'].buildCloneSessionEntry(clone_session_id, replicas, 0)

    # 2. Envía la orden al switch
    # Escribe esta regla en la tabla del Motor de Replicación.
    sw.WritePREEntry(clone_entry)

def addFlowRule( ingress_sw, src_eth_addr, dst_eth_addr, srcport, dstport, tunnel_id):
    """
    Install flow rule in flow cache table

    """

    table_entry = global_data['p4info_helper'].buildTableEntry(
        table_name="MyIngress.switch_id",
        match_fields={
            "meta.key_tunnel":      tunnel_id,
            "hdr.ethernet.srcAddr": src_eth_addr,
            "hdr.ethernet.dstAddr": dst_eth_addr
        },
        action_name="MyIngress.forwarding",
        action_params={
            "port":           dstport
        }
        )
    ingress_sw.WriteTableEntry(table_entry)

    table_entry2 = global_data['p4info_helper'].buildTableEntry(
        table_name="MyIngress.switch_id",
        match_fields={
            "meta.key_tunnel":      tunnel_id,
            "hdr.ethernet.srcAddr": dst_eth_addr,
            "hdr.ethernet.dstAddr": src_eth_addr
        },
        action_name="MyIngress.forwarding",
        action_params={
            "port":           srcport
        }
        )
    ingress_sw.WriteTableEntry(table_entry2)

# ctrl + / para comentar, descomentar todo
def packetOutMetadataList(opcode, reserved1, operand0):
    # This function does not use the generated contents of the P4Info
    # file to map PacketOut metadata fields to indices.  If you change
    # the PacketOut metadata format in the P4 program, this code must
    # be manually updated to match.
    return [{"value": opcode, "bitwidth": 8},
            {"value": reserved1, "bitwidth": 8},
            {"value": operand0, "bitwidth": 32}]


def sendPacketOut(sw ,payload, metadatas):
    sw.PacketOut(payload, metadatas)

def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print('\n----- Reading tables rules for %s -----' % sw.name)
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            
            # 1. TRADUCIR EL NOMBRE DE LA TABLA
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print("Table: %s" % table_name)
            
            # 2. TRADUCIR LOS CAMPOS DE MATCH (Match Fields)
            for m in entry.match:
                # Obtener el nombre del campo (ej: hdr.ethernet.dstAddr)
                match_field_name = p4info_helper.get_match_field_name(table_name, m.field_id)
                
                # Decodificar el valor (dependiendo de si es exact, lpm, etc.)
                # Nota: p4info_helper a veces tiene metodos para esto, pero aqui lo hacemos generico:
                match_value = ""
                if m.exact.value:
                    # Convertir bytes a Hex (ej: 00:00:00...)
                    match_value = ':'.join('{:02x}'.format(b) for b in m.exact.value)
                elif m.lpm.value:
                    val = ':'.join('{:02x}'.format(b) for b in m.lpm.value)
                    match_value = "{} / {}".format(val, m.lpm.prefix_len)
                
                print("  Match: %s = %s" % (match_field_name, match_value))

            # 3. TRADUCIR LA ACCIÓN
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print("  Action: %s" % action_name)
            
            # 4. TRADUCIR LOS PARÁMETROS DE LA ACCIÓN
            for p in action.params:
                param_name = p4info_helper.get_action_param_name(action_name, p.param_id)
                # Convertir el valor del parametro a entero o hex
                # 'byteorder="big"' es estándar en redes
                val_int = int.from_bytes(p.value, byteorder='big')
                print("    Arg: %s = %d" % (param_name, val_int))
            
            print('-----')

def printCounter(p4info_helper, sw, counter_name, index):
    """
    Reads the specified counter at the given index from the switch. In our
    program, the index is derived from the first 6 bits of the IP destination address.
    If the index is 0, it will return all values from the counter.

    :param p4info_helper: the P4Info helper
    :param sw:  the switch connection
    :param counter_name: the name of the counter from the P4 program
    :param index: the counter index (in our case, first 6 bits of the IP)
    """
    try:
        for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
            for entity in response.entities:
                counter = entity.counter_entry
                print("%s %s %d: %d packets (%d bytes)" % (
                    sw.name, counter_name, index,
                    counter.data.packet_count, counter.data.byte_count
                ))
    except grpc.RpcError as e:
           print(f"[gRPC Error in printCounter for {sw.name}]")
           printGrpcError(e)

           if e.code() == grpc.StatusCode.UNKNOWN:
            print(f"Unknown gRPC error from {sw.name}. Retrying...")
            time.sleep(2)

    except Exception as e:
           print(f"[Unexpected Error in printCounter for {sw.name}]: {e}")
           traceback.print_exc()
           time.sleep(2)

def broadcasting(sw, input_port, payload, src_eth):
    if sw not in broadcast_mcast:
        if sw.name == 's3':
            replicas = [{'egress_port': p, 'instance': 1} for p in [1, 3]]
            mcast_entry = global_data['p4info_helper'].buildMulticastGroupEntry(10, replicas) #esta hardcodeado el mgid
            sw.WritePREEntry(mcast_entry)

            replicas = [{'egress_port': p, 'instance': 1} for p in [1, 2]]
            mcast_entry = global_data['p4info_helper'].buildMulticastGroupEntry(20, replicas) #esta hardcodeado el mgid
            sw.WritePREEntry(mcast_entry)
        elif sw.name == 's7':
            replicas = [{'egress_port': p, 'instance': 1} for p in [1, 3]]
            mcast_entry = global_data['p4info_helper'].buildMulticastGroupEntry(20, replicas) #esta hardcodeado el mgid
            sw.WritePREEntry(mcast_entry)

            replicas = [{'egress_port': p, 'instance': 1} for p in [2, 3]]
            mcast_entry = global_data['p4info_helper'].buildMulticastGroupEntry(10, replicas) #esta hardcodeado el mgid
            sw.WritePREEntry(mcast_entry)
        elif sw.name == 's1' or sw.name == 's5' or sw.name == 's6':
            replicas = [{'egress_port': p, 'instance': 1} for p in [1, 2]]
            mcast_entry = global_data['p4info_helper'].buildMulticastGroupEntry(10, replicas) #esta hardcodeado el mgid
            sw.WritePREEntry(mcast_entry)
        else:
            replicas = [{'egress_port': p, 'instance': 1} for p in [1, 2, 3]]
            mcast_entry = global_data['p4info_helper'].buildMulticastGroupEntry(10, replicas) #esta hardcodeado el mgid
            sw.WritePREEntry(mcast_entry)

        broadcast_mcast.add(sw)

    if (input_port==2 and sw.name=='s3') or (input_port==1 and sw.name=='s7'):
        mcast=20
    elif input_port==1 and src_eth == global_data["mach2"] and (sw.name=='s3' or sw.name=='s7'):
        mcast=20
    elif input_port==3 and sw.name=='s7':
        mcast=20
        metadatas = packetOutMetadataList(
                        global_data['controller_opcode_name2int']['OP_FLOOD'],
                        mcast, input_port)
        sendPacketOut(sw, payload, metadatas)
        mcast=10
    else:
        mcast=10
    metadatas = packetOutMetadataList(
                        global_data['controller_opcode_name2int']['OP_FLOOD'],
                        mcast, input_port)
    sendPacketOut(sw, payload, metadatas)

def processPacket(message):
        payload = message["packet-in"].payload
        packet = message["packet-in"]
        print("Received PacketIn message of length %d bytes from switch %s"
              "" % (len(payload), message["sw"].name))
        if len(payload) > 0:
            i = 0
            pkt = Ether(payload)
            src_eth_addr = pkt.src
            dst_eth_addr = pkt.dst
            pktinfo = decodePacketInMetadata(global_data['cpm_packetin_id2data'], packet)
            
            debug_packetin = False
            if debug_packetin:
                i += 1
                print("")
                print("pktin %d of %d" % (i, len(payload)))
                print("type(pktin.packet.payload)=%s"
                      "" % (type(payload)))
                print(payload)
                print(pktinfo)
                print("Scapy decode:")
                print(pkt)
                print("MAC SA %s (type %s)"
                      "" % (src_eth_addr, type(src_eth_addr)))
                print("MAC DA %s (type %s)"
                      "" % (dst_eth_addr, type(dst_eth_addr)))
                print(pktinfo['metadata']['punt_reason'])

            if pktinfo['metadata']['punt_reason'] == global_data['punt_reason_name2int']['FLOW_UNKNOWN']:
                tabla_actual = lookup_table.get(message["sw"].name, {})
                srcport = pktinfo["metadata"]['input_port']
                if src_eth_addr not in tabla_actual:
                    print(">> Me apunto la MAC src pq no la tengo")
                    lookup_table[message["sw"].name][src_eth_addr] = srcport
                
                if dst_eth_addr == "ff:ff:ff:ff:ff:ff":
                    print(">> Detectado Broadcast MAC. Instalando regla de flooding...")
                    broadcasting(message["sw"], srcport, payload, src_eth_addr)
                elif dst_eth_addr in tabla_actual:
                    dstport = lookup_table[message["sw"].name][dst_eth_addr]
                    tunnel_id = pktinfo['metadata']['key_tunnel']
                    addFlowRule(message["sw"], src_eth_addr, dst_eth_addr, srcport, dstport, tunnel_id)

                    print(">> Creando regla bidireccional")
                    metadatas = packetOutMetadataList(
                        global_data['controller_opcode_name2int']['SEND_TO_PORT_IN_OPERAND0'],
                        0, dstport)
                
                    sendPacketOut(message["sw"], payload, metadatas)

                readTableRules(global_data['p4info_helper'], message["sw"])
                print(tabla_actual)


async def processNotif(notif_queue):
        while True:
            notif = await notif_queue.get()
            debug_notif = True
            if debug_notif:
                print(notif)
                pprint.pprint(notif_db)
            if notif["type"] == "packet-in":
                processPacket(notif)
                printCounter(global_data ['p4info_helper'], notif["sw"], 'MyIngress.ingressPktOutCounter', global_data ['index'])
                printCounter(global_data ['p4info_helper'], notif["sw"], 'MyEgress.egressPktInCounter', global_data ['index'])
                if debug_notif:
                    readTableRules(global_data ['p4info_helper'], notif["sw"])
            notif_queue.task_done()

async def packetInHandler(notif_queue,sw):
    # TODO: Implement the function logic to handle a packet-in message
    while True:
        try:
            packet_in = await asyncio.to_thread(sw.PacketIn)
            #print(f"Received packet: {packet_in}")
            message = {"type": "packet-in", "sw": sw, "packet-in": packet_in}
            await notif_queue.put(message)

        except grpc.RpcError as e:
            print(f"[gRPC Error in packetInHandler for {sw.name}]")
            printGrpcError(e)

            if e.code() == grpc.StatusCode.UNKNOWN:
                print(f"Unknown gRPC error from {sw.name}. Retrying...")
            await asyncio.sleep(2)

        except Exception as e:
            print(f"[Unexpected Error in packetInHandler for {sw.name}]: {e}")
            traceback.print_exc()
            await asyncio.sleep(2)

def printGrpcError(e):
    print("gRPC Error:", e.details(), end=' ')
    status_code = e.code()
    print("(%s)" % status_code.name, end=' ')
    traceback = sys.exc_info()[2]
    print("[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))

async def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    global_data ['p4info_helper'] = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
    p4info_helper = global_data ['p4info_helper']

    try:
        # Create a switch connection object for s1,s2,s3;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        # Supongamos que tienes la info de los switches en una lista de dicts
        switches_info = [
            {"name": "s1", "address": "127.0.0.1:50051", "device_id": 0},
            {"name": "s2", "address": "127.0.0.1:50052", "device_id": 1},
            {"name": "s3", "address": "127.0.0.1:50053", "device_id": 2},
            {"name": "s4", "address": "127.0.0.1:50054", "device_id": 3},
            {"name": "s5", "address": "127.0.0.1:50055", "device_id": 4},
            {"name": "s6", "address": "127.0.0.1:50056", "device_id": 5},
            {"name": "s7", "address": "127.0.0.1:50057", "device_id": 6}
        ]

        # Diccionarios para mantener conexiones y tablas de lookup
        switch_connections = {}

        # Crear las conexiones y configurar los switches
        for sw in switches_info:
            conn = p4runtime_lib.bmv2.Bmv2SwitchConnection(
                name=sw["name"],
                address=sw["address"],
                device_id=sw["device_id"],
                proto_dump_file=f'logs/{sw["name"]}-p4runtime-requests.txt'
            )
            
            # Guardar conexión y tabla de lookup
            switch_connections[sw["name"]] = conn
            lookup_table[sw["name"]] = {}
            tabla_id[sw["name"]] = set()

            # Master arbitration
            conn.MasterArbitrationUpdate()

            # Instalar el P4 program
            conn.SetForwardingPipelineConfig(
                p4info=p4info_helper.p4info,
                bmv2_json_file_path=bmv2_file_path
            )
            print(f"Installed P4 Program using SetForwardingPipelineConfig on {sw['name']}")

        # Configurar global_data (solo se hace una vez)
        global_data['p4info_obj_map'] = makeP4infoObjMap(p4info_helper.p4info)
        global_data['cpm_packetin_id2data'] = \
            controllerPacketMetadataDictKeyId(global_data['p4info_obj_map'], "packet_in")

        global_data['punt_reason_name2int'], global_data['punt_reason_int2name'] = \
            serializableEnumDict(p4info_helper.p4info, 'PuntReason_t')
        global_data['controller_opcode_name2int'], global_data['controller_opcode_int2name'] = \
            serializableEnumDict(p4info_helper.p4info, 'ControllerOpcode_t')

        # Configurar sesiones de clone
        replicas = [{"egress_port": global_data['CPU_PORT'], "instance": 1}]
        for sw in switch_connections.values():
            try:
                writeCloneSession(sw, global_data['CPU_PORT_CLONE_SESSION_ID'], replicas)
            except shp4rt.P4RuntimeWriteException:
                print(f"Clone session {global_data['CPU_PORT_CLONE_SESSION_ID']} assumed initialized already")

        # Crear cola de notificaciones y tareas asyncio
        notif_queue = asyncio.Queue()

        pkt_tasks = [
            asyncio.create_task(packetInHandler(notif_queue, sw_conn))
            for sw_conn in switch_connections.values()
        ]

        proc_notif = asyncio.create_task(processNotif(notif_queue))

        # Ejecutar todas las tareas
        await asyncio.gather(*pkt_tasks, proc_notif)

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        print(f"gRPC error occurred: {e}")
        print(f"Status code: {e.code()}")  # e.g., StatusCode.UNAVAILABLE or StatusCode.INVALID_ARGUMENT
        print(f"Details: {e.details()}")

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    p4_name = get_p4_filename()
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default=f'./build/{p4_name}.p4.p4info.txtpb')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default=f'./build/{p4_name}.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    asyncio.run(main(args.p4info, args.bmv2_json))
