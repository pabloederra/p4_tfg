#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import argparse
import os
import sys
import threading

import traceback
import time
import ipaddress
import pprint
import json

from pathlib import Path
from collections import Counter
from datetime import datetime, timedelta
from scapy.all import *

import grpc

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../utils/'))
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
global_data['macs'] = {}
global_data['macs']['mach1'] = "08:00:00:00:01:11"
global_data['macs']['mach2'] = "08:00:00:00:02:22"
global_data['macs']['mach3'] = "08:00:00:00:03:33"
global_data['macs']['mach4'] = "08:00:00:00:04:44"
global_data['macs']['mach5'] = "08:00:00:00:05:55"
global_data['macs']['mach6'] = "08:00:00:00:06:66"
global_data['mach5_2'] = "18:00:00:00:05:55"
global_data['mach6_2'] = "18:00:00:00:06:66"
global_data["timeout"] = 1000000   # 1 milisegundos



## The notification database keeps track of the received idle notifications and triggers the deletion of stale flow rules.
notif_db = {}

# The lookup table is defined to simplify reachability and provide connectivity
# among hosts. In a real-world scenario, however, you should use an algorithm
# to solve this problem more effectively.

lookup_table = {}
tabla_id = {}

import builtins
from datetime import datetime

# Guarda el print original por si acaso
original_print = builtins.print

def print(*args, **kwargs):
    # Formato: Hora:Minuto:Segundo.Milisegundos
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    original_print(f"[{timestamp}]", *args, **kwargs)

def get_p4_config_from_topo(topo_file='./topology.json'):
    if not os.path.exists(topo_file):
        print(f"Error: Topology file {topo_file} not found.")
        exit(1)

    with open(topo_file, 'r') as f:
        topo = json.load(f)

    switches_conf = {}

    for sw_name, sw_data in topo['switches'].items():
        # Obtenemos la ruta del JSON definida en la topología (ej: "build/router.json")
        json_path = sw_data.get('json_path')
        
        if not json_path:
            print(f"Warning: Switch {sw_name} has no json_path in topology.")
            continue

        # Deducimos el nombre base y el p4info
        # ej: "build/router.json" -> base: "router"
        base_name = os.path.splitext(os.path.basename(json_path))[0]
        
        # Asumimos la estructura estándar de p4c para el p4info
        # build/router.json -> build/router.p4.p4info.txtpb
        # Nota: Ajusta la ruta si tu makefile lo guarda en otro sitio
        p4info_path = f"./build/{base_name}.p4.p4info.txtpb"

        if not os.path.exists(p4info_path):
            print(f"Error: P4Info file not found for {sw_name}: {p4info_path}")
            exit(1)
            
        switches_conf[sw_name] = {
            'bmv2_json': json_path,
            'p4info': p4info_path,
            'program_name': base_name
        }
    
    return switches_conf

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

def intToMac(n):
    mac_hex = f"{n:012X}"  # 12 dígitos hex, relleno con ceros
    mac_str = ":".join(mac_hex[i:i+2] for i in range(0, 12, 2))

    return(mac_str.lower())


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

def decodeDigestList(digest_info, digest_list_msg):
    """
    digest_info: Lista con los nombres de los campos en orden (ej: ['ingress_port', 'src_mac'])
    digest_list_msg: El mensaje gRPC que recibiste (notif['payload'])
    """
    decoded_entries = []
    
    # 1. Un DigestList contiene MUCHAS entradas (data)
    for data_item in digest_list_msg.data:
        entry_dict = {}
        
        # 2. Cada entrada es un struct con miembros ordenados
        # digest_info debe tener los nombres en el mismo orden que el struct P4
        members = data_item.struct.members
        
        for i, member in enumerate(members):
            field_name = digest_info[i]['name'] # Obtenemos nombre por posición
            
            # El valor suele venir en 'bitstring' para datos simples
            val_int = int.from_bytes(member.bitstring, byteorder='big')
            
            entry_dict[field_name] = val_int
            
        decoded_entries.append(entry_dict)
        
    print(f"decodeDigestList: decoded {len(decoded_entries)} entries")
    return decoded_entries

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

def writeCloneSession(sw, clone_session_id, replicas, prog):
    # Size 0 bmv2 does not support truncation for clones, issue behavioral-model #996
    # 1. Construye el mensaje de configuración (la orden)
    # - clone_session_id: 67
    # - replicas: Es una lista de puertos destino junto a instancias (como una especie de IDs para diferenciar replicas).
    # - 0: Esto es la "truncación". Un 0 significa "copia el paquete entero".
    #   (El comentario dice que BMv2 falla si intentas cortar el paquete, así que ponemos 0 por seguridad).
    clone_entry = global_data['p4info_helper'][prog].buildCloneSessionEntry(clone_session_id, replicas, 0)

    # 2. Envía la orden al switch
    # Escribe esta regla en la tabla del Motor de Replicación.
    sw.WritePREEntry(clone_entry)

def modificar_puerto(puerto, tunnel_id):
        # Si el puerto es 1, se queda exactamente igual
        if puerto < 10:
            return puerto
        
        # Si no es 1, le quitamos el último dígito ([:-1]) y le pegamos el del túnel
        puerto_str = str(puerto)
        tunel_str=str(tunnel_id)
        nuevo_puerto_str = puerto_str[:-1] + tunel_str[-1]
        
        return int(nuevo_puerto_str) # Lo devolvemos como número entero

def addFlowRule( ingress_sw, src_eth_addr, dst_eth_addr, srcport, dstport, tunnel_id, prog):
    """
    Install flow rule in flow cache table

    """

    # Aplicamos la lógica a ambos puertos
    sport = modificar_puerto(srcport, tunnel_id)
    dport = modificar_puerto(dstport, tunnel_id)

    table_entry = global_data['p4info_helper'][prog].buildTableEntry(
        table_name="MyIngress.switch_id",
        match_fields={
            "meta.key_tunnel":      tunnel_id,
            "hdr.ethernet.srcAddr": src_eth_addr,
            "hdr.ethernet.dstAddr": dst_eth_addr
        },
        action_name="MyIngress.forwarding",
        action_params={
            "port":           dport
        }
        )

    table_entry2 = global_data['p4info_helper'][prog].buildTableEntry(
        table_name="MyIngress.switch_id",
        match_fields={
            "meta.key_tunnel":      tunnel_id,
            "hdr.ethernet.srcAddr": dst_eth_addr,
            "hdr.ethernet.dstAddr": src_eth_addr
        },
        action_name="MyIngress.forwarding",
        action_params={
            "port":           sport
        }
        )
    
    rules_to_write = [table_entry, table_entry2]

    for rule in rules_to_write:
        try:
            ingress_sw.WriteTableEntry(rule)
            print(f"Instalando regla: unidireccional")
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.ALREADY_EXISTS:
                print(f"WARNING: Cuidao, regla duplicada ignorada en {ingress_sw.name}")
            else:
                printGrpcError(e)
    

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

def broadcasting(sw, input_port, payload, src_eth, prog):

    mcast=10
    if sw.name == 's3':
        if input_port in [121, 123]:
            mcast = 20
        elif input_port == 1 and src_eth == global_data['macs']["mach2"]:
            mcast = 20

    elif sw.name == 's7':
        if input_port == 1: 
            mcast = 20
        elif input_port == 3:
            mcast = 20
            # Enviamos copia al mcast 20
            metadatas = packetOutMetadataList(
                            global_data['controller_opcode_name2int'][prog]['OP_FLOOD'],
                            mcast, input_port)
            sendPacketOut(sw, payload, metadatas)
            # Volvemos a 10 para el flujo principal que ocurra después
            mcast = 10
    
    metadatas = packetOutMetadataList(
                        global_data['controller_opcode_name2int'][prog]['OP_FLOOD'],
                        mcast, input_port)
    sendPacketOut(sw, payload, metadatas)

def broadcasting_digest(ingress_sw, prog, src_eth_addr, mcast, srcport):
    table_entry = global_data['p4info_helper'][prog].buildTableEntry(
        table_name="MyIngress.broadcasting",
        match_fields={
            "meta.inport": srcport,
            "hdr.ethernet.srcAddr": src_eth_addr
        },
        action_name="MyIngress.flooding",
        action_params={
            "mcast":           mcast
        }
        )
    ingress_sw.WriteTableEntry(table_entry)
    print(f"La table entrey deberia ser esta: {table_entry}")

def processPacket(message, prog):
        payload = message["packet-in"].payload
        packet = message["packet-in"]
        print("Received PacketIn message of length %d bytes from switch %s"
              "" % (len(payload), message["sw"].name))
        if len(payload) > 0:
            i = 0
            pkt = Ether(payload)
            src_eth_addr = pkt.src
            dst_eth_addr = pkt.dst
            pktinfo = decodePacketInMetadata(global_data['cpm_packetin_id2data'][prog], packet)
            
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

            if pktinfo['metadata']['punt_reason'] == global_data['punt_reason_name2int'][prog]['FLOW_UNKNOWN']:
                tabla_actual = lookup_table.get(message["sw"].name, {})
                srcport = pktinfo["metadata"]['input_port']
                if src_eth_addr not in tabla_actual:
                    print(">> Me apunto la MAC src pq no la tengo")
                    lookup_table[message["sw"].name][src_eth_addr] = srcport
                
                if dst_eth_addr == "ff:ff:ff:ff:ff:ff":
                    print(">> Detectado Broadcast MAC. Instalando regla de flooding...")
                    broadcasting(message["sw"], srcport, payload, src_eth_addr, prog)
                elif dst_eth_addr in tabla_actual:
                    dstport = lookup_table[message["sw"].name][dst_eth_addr]
                    tunnel_id = pktinfo['metadata']['key_tunnel']
                    addFlowRule(message["sw"], src_eth_addr, dst_eth_addr, srcport, dstport, tunnel_id, prog)

                    metadatas = packetOutMetadataList(
                        global_data['controller_opcode_name2int'][prog]['SEND_TO_PORT_IN_OPERAND0'],
                        0, modificar_puerto(dstport, tunnel_id))
                    print("Sacando packet_out")
                    sendPacketOut(message["sw"], payload, metadatas)

                #readTableRules(global_data['p4info_helper'][prog], message["sw"])
                #print(tabla_actual)

def processDigest(message, prog):
    # Usamos un set para procesar solo una vez cada flujo en esta ráfaga
    processed_flows = set()
    # Ejemplo de cómo se vería la info que necesitas pasarle a la función
    # Esto debe coincidir con tu struct digest_t en P4
    digest_field_names = [
        {'name': 'ingress_port'},
        {'name': 'key_tunnel'}, 
        {'name': 'src_mac'}, 
        {'name': 'dst_mac'}
    ]

    # Uso:
    decoded_data = decodeDigestList(digest_field_names, message["payload"])

    payload = message["payload"].data
    print("Received digestIn message of length %d bytes from switch %s"
            "" % (len(payload), message["sw"].name))
    # 3. Recorremos los datos decodificados
    for entry in decoded_data:
        srcport = entry['ingress_port']
        src_mac = entry['src_mac']
        dst_mac = entry['dst_mac']
        key_tunnel = entry['key_tunnel']
        
        # Creamos un identificador único para este flujo
        flow_id = (srcport, src_mac, dst_mac, key_tunnel)
        print(flow_id)
        i=0
        # Si es la primera vez que vemos este flujo en este lote...
        if flow_id not in processed_flows:
            
            tabla_actual = lookup_table.get(message["sw"].name, {})
            src_eth_addr = intToMac(src_mac)
            dst_eth_addr = intToMac(dst_mac)

            print(f"Instalando regla nueva para MAC {src_eth_addr} hacia {dst_eth_addr} en puerto {srcport}")
            if src_eth_addr not in tabla_actual:
                print(">> Me apunto la MAC src pq no la tengo")
                lookup_table[message["sw"].name][src_eth_addr] = srcport
            
            if dst_eth_addr == "ff:ff:ff:ff:ff:ff":
                print(">> Detectado Broadcast MAC. Instalando regla de flooding...")
                mcast=10
                if message["sw"].name == 's3':
                    if srcport in [121, 123]:
                        mcast = 20
                    elif srcport == 1 and src_eth_addr == global_data['macs']["mach2"]:
                        mcast = 20
                broadcasting_digest(message["sw"], prog, src_eth_addr, mcast, srcport)
            elif dst_eth_addr in tabla_actual:
                dstport = lookup_table[message["sw"].name][dst_eth_addr]
                addFlowRule(message["sw"], src_eth_addr, dst_eth_addr, srcport, dstport, key_tunnel, prog)
            
            # Lo añadimos al set para ignorar los siguientes duplicados
            processed_flows.add(flow_id)
        else:
            i=i+1
            # Es un paquete UDP duplicado de la misma ráfaga. ¡Lo ignoramos!
            print(f"Paquete repetido numero {i} proveniente de {sw.name}")
    
    # 4. Enviamos el ACK al switch
    message["sw"].DigestAck(message["payload"].digest_id, message["payload"].list_id)
    print("Envio ack")

def processBroadcast(message):
    # 1. Filtro de duplicados para evitar ALREADY_EXISTS (UNKNOWN)
    # Usamos un set para procesar solo una vez cada flujo en esta ráfaga
    processed_flows = set()
    # Ejemplo de cómo se vería la info que necesitas pasarle a la función
    # Esto debe coincidir con tu struct digest_t en P4
    digest_field_names = [
        {'name': 'ingress_port'}, 
        {'name': 'src_mac'}
    ]

    # Uso:
    decoded_data = decodeDigestList(digest_field_names, message["payload"])

    payload = message["payload"].data
    print(f"Received digestIn broadcast learning from switch {message["sw"].name}")
    # 3. Recorremos los datos decodificados
    for entry in decoded_data:
        srcport = entry['ingress_port']
        src_mac = entry['src_mac']
        
        # Creamos un identificador único para este flujo
        flow_id = (srcport, src_mac)
        i=0
        # Si es la primera vez que vemos este flujo en este lote...
        if flow_id not in processed_flows:
            
            tabla_actual = lookup_table.get(message["sw"].name, {})
            src_eth_addr = intToMac(src_mac)
            if src_eth_addr not in tabla_actual:
                print(">> Me apunto la MAC src pq no la tengo")
                lookup_table[message["sw"].name][src_eth_addr] = srcport
            
            # Lo añadimos al set para ignorar los siguientes duplicados
            processed_flows.add(flow_id)
        else:
            i=i+1
            print(f"Paquete repetido numero {i} proveniente de {sw.name}")
    
    # 4. Enviamos el ACK al switch
    message["sw"].DigestAck(message["payload"].digest_id, message["payload"].list_id)

# async def processNotif(notif_queue):
#         while True:
#             notif = await notif_queue.get()
#             debug_notif = False
#             if debug_notif:
#                 print(notif)
#                 pprint.pprint(notif_db)
#             sw_name=notif["sw"].name
#             prog= global_data ['prog_switches'][sw_name]['program_name']
#             if notif["type"] == "packet-in":
#                 print(f"me ha llegado un paquete tipo {prog}")
#                 processPacket(notif, prog)
#                 printCounter(global_data ['p4info_helper'][prog], notif["sw"], 'MyIngress.ingressPktOutCounter', global_data ['index'])
#                 printCounter(global_data ['p4info_helper'][prog], notif["sw"], 'MyEgress.egressPktInCounter', global_data ['index'])
#                 if debug_notif:
#                     readTableRules(global_data ['p4info_helper'][prog], notif["sw"])
#             elif notif["type"] == "digest":
#                 digest_list = notif["payload"]
#                 print(f"--- Recibido Digest de {sw_name} con {len(digest_list.data)} entradas ---")
                
                
#                 if digest_list.digest_id == global_data["id_digest_unknown"]:
#                     # Lógica compleja (puerto, tunnel, IPs...)
#                     processDigest(notif, prog)
#                 elif digest_list.digest_id == global_data["id_mac_learning"]:
#                     # Lógica simple (puerto, MAC)
#                     processBroadcast(notif)
#                 else:
#                     print(f"Me ha llegado con este id: {digest_list.digest_id}")

#             else:
#                  print(f"--- Recibido un {notif["type"]} de {sw_name} ---")
#             notif_queue.task_done()
#             print("Tarea HECHA")

# async def packetInHandler(notif_queue,sw):
#     # TODO: Implement the function logic to handle a packet-in message
#     while True:
#         try:
#             packet_in = await asyncio.to_thread(sw.PacketIn)
#             print(f"Received packet: {packet_in}")
#             message = {"type": "packet-in", "sw": sw, "packet-in": packet_in}
#             notif_queue.put_nowait(message)

#         except grpc.RpcError as e:
#             print(f"[gRPC Error in packetInHandler for {sw.name}]")
#             printGrpcError(e)

#             if e.code() == grpc.StatusCode.UNKNOWN:
#                 print(f"Unknown gRPC error from {sw.name}. Retrying...")
#             await asyncio.sleep(2)

#         except Exception as e:
#             print(f"[Unexpected Error in packetInHandler for {sw.name}]: {e}")
#             traceback.print_exc()
#             await asyncio.sleep(2)

# async def digestInHandler(notif_queue,sw):
#     while True:
#         try:
#             digest_msg = await asyncio.to_thread(sw.DigestIn)
#             print(f"TS RECEIVED Received digest: {digest_msg}")
#             message = {"type": "digest", "sw": sw, "payload": digest_msg}
#             notif_queue.put_nowait(message)

#         except grpc.RpcError as e:
#             print(f"[gRPC Error in digestInHandler for {sw.name}]")
#             printGrpcError(e)

#             if e.code() == grpc.StatusCode.UNKNOWN:
#                 print(f"Unknown gRPC error from {sw.name}. Retrying...")
#             await asyncio.sleep(2)

#         except Exception as e:
#             print(f"[Unexpected Error in digestInHandler for {sw.name}]: {e}")
#             traceback.print_exc()
#             await asyncio.sleep(2)

def printGrpcError(e):
    print("gRPC Error:", e.details(), end=' ')
    status_code = e.code()
    print("(%s)" % status_code.name, end=' ')
    traceback = sys.exc_info()[2]
    print("[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))

def packet_worker(sw, prog):
    while True:
        try:
            packet_in = sw.PacketIn()
            message = {"type": "packet-in", "sw": sw, "packet-in": packet_in}
            processPacket(message, prog)

        except grpc.RpcError as e:
            print(f"[gRPC Error packet_worker {sw.name}]")
            printGrpcError(e)
            time.sleep(1)

        except Exception as e:
            print(f"[Unexpected Error packet_worker {sw.name}]: {e}")
            traceback.print_exc()
            time.sleep(1)


def digest_worker(sw, prog):
    while True:
        try:
            digest_msg = sw.DigestIn()
            message = {"type": "digest", "sw": sw, "payload": digest_msg}

            print(f"--- Recibido Digest de {sw.name} con {len(digest_msg.data)} entradas ---")

            if digest_msg.digest_id == global_data["id_digest_unknown"]:
                processDigest(message, prog)
            elif digest_msg.digest_id == global_data["id_mac_learning"]:
                processBroadcast(message)

        except grpc.RpcError as e:
            print(f"[gRPC Error digest_worker {sw.name}]")
            printGrpcError(e)
            time.sleep(1)

        except Exception as e:
            print(f"[Unexpected Error digest_worker {sw.name}]: {e}")
            traceback.print_exc()
            time.sleep(1)


def addMarkedRule(sw, eth_addr, srcport, tunnel_id, prog):

    helper = global_data['p4info_helper'][prog]

   # 1. Buscamos la tabla iterando directamente sobre el p4info
    table_info = None
    for t in helper.p4info.tables:
        if t.preamble.name == "MyIngress.marked_ip":
            table_info = t
            break
            
    # Si la tabla no existe en el P4 de este switch (ej. un switch tonto), salimos
    if table_info is None:
        print(f"El switch {sw.name} ({prog}) NO tiene la tabla 'MyIngress.marked_ip'")
        return

    # Iteramos sobre los match_fields para ver cuáles están definidos en el P4
    eth_match_field = None
    for match_field in table_info.match_fields:
        if "dstAddr" in match_field.name:
            eth_match_field = "hdr.ethernet.dstAddr"
            break
        elif "srcAddr" in match_field.name:
            eth_match_field = "hdr.ethernet.srcAddr"
            break
    
    if eth_match_field == None:
        print(f"Error eth_match_field none in {sw.name}")
        return

    table_entry = global_data['p4info_helper'][prog].buildTableEntry(
        table_name="MyIngress.marked_ip",
        match_fields={
            "hdr.ipv4.protocol"    : 6,
            eth_match_field : eth_addr,
            "standard_metadata.ingress_port" : srcport
        },
        action_name="MyIngress.marking",
        action_params={
            "key":           tunnel_id
        }
    )
    sw.WriteTableEntry(table_entry)


def main(switches_config):
    # Instantiate a P4Runtime helper from the p4info file
    # Diccionario para guardar los helpers de cada programa para no recargarlos mil veces
 
    helpers = {}
    switches_info = []
    # Instanciamos los helpers necesarios
    for sw_name, conf in switches_config.items():
        prog_name = conf['program_name']
        if prog_name not in helpers:
            # Creamos el helper solo si es un programa nuevo
            print(f"Cargando P4Info para: {prog_name}")
            helpers[prog_name] = p4runtime_lib.helper.P4InfoHelper(conf['p4info'])

        nuevo_switch = {
            "name": sw_name,
            "address": f"127.0.0.1:5005{sw_name[1:]}",
            "device_id": int(sw_name[1:]) - 1
        }
        switches_info.append(nuevo_switch)

    global_data ['p4info_helper'] = helpers
    p4info_helper = global_data ['p4info_helper']
    global_data ['prog_switches'] = switches_config

    try:
        # Diccionarios para mantener conexiones y tablas de lookup
        switch_connections = {}

        # Crear las conexiones y configurar los switches
        for sw in switches_info:
            prog = switches_config[sw['name']]['program_name']
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
                p4info=p4info_helper[prog].p4info,
                bmv2_json_file_path=switches_config[sw['name']]['bmv2_json']
            )
            print(f"Installed P4 {prog} using SetForwardingPipelineConfig on {sw['name']}")

            try:
                # Max list size 100 evita el error UNKNOWN en UDP flood
                global_data["id_mac_learning"] = p4info_helper[prog].get_digests_id("mac_learning_digest_t")
                conn.EnableDigest(global_data["id_mac_learning"], max_timeout_ns=global_data["timeout"], max_list_size=1)

                global_data["id_digest_unknown"] = p4info_helper[prog].get_digests_id("digest_t")
                conn.EnableDigest(global_data["id_digest_unknown"], max_timeout_ns=global_data["timeout"], max_list_size=1)
                print(f"Digest habilitado en {sw['name']}")
            except Exception as e:
                print(f"Advertencia: No se pudo habilitar digest en {sw['name']}: {e}")
                import traceback
                traceback.print_exc()
            # -----------------------------------------------------------

        global_data['p4info_obj_map'] = {}
        global_data['cpm_packetin_id2data'] = {}
        global_data['punt_reason_name2int'] = {}
        global_data['punt_reason_int2name'] = {}
        global_data['controller_opcode_name2int'] = {}
        global_data['controller_opcode_int2name'] = {}

        for prog, p4_helper in p4info_helper.items():
            # Configurar global_data (solo se hace una vez)
            global_data['p4info_obj_map'][prog] = makeP4infoObjMap(p4_helper.p4info)
            global_data['cpm_packetin_id2data'][prog] = \
                controllerPacketMetadataDictKeyId(global_data['p4info_obj_map'][prog], "packet_in")

            global_data['punt_reason_name2int'][prog], global_data['punt_reason_int2name'][prog] = \
                serializableEnumDict(p4_helper.p4info, 'PuntReason_t')
            global_data['controller_opcode_name2int'][prog], global_data['controller_opcode_int2name'][prog] = \
                serializableEnumDict(p4_helper.p4info, 'ControllerOpcode_t')

        # Crear grupos mcast para broadcast:
        # 1. Defines tus datos de configuración (el "qué")
        # Esto mapea el nombre del switch a una lista de sus grupos multicast.
        mcast_configs = {
            's1': [{'mgid': 10, 'ports': [1, 121]}],
            's2': [{'mgid': 10, 'ports': [1, 111, 131]}],
            's3': [
                {'mgid': 10, 'ports': [1, 141]},
                {'mgid': 20, 'ports': [1, 121]}
            ],
            's4': [{'mgid': 10, 'ports': [1, 151, 131]}],
            's5': [{'mgid': 10, 'ports': [1, 141]}],
            's6': [{'mgid': 10, 'ports': [1, 2]}],
            's7': [{'mgid': 10, 'ports': [1, 2, 3]}]
        }
        # Configurar sesiones de clone y aprovecho y croe grupos multicast para broadcast
        replicas = [{"egress_port": global_data['CPU_PORT'], "instance": 1}]
        for sw in switch_connections.values():
            try:
                prog = switches_config[sw.name]['program_name']
                writeCloneSession(sw, global_data['CPU_PORT_CLONE_SESSION_ID'], replicas, prog)

                switch_mcast_rules = mcast_configs.get(sw.name, [])

                helper = global_data['p4info_helper'][prog]

                for rule in switch_mcast_rules:
                    replics = [{'egress_port': p, 'instance': 1} for p in rule['ports']]
                    mcast_entry = helper.buildMulticastGroupEntry(rule['mgid'], replics)
                    sw.WritePREEntry(mcast_entry)

            except shp4rt.P4RuntimeWriteException:
                print(f"Clone session {global_data['CPU_PORT_CLONE_SESSION_ID']} assumed initialized already")

        

        # 2. Haces el bucle iterando sobre esa lista
        for sw in switch_connections.values():
            for mac in global_data['macs'].values():
                
                addMarkedRule(
                    sw=sw,
                    eth_addr=mac,
                    srcport=1,
                    tunnel_id=0xeb,
                    prog=switches_config[sw.name]['program_name']
                )
                print(f"Regla instalada en {sw.name} para la MAC {mac}")

        threads = []

        for sw_name, sw_conn in switch_connections.items():
            prog = switches_config[sw_name]['program_name']

            t1 = threading.Thread(
                target=packet_worker,
                args=(sw_conn, prog),
                daemon=True
            )

            t2 = threading.Thread(
                target=digest_worker,
                args=(sw_conn, prog),
                daemon=True
            )

            t1.start()
            t2.start()

            threads.append(t1)
            threads.append(t2)

        print("Controller running (thread-based)...")

        # Mantener proceso vivo
        while True:
            time.sleep(10)


        # # Crear cola de notificaciones y tareas asyncio
        # notif_queue = asyncio.Queue(maxsize=0)

        # pkt_tasks = [
        #     asyncio.create_task(packetInHandler(notif_queue, sw_conn))
        #     for sw_conn in switch_connections.values()
        # ]

        # # 2. Tareas para Digest (NUEVO)
        # digest_tasks = [
        #     asyncio.create_task(digestInHandler(notif_queue, sw_conn))
        #     for sw_conn in switch_connections.values()
        # ]

        # proc_notif = asyncio.create_task(processNotif(notif_queue))

        # # Ejecutar todas las tareas
        # await asyncio.gather(*pkt_tasks, *digest_tasks, proc_notif)

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        print(f"gRPC error occurred: {e}")
        print(f"Status code: {e.code()}")  # e.g., StatusCode.UNAVAILABLE or StatusCode.INVALID_ARGUMENT
        print(f"Details: {e.details()}")

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller Multi-P4')
    parser.add_argument('--topo', help='Topology JSON file',
                        type=str, action="store", required=False,
                        default='./topology.json')
    args = parser.parse_args()

    # 1. Leemos la configuración de cada switch desde la topología
    switches_config = get_p4_config_from_topo(args.topo)

    print("Configuración detectada:")
    for sw, conf in switches_config.items():
        print(f"  Switch: {sw} -> Prog: {conf['program_name']}")

    # 2. Llamamos a main pasando el DICCIONARIO completo, no archivos sueltos
    main(switches_config)
