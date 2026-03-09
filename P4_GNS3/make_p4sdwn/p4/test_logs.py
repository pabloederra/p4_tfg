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

import logging
import logging.handlers
import queue

from pathlib import Path
from collections import Counter
from datetime import datetime, timedelta
from scapy.all import *
from scapy.layers.l2 import Ether, ARP  # Para que no me salte un warning
import grpc

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                # '../utils/'))
                 '../deps/utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_sh.p4runtime as shp4rt

NSEC_PER_SEC = 1000 * 1000 * 1000
LOG_LEVEL = logging.INFO

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


global_data["timeout"] = 1000000
## The notification database keeps track of the received idle notifications and triggers the deletion of stale flow rules.
notif_db = {}

# The lookup table is defined to simplify reachability and provide connectivity
# among hosts. In a real-world scenario, however, you should use an algorithm
# to solve this problem more effectively.

lookup_table = {}
tabla_id = {}

class CustomFormatter(logging.Formatter):
    # Colores base para los niveles de log
    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"

    # Diccionario de colores para los hilos (puedes añadir más)
    THREAD_COLORS = {
        "Thread-s1": "\x1b[32m", # Verde
        "Thread-s2": "\x1b[34m", # Azul
        "Thread-s3": "\x1b[35m", # Magenta
        "Thread-s4": "\x1b[36m", # Cian
        "Thread-s5": "\x1b[33m", # Amarillo
        "Thread-s6": "\x1b[92m", # Verde claro
        "Thread-s7": "\x1b[94m", # Azul claro
        "T_Digest-s2": "\x1b[97m", # Tampoco lo sé
        "T_Digest-s4": "\x1b[97m", # No sé
    }

    def format(self, record):
        # 1. Elegimos el color del nivel (Prioridad: Errores en rojo siempre)
        if record.levelno >= logging.ERROR:
            level_color = self.red
        elif record.levelno == logging.WARNING:
            level_color = self.yellow
        else:
            level_color = self.grey

        # 2. Elegimos el color del hilo basado en su nombre
        # Si el nombre del hilo no está en la lista, usamos el reset (blanco/gris)
        thread_color = self.THREAD_COLORS.get(record.threadName, self.reset)

        # 3. Construimos el formato dinámicamente
        # Ponemos el color del hilo a la marca de tiempo y al nombre del hilo
        # El nivel de log mantiene su propio color para que resalte el WARNING/ERROR
        format_str = (
            f"{thread_color}[%(asctime)s.%(msecs)03d]{self.reset} "
            f"{level_color}[%(levelname)-7s]{self.reset} "
            f"{thread_color}[%(threadName)-9s]{self.reset} "
            f"{thread_color}%(message)s{self.reset}"
        )

        formatter = logging.Formatter(format_str, datefmt="%H:%M:%S")
        return formatter.format(record)
    
# Inicializar logger
logger = logging.getLogger("P4Controller")
logger.setLevel(LOG_LEVEL)

# Queue para logs multithread
log_queue = queue.Queue()
queue_handler = logging.handlers.QueueHandler(log_queue)
logger.addHandler(queue_handler)

# StreamHandler único que imprimirá los logs desde el listener
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(CustomFormatter())

# Listener thread que procesa el queue
def listener_thread():
    while True:
        record = log_queue.get()
        if record is None:  # Señal de cierre
            break
        stream_handler.handle(record)

listener = threading.Thread(target=listener_thread, name="LogListener", daemon=True)
listener.start()

# ---------------------------
# Función para cerrar el listener al finalizar
# ---------------------------
def stop_logger():
    log_queue.put(None)
    listener.join()

def get_p4_config_from_topo(topo_file='./topology.json'):
    if not os.path.exists(topo_file):
        logger.error(f"Error: Topology file {topo_file} not found.")
        logging.shutdown()
        exit(1)

    with open(topo_file, 'r') as f:
        topo = json.load(f)

    switches_conf = {}

    for sw_name, sw_data in topo['switches'].items():
        # Obtenemos la ruta del JSON definida en la topología (ej: "build/router.json")
        json_path = sw_data.get('json_path')
        
        if not json_path:
            logger.warning(f"Warning: Switch {sw_name} has no json_path in topology.")
            continue

        # Deducimos el nombre base y el p4info
        # ej: "build/router.json" -> base: "router"
        base_name = os.path.splitext(os.path.basename(json_path))[0]
        
        # Asumimos la estructura estándar de p4c para el p4info
        # build/router.json -> build/router.p4.p4info.txtpb
        # Nota: Ajusta la ruta si tu makefile lo guarda en otro sitio
        #p4info_path = f"./build/{base_name}.p4.p4info.txtpb"
        p4info_path = f"./{base_name}.p4.p4info.txtpb"

        if not os.path.exists(p4info_path):
            logger.error(f"Error: P4Info file not found for {sw_name}: {p4info_path}")
            logging.shutdown()
            exit(1)
            
        switches_conf[sw_name] = {
            'bmv2_json': json_path,
            'p4info': p4info_path,
            'program_name': base_name,
            'ip': sw_data.get('ip') # NEW
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
    logger.debug("decodePacketInMetadata: ret=%s" % (ret))
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
    logger.debug("serializableEnumDict: name='%s' name_to_int=%s int_to_name=%s"
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
            logger.debug(f"Instalando regla: unidireccional")
        except grpc.RpcError as e:
            code = e.code()
            details = e.details() or ""

            if (
                code == grpc.StatusCode.UNKNOWN
            ):
                logger.warning(f"Regla duplicada ignorada en {ingress_sw.name}")
                logger.debug(f"gRPC code: {e.code()}")
                logger.debug(f"gRPC details: {e.details()}")
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
    logger.debug('\n----- Reading tables rules for %s -----' % sw.name)
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            
            # 1. TRADUCIR EL NOMBRE DE LA TABLA
            table_name = p4info_helper.get_tables_name(entry.table_id)
            logger.debug("Table: %s" % table_name)
            
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
                
                logger.debug("  Match: %s = %s" % (match_field_name, match_value))

            # 3. TRADUCIR LA ACCIÓN
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            logger.debug("  Action: %s" % action_name)
            
            # 4. TRADUCIR LOS PARÁMETROS DE LA ACCIÓN
            for p in action.params:
                param_name = p4info_helper.get_action_param_name(action_name, p.param_id)
                # Convertir el valor del parametro a entero o hex
                # 'byteorder="big"' es estándar en redes
                val_int = int.from_bytes(p.value, byteorder='big')
                logger.debug("    Arg: %s = %d" % (param_name, val_int))
            
            logger.debug('-----')

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
                logger.debug("%s %s %d: %d packets (%d bytes)" % (
                    sw.name, counter_name, index,
                    counter.data.packet_count, counter.data.byte_count
                ))
    except grpc.RpcError as e:
            logger.error(f"[gRPC Error in printCounter for {sw.name}]")
            printGrpcError(e)

            if e.code() == grpc.StatusCode.UNKNOWN:
                logger.error(f"Unknown gRPC error from {sw.name}. Retrying...")
                time.sleep(2)

    except Exception as e:
           logger.error(f"[Unexpected Error in printCounter for {sw.name}]: {e}")
           traceback.print_exc()
           time.sleep(2)

def broadcasting(sw, input_port, payload, src_eth, prog):

    mcast=10
    if sw.name == 's3':
        if input_port in [121, 123]:
            mcast = 20
        elif input_port == 1 and src_eth == global_data['macs']["mach2"]:
            mcast = 20
    
    metadatas = packetOutMetadataList(
                        global_data['controller_opcode_name2int'][prog]['OP_FLOOD'],
                        mcast, input_port)
    sendPacketOut(sw, payload, metadatas)

def processPacket(message, prog):
    sw = message["sw"]
    payload = message["packet-in"].payload
    packet = message["packet-in"]
    
    if len(payload) == 0: return

    pkt = Ether(payload)
    pktinfo = decodePacketInMetadata(global_data['cpm_packetin_id2data'][prog], packet)
    punt_reason = pktinfo['metadata']['punt_reason']
    reason_name = global_data['punt_reason_int2name'][prog].get(punt_reason, "UNKNOWN")
    # Definimos un ancho estándar para la caja
    WIDTH = 60 
    
    logger.info(f"╔{'═' * WIDTH}")
    logger.info(f"║ PacketIn de {len(payload)} bytes desde {sw.name} ({prog})")
    logger.info(f"║ Port: {pktinfo['metadata']['input_port']} | Reason: {reason_name}")
    logger.info(f"║ Eth: {pkt.src} -> {pkt.dst}")

    if reason_name == 'FLOW_UNKNOWN':
        tabla_actual = lookup_table.get(sw.name, {})
        src_port = pktinfo["metadata"]['input_port']
        
        if pkt.src not in tabla_actual:
            logger.info(f"║ [LEARN] {sw.name}: MAC {pkt.src} vinculada a puerto {src_port}")
            lookup_table[sw.name][pkt.src] = src_port
        
        
        if pkt.dst in tabla_actual:
            dst_port = tabla_actual[pkt.dst]
            tunnel_id = pktinfo['metadata']['key_tunnel']
            logger.info(f"║ [FLOW] Instalando regla: {pkt.src} -> {pkt.dst} (Port {dst_port} en {tunnel_id})")
            addFlowRule(sw, pkt.src, pkt.dst, src_port, dst_port, tunnel_id, prog)
            
            # Packet Out
            metadatas = packetOutMetadataList(
                        global_data['controller_opcode_name2int'][prog]['SEND_TO_PORT_IN_OPERAND0'],
                        0, modificar_puerto(dst_port, tunnel_id))
            sendPacketOut(sw, payload, metadatas)
        else:
            if pkt.dst == "ff:ff:ff:ff:ff:ff":
                if pkt.haslayer(ARP):
                    # 3. Extraer la IP por la que se está preguntando
                    ip_preguntada = pkt[ARP].pdst
                    
                    # Opcional: Extraer quién está haciendo la pregunta
                    ip_que_pregunta = pkt[ARP].psrc
                    
                    logger.info(f"║ IP {ip_que_pregunta} está preguntando por la IP {ip_preguntada}")
                logger.info(f"║ [BCAST] Realizando inundación (Flooding)...")
            else:
                logger.warning(f"║ [WARN] No conozco mac destino (Flooding)...")
            broadcasting(sw, src_port, payload, pkt.src, prog)
    
    logger.info(f"╚{'═' * WIDTH}")
    if LOG_LEVEL ==  logging.DEBUG:
        readTableRules


def printGrpcError(e):
    status_code = e.code()
    details = e.details()
    tb = sys.exc_info()[2]
    line = tb.tb_lineno if tb else 0
    fname = os.path.split(tb.tb_frame.f_code.co_filename)[1] if tb else "unknown"
    
    logger.error(f"gRPC Error en {fname}:{line} | Code: {status_code.name} | Details: {details}")

def packet_worker(sw, prog):
    while True:
        try:
            packet_in = sw.PacketIn()
            message = {"type": "packet-in", "sw": sw, "packet-in": packet_in}
            processPacket(message, prog)

        except grpc.RpcError as e:
            logger.error(f"[gRPC Error packet_worker {sw.name}]")
            printGrpcError(e)
            time.sleep(1)

        except Exception as e:
            logger.error(f"[Unexpected Error packet_worker {sw.name}]: {e}")
            traceback.print_exc()
            time.sleep(1)


def digest_worker(sw, prog):
    while True:
        try:
            digest_msg = sw.DigestIn()
            message = {"type": "digest", "sw": sw, "payload": digest_msg}

            logger.info(f"--- Recibido Digest de {sw.name} con {len(digest_msg.data)} entradas ---")
            if digest_msg.digest_id == global_data["id_digest_unknown"]:
                digest_field_names = [
                    {'name': 'ingress_port'},
                    {'name': 'key_tunnel'}, 
                    {'name': 'src_mac'}, 
                    {'name': 'dst_mac'}
                ]

                # Uso:
                decoded_data = decodeDigestList(digest_field_names, message["payload"])
                for entry in decoded_data:
                    srcport = entry['ingress_port']
                    src_mac = entry['src_mac']
                    dst_mac = entry['dst_mac']
                    key_tunnel = entry['key_tunnel']

                    logger.info(f"DIGEST: {src_mac} -> {dst_mac} con {key_tunnel} desde port{srcport}")
        except grpc.RpcError as e:
            logger.error(f"[gRPC Error digest_worker {sw.name}]")
            printGrpcError(e)
            time.sleep(1)

        except Exception as e:
            logger.error(f"[Unexpected Error digest_worker {sw.name}]: {e}")
            traceback.print_exc()
            time.sleep(1)

        sw.DigestAck(digest_msg.digest_id, digest_msg.list_id)



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
        logger.warning(f"El switch {sw.name} ({prog}) NO tiene la tabla 'MyIngress.marked_ip'")
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
        logger.warning(f"No hay ningun eth_atch_field en {sw.name}")
        return

    table_entry = global_data['p4info_helper'][prog].buildTableEntry(
        table_name="MyIngress.marked_ip",
        match_fields={
            "hdr.ipv4.protocol"    : 17,
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
            logger.info(f"Cargando P4Info para: {prog_name}")
            helpers[prog_name] = p4runtime_lib.helper.P4InfoHelper(conf['p4info'])

        nuevo_switch = {
            "name": sw_name,
            #"address": f"127.0.0.1:5005{sw_name[1:]}",
            "address": f"{conf['ip']}:9559",
            #"device_id": int(sw_name[1:]) - 1
            "device_id": 0
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
                proto_dump_file=f'../logs/{sw["name"]}-p4runtime-requests.txt'
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
            logger.info(f"Installed P4 {switches_config[sw['name']]['program_name']} using SetForwardingPipelineConfig on {sw['name']}")

            try:
                # Max list size 100 evita el error UNKNOWN en UDP flood
                # global_data["id_mac_learning"] = p4info_helper[prog].get_digests_id("mac_learning_digest_t")
                # conn.EnableDigest(global_data["id_mac_learning"], max_timeout_ns=global_data["timeout"], max_list_size=1)

                global_data["id_digest_unknown"] = p4info_helper[prog].get_digests_id("digest_t")
                conn.EnableDigest(global_data["id_digest_unknown"], max_timeout_ns=global_data["timeout"], max_list_size=1)
                logger.info(f"{'═' * 60}")
                logger.info(f"Digest habilitado en {sw['name']}")
                logger.info(f"{'═' * 60}")
            except Exception as e:
                logger.error(f"Advertencia: No se pudo habilitar digest en {sw['name']}: {e}")
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
            's5': [{'mgid': 10, 'ports': [1, 141]}]
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
                logger.warning(f"Clone session {global_data['CPU_PORT_CLONE_SESSION_ID']} assumed initialized already")

        
        list_ports=[1, 113, 123, 133, 143, 153]
        # 2. Haces el bucle iterando sobre esa lista (no es lo más óptimo pero bueno)
        for sw in switch_connections.values():
            for mac in global_data['macs'].values():
                for port in list_ports:
                    addMarkedRule(
                        sw=sw,
                        eth_addr=mac,
                        srcport=port,
                        tunnel_id=0x3eb,
                        prog=switches_config[sw.name]['program_name']
                    )
                    logger.debug(f"Regla instalada en {sw.name} para la MAC {mac}")

        threads = []
        for sw_name, sw_conn in switch_connections.items():
            prog = switches_config[sw_name]['program_name']

            t1 = threading.Thread(
                target=packet_worker,
                args=(sw_conn, prog),
                name=f"Thread-{sw_name}", # NOMBRE DEL HILO
                daemon=True
            )

            t2 = threading.Thread(
                target=digest_worker,
                args=(sw_conn, prog),
                name=f"T_Digest-{sw_name}", # NOMBRE DEL HILO
                daemon=True
            )

            t1.start()
            t2.start()
            threads.append(t1)
            threads.append(t2)

        logger.debug("Controller running (thread-based)...")

        # Mantener proceso vivo
        while True:
            time.sleep(10)

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        logger.error(f"gRPC error occurred: {e}")
        logger.error(f"Status code: {e.code()}")  # e.g., StatusCode.UNAVAILABLE or StatusCode.INVALID_ARGUMENT
        logger.error(f"Details: {e.details()}")

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller Multi-P4')
    parser.add_argument('--topo', help='Topology JSON file',
                        type=str, action="store", required=False,
                        #default='./topology.json')
                        default='./swtopo.json')
    args = parser.parse_args()
    # 1. Leemos la configuración de cada switch desde la topología
    switches_config = get_p4_config_from_topo(args.topo)

    logger.debug("Configuración detectada:")
    for sw, conf in switches_config.items():
        logger.debug(f"  Switch: {sw} -> Prog: {conf['program_name']}")

    # 2. Llamamos a main pasando el DICCIONARIO completo, no archivos sueltos
    main(switches_config)
