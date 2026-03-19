#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import argparse
import os
import sys
import threading
import traceback
import time
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
IDLE_TIMEOUT_NS = 10 * NSEC_PER_SEC
LOG_LEVEL = logging.DEBUG

global_data = {}

global_data['CPU_PORT'] = 510
global_data['CPU_PORT_CLONE_SESSION_ID'] = 67
global_data['macs'] = {}
global_data['macs']['mach2'] = "08:00:00:00:02:22"



global_data["timeout"] = 1000000
## The notification database keeps track of the received idle notifications and triggers the deletion of stale flow rules.
notif_db = {}

# The lookup table is defined to simplify reachability and provide connectivity
# among hosts. In a real-world scenario, however, you should use an algorithm
# to solve this problem more effectively.

lookup_table = {}
flow_peers = {}  # flow_peers[sw_name][mac] = set of (tunnel_id, peer_mac)

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

def addFlowRule( ingress_sw, src_eth_addr, dst_eth_addr, sport, dport, prog):
    """
    Install flow rule in flow cache table

    """

    table_entry = global_data['p4info_helper'][prog].buildTableEntry(
        table_name="MyIngress.mac_forwarding",
        match_fields={
            "hdr.ethernet.srcAddr": src_eth_addr,
            "hdr.ethernet.dstAddr": dst_eth_addr
        },
        action_name="MyIngress.forwarding",
        action_params={
            "port":           dport
        },
        idle_timeout_ns=IDLE_TIMEOUT_NS
        )

    table_entry2 = global_data['p4info_helper'][prog].buildTableEntry(
        table_name="MyIngress.mac_forwarding",
        match_fields={
            "hdr.ethernet.srcAddr": dst_eth_addr,
            "hdr.ethernet.dstAddr": src_eth_addr
        },
        action_name="MyIngress.forwarding",
        action_params={
            "port":           sport
        },
        idle_timeout_ns=IDLE_TIMEOUT_NS
        )
    
    rules_to_write = [table_entry, table_entry2]

    for rule in rules_to_write:
        try:
            ingress_sw.WriteTableEntry(rule)
            logger.debug(f"Instalando regla: unidireccional")
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.UNKNOWN:
                logger.warning(f"Regla duplicada ignorada en {ingress_sw.name}")
                logger.debug(f"gRPC code: {e.code()}")
                logger.debug(f"gRPC details: {e.details()}")
            else:
                printGrpcError(e)
    

def modifyFlowRule(sw, prog, src_eth_addr, dst_eth_addr, sport, dport):
    """
    Modifica las reglas existentes para actualizar los puertos tras un handover.
    new_srcport y new_dstport ya tienen el segundo dígito actualizado.
    """

    # Regla src -> dst: el paquete sale por dport
    table_entry = global_data['p4info_helper'][prog].buildTableEntry(
        table_name="MyIngress.mac_forwarding",
        match_fields={
            "hdr.ethernet.srcAddr": src_eth_addr,
            "hdr.ethernet.dstAddr": dst_eth_addr
        },
        action_name="MyIngress.forwarding",
        action_params={
            "port":           dport
        },
        idle_timeout_ns=IDLE_TIMEOUT_NS
    )

    # Regla dst -> src: el paquete sale por sport
    table_entry2 = global_data['p4info_helper'][prog].buildTableEntry(
        table_name="MyIngress.mac_forwarding",
        match_fields={
            "hdr.ethernet.srcAddr": dst_eth_addr,
            "hdr.ethernet.dstAddr": src_eth_addr
        },
        action_name="MyIngress.forwarding",
        action_params={
            "port":           sport
        },
        idle_timeout_ns=IDLE_TIMEOUT_NS
    )

    rules_to_modify = [table_entry, table_entry2]

    for rule in rules_to_modify:
        try:
            #sw.ModifyTableEntry(rule) Si funciona con deletewrite, habra que ver con modify
            sw.DeleteTableEntry(rule)
            sw.WriteTableEntry(rule)
            logger.debug(f"Regla modificada (handover) en {sw.name}")
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.UNKNOWN:
                logger.warning(f"Regla no encontrada para modificar en {sw.name}, ignorando")
                logger.debug(f"gRPC code: {e.code()}")
                logger.debug(f"gRPC details: {e.details()}")
            else:
                printGrpcError(e)

def createFlowRuleFromNotif(idle_notif, prog):
    """Construye un table_entry a partir de una idle notification para poder eliminarlo."""
    te = idle_notif.table_entry[0]
    src_mac    = int.from_bytes(te.match[0].exact.value, byteorder='big')
    dst_mac    = int.from_bytes(te.match[1].exact.value, byteorder='big')

    table_entry = global_data['p4info_helper'][prog].buildTableEntry(
        table_name="MyIngress.mac_forwarding",
        match_fields={
            "hdr.ethernet.srcAddr": src_mac,
            "hdr.ethernet.dstAddr": dst_mac
        }
    )
    return table_entry

def addNotification(sw_name, flow_rule):
    """Añade una notificación a la base de datos de notificaciones."""
    notification = {
        "timestamp": datetime.now(),
        "flow_rule": flow_rule,
    }
    notif_db[sw_name].append(notification)

def checkFlowRule(sw_name, flow_rule):
    """Comprueba si una regla ya está en la DB de notificaciones (para evitar duplicados)."""
    if sw_name not in notif_db:
        return False
    for notif in notif_db[sw_name]:
        if notif["flow_rule"] == flow_rule:
            return True
    return False

def isExpired(timestamp, timeout):
    return datetime.now() - timestamp > timedelta(seconds=timeout)

def cleanExpiredNotification(sw_name, timeout=5):
    """Elimina las notificaciones caducadas."""
    if sw_name not in notif_db:
        return False
    notif_db[sw_name] = [
        notif for notif in notif_db[sw_name]
        if not isExpired(notif["timestamp"], timeout)
    ]
    return True

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

def broadcasting(sw, input_port, payload, src_eth, prog):

    mcast=10
    if sw.name == 's3':
        if input_port==120:
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
        did_handover=False

        if pkt.src not in tabla_actual:
            logger.info(f"║ [LEARN] {sw.name}: MAC {pkt.src} vinculada a puerto {src_port}")
            tabla_actual[pkt.src] = src_port
        else:
            old_port = tabla_actual[pkt.src]
            
            if old_port != src_port:
                # Me esta viniendo un packet de la misma mac desde otro lado (handover)
                # Actualizamos la tabla general para que el nuevo puerto quede registrado
                tabla_actual[pkt.src] = src_port
                
                # Usamos flow_peers para saber con qué peers tiene reglas esta MAC
                logger.debug(f"║ [DEBUG] flow_peers para MAC {pkt.src} en {sw.name}: {flow_peers.get(sw.name, {}).get(pkt.src, set())}")
                for peer_mac in flow_peers.get(sw.name, {}).get(pkt.src, set()).copy():
                    peer_port = tabla_actual.get(peer_mac, src_port)  # fallback si el peer tampoco se conoce
                    modifyFlowRule(sw, prog, pkt.src, peer_mac, src_port, peer_port)
                    # Si hay túnel, refinamos el puerto en la tabla (por si difiere el último dígito)
                    logger.info(f"║ [HANDOVER] MAC {pkt.src} del puerto {old_port} al puerto {src_port}")
                did_handover=True
        
        if pkt.dst in tabla_actual:
            dst_port = tabla_actual[pkt.dst]
            tunnel_id = pktinfo['metadata']['key_tunnel']
            # Registrar peers para poder hacer handover sin conocer pkt.dst
            flow_peers.setdefault(sw.name, {}).setdefault(pkt.src, set()).add(pkt.dst)
            flow_peers.setdefault(sw.name, {}).setdefault(pkt.dst, set()).add(pkt.src)
                
            if not did_handover:
                logger.info(f"║ [FLOW] Instalando regla: {pkt.src} <-> {pkt.dst} (Port {src_port} <-> {dst_port})")
                addFlowRule(sw, pkt.src, pkt.dst, src_port, dst_port, prog)
            
            # Packet Out
            metadatas = packetOutMetadataList(
                        global_data['controller_opcode_name2int'][prog]['SEND_TO_PORT_IN_OPERAND0'],
                        0, dst_port)
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
        readTableRules(p4info_helper, sw)


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


def idle_worker(sw, prog):
    """Hilo que escucha las idle timeout notifications del switch y elimina las reglas caducadas."""
    while True:
        try:
            idle_notif = sw.IdleTimeoutNotification()
            # Si no existe la base de datos de notificaciones, la crea; si existe, la limpia
            if sw.name not in notif_db:
                notif_db[sw.name] = []
            else:
                cleanExpiredNotification(sw.name, 10)

            table_entry = createFlowRuleFromNotif(idle_notif, prog)

            # Si la regla no está en la base de datos, la elimina
            if not checkFlowRule(sw.name, table_entry):
                addNotification(sw.name, table_entry) # Añadir table_entry a la base de datos para no eliminarlo de nuevo
                sw.DeleteTableEntry(table_entry) # Borrar table_entry por timeout
                # Lo pongo aqui por si saltase error en el delete
                # Extraer tunnel_id y MACs de la notificación para limpiar mac_tunnel y lookup_table
                te = idle_notif.table_entry[0]
                src_mac   = intToMac(int.from_bytes(te.match[1].exact.value, byteorder='big'))
                dst_mac   = intToMac(int.from_bytes(te.match[2].exact.value, byteorder='big'))

                logger.info(f"[IDLE] Eliminada regla por timeout en {sw.name}: {src_mac} --> {dst_mac}")

                # Limpiar flow_peers para ambas MACs
                if sw.name in flow_peers:
                    if src_mac in flow_peers[sw.name]:
                        flow_peers[sw.name][src_mac].discard(dst_mac)
                        if not flow_peers[sw.name][src_mac]:
                            del flow_peers[sw.name][src_mac]
            else:
                logger.debug(f"[IDLE] Notificación duplicada ignorada en {sw.name}")

        except grpc.RpcError as e:
            logger.error(f"[gRPC Error idle_worker {sw.name}]")
            printGrpcError(e)
            time.sleep(1)

        except Exception as e:
            logger.error(f"[Unexpected Error idle_worker {sw.name}]: {e}")
            traceback.print_exc()
            time.sleep(1)


def addMarkedRule(sw, tunnel_id, protocol, prog):

    helper = global_data['p4info_helper'][prog]

   # 1. Buscamos la tabla iterando directamente sobre el p4info
    table_info = None
    for t in helper.p4info.tables:
        if t.preamble.name == "MyEgress.tunneling":
            table_info = t
            break
            
    # Si la tabla no existe en el P4 de este switch (ej. un switch tonto), salimos
    if table_info is None:
        logger.warning(f"El switch {sw.name} ({prog}) NO tiene la tabla 'MyEgress.tunneling'")
        return

    table_entry = global_data['p4info_helper'][prog].buildTableEntry(
        table_name="MyEgress.tunneling",
        match_fields={
            "hdr.ipv4.protocol"    : protocol
        },
        action_name="MyEgress.marking_tunnel",
        action_params={
            "key_tunnel":           tunnel_id
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
            "address": f"{conf['ip']}:9559",
            "device_id": 0
        }
        switches_info.append(nuevo_switch)

    global_data ['p4info_helper'] = helpers
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

            # Master arbitration
            conn.MasterArbitrationUpdate()
            # Instalar el P4 program
            conn.SetForwardingPipelineConfig(
                p4info=helpers[prog].p4info,
                bmv2_json_file_path=switches_config[sw['name']]['bmv2_json']
            )
            logger.info(f"Installed P4 {switches_config[sw['name']]['program_name']} using SetForwardingPipelineConfig on {sw['name']}")

        global_data['p4info_obj_map'] = {}
        global_data['cpm_packetin_id2data'] = {}
        global_data['punt_reason_name2int'] = {}
        global_data['punt_reason_int2name'] = {}
        global_data['controller_opcode_name2int'] = {}
        global_data['controller_opcode_int2name'] = {}

        for prog, p4_helper in helpers.items():
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
            's1': [{'mgid': 10, 'ports': [1, 120]}],
            's2': [{'mgid': 10, 'ports': [1, 110, 130]}],
            's3': [
                {'mgid': 10, 'ports': [1, 140]},
                {'mgid': 20, 'ports': [1, 120]}
            ],
            's4': [{'mgid': 10, 'ports': [1, 150, 130]}],
            's5': [{'mgid': 10, 'ports': [1, 140]}]
        }
        # Configurar sesiones de clone y aprovecho y croe grupos multicast para broadcast
        replicas = [{"egress_port": global_data['CPU_PORT'], "instance": 1}]
        for sw in switch_connections.values():
            try:
                prog = switches_config[sw.name]['program_name']
                writeCloneSession(sw, global_data['CPU_PORT_CLONE_SESSION_ID'], replicas, prog)

                switch_mcast_rules = mcast_configs.get(sw.name, [])

                helper = helpers[prog]

                for rule in switch_mcast_rules:
                    replics = [{'egress_port': p, 'instance': 1} for p in rule['ports']]
                    mcast_entry = helper.buildMulticastGroupEntry(rule['mgid'], replics)
                    sw.WritePREEntry(mcast_entry)

            except shp4rt.P4RuntimeWriteException:
                logger.warning(f"Clone session {global_data['CPU_PORT_CLONE_SESSION_ID']} assumed initialized already")

        
        # Definir el mapeo de Protocolo IPv4 -> ID de túnel
        protocol_to_tunnel = {
            1:  0x1, # ICMP
            6:  0xf0, # TCP
            17: 0xf  # UDP
        }
        
        for sw in switch_connections.values():
            prog = switches_config[sw.name]['program_name']
            for proto, tun_id in protocol_to_tunnel.items():
                addMarkedRule(
                    sw=sw,
                    tunnel_id=tun_id,
                    protocol=proto,
                    prog=prog
                )
                logger.debug(f"Regla de túnel instalada en {sw.name}: Protocolo {proto} -> Tunnel {tun_id}")

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
                target=idle_worker,
                args=(sw_conn, prog),
                name=f"T_Idle-{sw_name}",
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
