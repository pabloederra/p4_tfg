#!/bin/bash
set -e


####################################
#
# INTERFACES A GRE
#
####################################
# 1. Borrar todas las interfaces gretap (menos gretap0) con limpieza previa
for intf in $(ip -br link show type gretap | grep -v "gretap0" | awk '{print $1}'); do
    echo "Forzando eliminación de $intf..."
    # Bajamos la interfaz primero para liberar recursos del kernel
    ip link set dev "$intf" down 2>/dev/null
    # Eliminamos cualquier dirección IP asociada
    ip addr flush dev "$intf" 2>/dev/null
    # Borramos la interfaz
    ip link delete "$intf" 2>/dev/null || echo "Error al borrar $intf, quizás ya no existe."
done

# 2. Resetear gretap0 (que no se puede borrar)
ip link set dev gretap0 down 2>/dev/null
ip addr flush dev gretap0 2>/dev/null
ip link set dev gretap0 multicast off 2>/dev/null
sysctl -w net.ipv6.conf.gretap0.disable_ipv6=1 >/dev/null

echo "Creando interfaces gretap..."
ip link add gretap121 type gretap \
    local 192.168.1.3 remote 192.168.1.2 \
    key 1001
ip link set gretap121 up

ip link add gretap123 type gretap \
    local 192.168.1.3 remote 192.168.1.2 \
    key 1003
ip link set gretap123 up

ip link add gretap141 type gretap \
    local 192.168.1.3 remote 192.168.1.4 \
    key 1001
ip link set gretap141 up

ip link add gretap143 type gretap \
    local 192.168.1.3 remote 192.168.1.4 \
    key 1003
ip link set gretap143 up

# Si tu red física tiene una MTU de 1500:
# 1500 - 20 (IP) - 8 (GRE) - 14 (Eth_{interna}) = 1458 bytes.
# Para ir sobre seguro y evitar cualquier problema con opciones adicionales o 
# etiquetas VLAN de 4 bytes que pudieras añadir en P4, configurar la MTU de tus 
# interfaces gretap en 1450 es la decisión más robusta.

ip link set dev gretap121 mtu 1450
ip link set dev gretap123 mtu 1450
ip link set dev gretap141 mtu 1450
ip link set dev gretap143 mtu 1450

# Silenciar gretap0
ip link set dev gretap0 down
#ip link set dev gretap0 nomulticast
sysctl -w net.ipv6.conf.gretap0.disable_ipv6=1
sysctl -w net.ipv6.conf.gretap0.autoconf=0

# Aplicar lo mismo a tus interfaces reales de P4
for intf in gretap121 gretap123 gretap141 gretap143; do # añade aquí tus interfaces
    sysctl -w net.ipv6.conf.$intf.disable_ipv6=1
    sysctl -w net.ipv6.conf.$intf.autoconf=0
    ip link set dev $intf promisc off
    ip link set dev $intf arp off
done




simple_switch_grpc --device-id 0 \
  -i 1@eth1 \
  -i 121@gretap121 \
  -i 123@gretap123 \
  -i 141@gretap141 \
  -i 143@gretap143 \
  --log-file ../logs/s3.log \
  --no-p4 \
  -- \
  --grpc-server-addr 0.0.0.0:9559 \
  --cpu-port 510 > /dev/null 2>&1 &

echo "Switch ejecutándose en segundo plano. Logs en logs/s3.log"
# sleep infinity
