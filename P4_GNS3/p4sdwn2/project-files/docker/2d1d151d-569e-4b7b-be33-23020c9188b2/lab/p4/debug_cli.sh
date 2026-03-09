#!/bin/bash

# Valores por defecto para S1 (router)
# Ajusta la IP si quieres conectar a S2 (ej: ./debug_cli.sh 192.168.0.2)
SWITCH_IP=${1:-"192.168.0.1"}
SWITCH_PORT=${2:-"9559"}
DEVICE_ID=0

echo "Conectando p4runtime-shell a $SWITCH_IP:$SWITCH_PORT (DeviceId: $DEVICE_ID)..."
echo "Usa 'tables' para ver tablas."
echo "Ejemplo: table_entry['MyIngress.flow_eth'].read()"

# Lanzar la shell
python3 -m p4runtime_sh \
  --grpc-addr $SWITCH_IP:$SWITCH_PORT \
  --device-id $DEVICE_ID \
  --election-id 0,2  # Usamos election-id diferente para no pisar al controlador principal (que suele usar 0,1)
