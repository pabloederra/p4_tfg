#!/bin/bash

# Directorio destino donde buscar los archivos a reemplazar
TARGET_DIR="/home/p4/GNS3/projects/p4sdwn2/project-files/docker"

# Lista de archivos de configuración específicos
CONFIG_FILES=(
    "config/s1start.sh"
    "config/s2start.sh"
    "config/s3start.sh"
    "config/s4start.sh"
    "config/s5start.sh"
)

# Lista de archivos de P4 específicos
P4_FILES=(
    "p4/switch.p4"
    "p4/router.p4"
    "p4/Makefile"
    "p4/micontrolador.py"
    "p4/test_logs.py"
    "p4/debug_cli.sh"
    "p4/swtopo.json"
)

# Función para buscar y reemplazar archivos
update_file() {
    local source_path="$1"
    local filename=$(basename "$source_path")
    
    if [ -f "$source_path" ]; then
        echo "Buscando instancias de '$filename' en GNS3 para actualizar..."
        # Busca archivos con ese nombre en el directorio destino y los sobrescribe con la versión local
        # Usamos -name para buscar por nombre de archivo sin importar la ruta
        find "$TARGET_DIR" -type f -name "$filename" -exec cp -v "$source_path" {} \;
    else
        echo "Advertencia: El archivo origen '$source_path' no existe."
    fi
}

# 1. Actualizar scripts de configuración
echo "=== Actualizando scripts de configuración ==="
for file in "${CONFIG_FILES[@]}"; do
    update_file "$file"
done

# 2. Actualizar scripts de configuración
echo "=== Actualizando archivos P4 ==="
for file in "${P4_FILES[@]}"; do
    update_file "$file"
done

echo "=== Proceso completado ==="