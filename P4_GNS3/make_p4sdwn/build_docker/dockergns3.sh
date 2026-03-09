#!/bin/bash

# Script de instalación para Docker, GNS3 y contenedores P4
# Nota: Este script requiere permisos de sudo para ciertas operaciones.

echo "--- 1º: INSTALANDO DOCKER Y DEPENDECIAS ---"
sudo apt update
sudo apt install -y docker.io python3 python3-pip

# Configuración de permisos para Docker (sin sudo)
echo "Configurando permisos de Docker para el usuario $USER..."
sudo usermod -aG docker $USER

---

echo "--- 2º: INSTALANDO GNS3 ---"
sudo add-apt-repository -y ppa:gns3/ppa
sudo apt update
sudo apt install -y gns3-gui gns3-server

---

echo "--- 3º: CONSTRUYENDO IMÁGENES DOCKER P4 ---"

# Cambia esta ruta a la ubicación real de tu carpeta build_docker
# Por defecto intenta entrar en la carpeta actual si existe build_docker
    
echo "Construyendo p4node..."
docker build -t p4node -f Dockerfile.p4node .

echo "Construyendo p4router..."
docker build -t p4router -f Dockerfile.p4router .

echo "Construyendo p4controller..."
docker build -t p4ctrlp4c -f Dockerfile.p4controller .

echo "Renombrando imágenes (Tagging)..."
docker tag p4node p4sdwn/p4node:latest
docker tag p4router p4sdwn/p4router:latest
docker tag p4ctrlp4c p4sdwn/p4ctrlp4c:latest

echo "Proceso de Docker completado con éxito."

---

echo "--- INSTALACIÓN FINALIZADA ---"
echo "IMPORTANTE: Debes REINICIAR el sistema (o cerrar sesión) para que los cambios"
echo "de grupo de Docker surtan efecto y GNS3 pueda comunicarse con el motor de Docker."