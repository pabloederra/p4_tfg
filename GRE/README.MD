# Escenario P4 – Tunelización y desencapsulado GRE con controlador

## Descripción general

Este proyecto implementa un escenario en **P4_16** que introduce **tunelización GRE (Generic Routing Encapsulation)** entre switches programables, utilizando un **controlador externo en Python** mediante **P4Runtime**.  

El objetivo principal es demostrar cómo un switch P4 puede:
- **Encapsular tráfico IP dentro de un túnel GRE**
- **Desencapsular tráfico GRE entrante**
- Tomar decisiones de forwarding basadas tanto en el encabezado externo como en el interno

Este escenario se apoya en **BMv2 (v1model)** y amplía significativamente las funcionalidades vistas en los escenarios anteriores (ARP y DSCP).

---

## Estructura del proyecto

```text
GRE/
├── gre.p4                    # Programa P4 con soporte GRE
├── micontrolador.py          # Controlador P4Runtime en Python
├── topology.json             # Definición de la topología
├── Makefile                  # Automatización de compilación y ejecución
├── build/                    # Archivos P4 compilados (JSON y P4Info)
├── logs/                     # Logs de switches y P4Runtime
└── pcaps/                    # Capturas de tráfico por interfaz
````

---

## Funcionamiento del programa P4 (`gre.p4`)

El programa P4 introduce una pipeline más compleja que en los escenarios anteriores:

### Encabezados soportados

* Ethernet
* IP externo
* GRE
* IP interno (payload del túnel)

### Parsing

* El parser distingue entre:

  * Paquetes IP normales
  * Paquetes GRE
* Si se detecta GRE, se extraen:

  * Encabezado GRE
  * Encabezado IP interno encapsulado

### Pipeline de procesamiento

El switch puede operar en dos modos lógicos:

#### 1. Encapsulación (ingreso al túnel)

* Paquetes IP “normales” que cumplen ciertas condiciones:

  * Se encapsulan dentro de un nuevo encabezado IP + GRE.
* Se construye:

  * IP externo (origen/destino del túnel)
  * Encabezado GRE
* El paquete encapsulado se reenvía hacia el switch remoto del túnel.

#### 2. Desencapsulación (egreso del túnel)

* Paquetes GRE entrantes:

  * Se elimina el encabezado IP externo.
  * Se elimina el encabezado GRE.
* El paquete IP interno resultante se reinyecta al pipeline para su forwarding normal.

### Deparser

* Reconstruye correctamente el paquete según haya sido encapsulado o desencapsulado.

---

## Funcionamiento del controlador (`micontrolador.py`)

El controlador cumple un rol **proactivo**, configurando el comportamiento del túnel:

1. **Inicialización**

   * Conexión a los switches BMv2 mediante gRPC.
   * Carga del `p4info` y del JSON compilado.

2. **Configuración del túnel GRE**

   * Instalación de reglas para:

     * Identificar tráfico que debe encapsularse.
     * Definir direcciones IP externas del túnel.
     * Seleccionar puertos de salida del túnel.

3. **Reglas de desencapsulado**

   * Configura tablas que reconocen paquetes GRE entrantes.
   * Asocia acciones de desencapsulación y forwarding del tráfico interno.

4. **Gestión centralizada**

   * Toda la lógica de qué tráfico entra o sale del túnel reside en el controlador.
   * El programa P4 actúa como un motor genérico de encapsulación/desencapsulación.

---

## Topología

La topología definida en `topology.json` incluye:

* Dos switches P4 que actúan como extremos del túnel GRE.
* Hosts conectados a cada extremo.
* Enlaces directos entre switches que representan el “core” o red intermedia.

Esto permite observar claramente:

* Tráfico original del host
* Tráfico encapsulado GRE entre switches
* Tráfico desencapsulado en el extremo remoto

---

## Cambios respecto a los escenarios anteriores

Este escenario introduce nuevas capacidades clave en comparación con ARP y DSCP:

### 1. Complejidad del parsing

* **ARP / DSCP**:
  Parsing simple (Ethernet + ARP o IP).
* **GRE**:
  Parsing jerárquico y condicional (Ethernet → IP → GRE → IP interno).

### 2. Manipulación profunda del paquete

* **ARP**: Reenvío de paquetes al controlador.
* **DSCP**: Modificación de un campo del encabezado IP.
* **GRE**:

  * Inserción y eliminación de múltiples encabezados.
  * Manejo de paquetes “anidados”.

### 3. Rol del switch

* **ARP**: Switch reactivo, dependiente del controlador.
* **DSCP**: Switch clasificador y marcador.
* **GRE**: Switch como **endpoint de túnel**, similar a un router o gateway.

### 4. Uso de P4Runtime

* **ARP**: PacketIn / PacketOut.
* **DSCP**: Inserción de reglas de clasificación.
* **GRE**:

  * Instalación de reglas de encapsulación.
  * Configuración de parámetros del túnel (IPs, puertos).

### 5. Objetivo funcional

* **ARP**: Resolución de direcciones.
* **DSCP**: QoS y diferenciación de tráfico.
* **GRE**: **Virtualización de la red y creación de overlays**.

---

## Ejecución del escenario

El flujo general es:

1. Compilación del programa `gre.p4`.
2. Despliegue de la topología.
3. Inicio del controlador.
4. Generación de tráfico IP entre hosts.
5. Observación del encapsulado GRE entre switches.
6. Verificación mediante archivos PCAP y logs.

El `Makefile` automatiza los pasos principales.

---

## Objetivo didáctico

Este escenario permite comprender:

* Cómo implementar **túneles GRE en P4**.
* Manipulación avanzada de paquetes en el plano de datos.
* Separación clara entre:

  * Lógica genérica en P4
  * Políticas concretas en el controlador
* Evolución desde funciones básicas (ARP) hasta mecanismos avanzados de red (overlays).

---

## Notas finales

* El escenario puede extenderse para VXLAN u otros protocolos de encapsulación.
* Las capturas en `pcaps/` son clave para validar el encapsulado y desencapsulado.
* Junto con ARP y DSCP, este escenario completa una progresión clara en complejidad y capacidades de P4.
