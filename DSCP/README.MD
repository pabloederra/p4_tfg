README.MD
# Escenario P4 – Clasificación y marcado DSCP con controlador

## WARNING

Me falta poner que el marcado del tipo ipv4 sea cuando un pacquete entra por el puerto 1

## Descripción general

Este proyecto implementa un escenario en **P4_16** orientado a la **clasificación y tratamiento del campo DSCP** del encabezado IP, utilizando un **controlador externo en Python** mediante **P4Runtime**.  
A diferencia del escenario anterior centrado en ARP, este caso se enfoca en **tráfico IP** y en cómo aplicar políticas de red (QoS / diferenciación de tráfico) desde el plano de control.

El escenario se ejecuta sobre **BMv2 (v1model)** y combina lógica sencilla en el plano de datos con decisiones de mayor nivel tomadas por el controlador.

---

## Estructura del proyecto

```text
DSCP/
├── dscp.p4                   # Programa P4 para el tratamiento DSCP
├── micontrolador.py          # Controlador P4Runtime en Python
├── topology.json             # Definición de la topología
├── Makefile                  # Automatización de compilación y ejecución
├── build/                    # Archivos P4 compilados (JSON y P4Info)
├── logs/                     # Logs de switches y P4Runtime
└── pcaps/                    # Capturas de tráfico por interfaz
````

---

## Funcionamiento del programa P4 (`dscp.p4`)

El programa P4 implementa la lógica básica para el procesamiento de paquetes IP:

* Define encabezados Ethernet e IP.
* Extrae el campo **DSCP** del encabezado IP.
* Clasifica los paquetes en función del valor DSCP.
* Aplica acciones simples como:

  * Reenvío por un puerto determinado.
  * Modificación del campo DSCP (según reglas instaladas).
* Permite que el controlador instale dinámicamente las reglas de clasificación mediante tablas P4.

El switch actúa como un **elemento de forwarding y marcado**, mientras que la política concreta depende del controlador.

---

## Funcionamiento del controlador (`micontrolador.py`)

El controlador en Python cumple las siguientes funciones:

1. **Inicialización del switch**

   * Conexión al switch BMv2 vía gRPC.
   * Carga del `p4info` y del JSON generado.

2. **Instalación de reglas DSCP**

   * Inserta entradas en las tablas P4 para:

     * Reconocer determinados valores DSCP.
     * Asociar dichos valores a acciones específicas (forwarding o remarking).

3. **Gestión centralizada de políticas**

   * La lógica de decisión (qué DSCP tratar de qué manera) se mantiene en el plano de control.
   * Facilita modificar el comportamiento de la red sin recompilar el programa P4.

4. **Monitoreo y depuración**

   * Registro de interacciones P4Runtime.
   * Soporte para análisis posterior mediante logs y capturas PCAP.

---

## Topología

La topología definida en `topology.json` incluye:

* Dos switches P4.
* Hosts conectados a cada switch.
* Enlaces simples que permiten observar cómo el tráfico con distintos valores DSCP atraviesa la red.

Esta topología es adecuada para verificar políticas de clasificación y forwarding basadas en DSCP.

---

## Cambios respecto al escenario ARP

En comparación con el escenario anterior (ARP con controlador), este proyecto introduce varios cambios conceptuales y técnicos:

### 1. Protocolo tratado

* **Escenario ARP**:
  Se centra en paquetes ARP y en su resolución mediante el controlador.
* **Escenario DSCP**:
  Trabaja sobre paquetes **IP**, específicamente sobre el campo DSCP del encabezado.

### 2. Rol del controlador

* **ARP**:
  El controlador procesa paquetes ARP enviados al CPU, aprende direcciones y genera respuestas ARP.
* **DSCP**:
  El controlador **no responde paquetes**, sino que instala **reglas proactivas** para clasificar y tratar el tráfico.

### 3. Plano de datos

* **ARP**:
  El switch es deliberadamente “tonto” y reenvía ARP al controlador.
* **DSCP**:
  El switch realiza clasificación y acciones directamente en el pipeline, usando reglas cargadas dinámicamente.

### 4. Objetivo funcional

* **ARP**:
  Resolver direcciones IP–MAC y demostrar manejo de paquetes excepcionales.
* **DSCP**:
  Demostrar **QoS, diferenciación de tráfico y políticas de red** basadas en campos IP.

### 5. Interacción con P4Runtime

* **ARP**:
  Predomina el uso de `PacketIn` y `PacketOut`.
* **DSCP**:
  Predomina la inserción y modificación de **entradas de tablas P4**.

---

## Ejecución del escenario

El flujo general es:

1. Compilación del programa `dscp.p4`.
2. Despliegue de la topología.
3. Inicio del controlador.
4. Generación de tráfico IP con distintos valores DSCP.
5. Verificación del comportamiento mediante PCAPs y logs.

El `Makefile` automatiza estos pasos.

---

## Objetivo didáctico

Este escenario permite entender:

* Cómo usar P4 para clasificar tráfico IP.
* Cómo delegar políticas de red al plano de control.
* Diferencias entre control **reactivo** (ARP) y **proactivo** (DSCP).
* Uso práctico de P4Runtime para gestionar QoS de forma centralizada.

---

## Notas finales

* El escenario puede extenderse para colas, prioridades o integración con traffic shaping.
* Las capturas en `pcaps/` permiten validar el marcado y forwarding DSCP.
* Junto con el escenario ARP, ofrece una visión progresiva del diseño SDN con P4.
