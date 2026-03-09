# Reactive SDN Switch con P4 y Flow Cache

Este proyecto implementa un switch SDN reactivo utilizando P4 (Data Plane) y Python (Control Plane). El sistema gestiona el tráfico entre hosts instalando reglas de flujo bajo demanda (*Packet-In*) y eliminándolas automáticamente cuando dejan de usarse (*Idle Timeout*).

## 🏗 Arquitectura del Escenario

La topología emulada en Mininet consta de dos hosts conectados a través de dos switches en serie:

```text
h1 (10.0.0.1) <--> [p1] s1 [p2] <----> [p2] s2 [p1] <--> h2 (10.0.0.2)
```

### Componentes Clave

1. **Data Plane (`first.p4`):**
* Define headers para Ethernet, IPv4, PacketIn y PacketOut.
* Utiliza una tabla `flow_cache` con soporte para **Idle Timeout** (detección de inactividad).
* Si un paquete no coincide con ninguna regla, se envía al controlador (Packet-In).
* Maneja la clonación de paquetes hacia el puerto CPU (510).


2. **Control Plane (`micontrolador.py`):**
* Escrito en Python 3 usando `p4runtime_lib` y `asyncio`.
* Procesa mensajes **Packet-In**: Calcula el puerto de salida y la MAC destino.
* Instala reglas de flujo (**Flow Rules**) dinámicamente.
* Gestiona **Packet-Out**: Reinyecta el primer paquete del flujo a la red.
* Gestiona **Idle Notifications**: Recibe avisos del switch cuando una regla caduca y la elimina de la memoria para mantener la tabla limpia.



---

## La "Trampa" ARP (Static ARP Entries)

Para simplificar el código P4 y centrarnos en el routing L3/L2, se ha implementado una solución estática para la resolución de direcciones (ARP).

**El Problema:**
Al estar `h1` y `h2` en la misma subred (`10.0.0.0/24`), Linux intenta resolver la MAC del destino enviando peticiones ARP Broadcast. Como nuestro código P4 en `MyIngress` descarta paquetes que no sean IPv4 o PacketOut, las peticiones ARP se perderían y el Ping fallaría.

**La Solución (En `topology.json`):**
Se han inyectado entradas ARP estáticas en los hosts para "engañarlos" y forzar el envío inmediato del tráfico hacia el switch sin preguntar.

* **En h1:** `arp -s 10.0.0.2 08:00:00:00:01:00`
* *Traducción:* "H1, si quieres hablar con H2, no preguntes. Envía el paquete a la MAC `...01:00` (que corresponde al puerto de entrada de S1)".


* **En h2:** `arp -s 10.0.0.1 08:00:00:00:02:00`

De esta forma, el paquete entra al pipeline P4 como un paquete IPv4 válido unicast desde el primer momento.

---

## Instrucciones de Ejecución

### 1. Compilación y Arranque de la Red

Este comando compila el código P4, genera los archivos JSON/P4Info y levanta la topología en Mininet.

```bash
make

```

### 2. Iniciar el Controlador

En una nueva terminal, ejecuta el controlador. Este script se conectará a los switches s1 y s2 vía gRPC.

```bash
./micontrolador.py

```

### 3. Prueba de Conectividad (Ping)

En la consola de Mininet, lanza un ping.

```bash
mininet> h1 ping h2

```

**Comportamiento esperado:**

1. **Primer Paquete:** El controlador recibe un `Packet-In`. Instala la regla en s1 y s2 (unidireccional).
2. **Siguientes Paquetes:** Fluyen directamente por el hardware (Data Plane) gracias a la regla instalada.
3. **Timeout:** Si detienes el ping y esperas unos segundos (configurado a 3s en el código), verás en el log del controlador cómo se eliminan las reglas por inactividad (`IdleTimeoutNotification`).
---
## 📂 Estructura del Proyecto

* `first.p4`: Código fuente P4 (Ingress, Egress, Parser).
* `micontrolador.py`: Lógica del controlador (Manejo de reglas, timeouts y decoding de metadatos).
* `topology.json`: Definición de la red y comandos de configuración de hosts (ARP estático).
* `Makefile`: Scripts de automatización para compilar y ejecutar.

---
## ⚙️ Detalles Técnicos Adicionales

* **CPU Port:** 510. Usado como interfaz virtual entre el switch y el controlador.
* **Clone Session ID:** 67. Usado para duplicar paquetes hacia la CPU.