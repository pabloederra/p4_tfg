# Escenario P4 – Manejo básico de ARP con controlador

## Warning

El flooding esta mal hecho (no da error pero esta mal hecho, confia). En DSCP lo he arreglado

## Descripción general

Este proyecto implementa un escenario sencillo en **P4_16** para el manejo de tráfico **ARP** utilizando un **controlador externo en Python** a través de **P4Runtime**.  
El objetivo principal es mostrar cómo un plano de datos programable puede delegar cierta lógica (en este caso, el aprendizaje y la resolución ARP) al plano de control, manteniendo el programa P4 lo más simple posible.

El escenario está pensado para ejecutarse sobre **BMv2 (v1model)** y se apoya en un controlador que procesa paquetes ARP enviados al CPU del switch y responde de forma adecuada.

---

## Estructura del proyecto

```text
ARP/
├── arp_tonto.p4              # Programa P4 del switch
├── micontrolador.py          # Controlador P4Runtime en Python
├── topology.json             # Topología del escenario
├── Makefile                  # Automatización de compilación y ejecución
├── build/                    # Archivos generados (JSON y P4Info)
├── logs/                     # Logs del switch y P4Runtime
└── pcaps/                    # Capturas de tráfico por interfaz
````

---

## Funcionamiento del programa P4 (`arp_tonto.p4`)

El programa P4 implementa un comportamiento mínimo en el plano de datos:

* Define los encabezados necesarios para Ethernet y ARP.
* Identifica paquetes ARP en el pipeline de parsing.
* Reenvía los paquetes ARP al **puerto CPU** (control plane) en lugar de resolverlos completamente en el switch.
* Para el resto del tráfico, el comportamiento es básico (forwarding simple o descarte, según la configuración).

La idea central es que el switch **no mantiene una tabla ARP compleja**, sino que delega esa responsabilidad al controlador.

---

## Funcionamiento del controlador (`micontrolador.py`)

El controlador está implementado en Python y utiliza la API de **P4Runtime**. Sus funciones principales son:

1. **Conexión al switch**
   Se conecta al switch BMv2 usando gRPC y carga el archivo `p4info` y el JSON compilado.

2. **Recepción de paquetes ARP**

   * Escucha los paquetes enviados al CPU por el switch.
   * Analiza los paquetes ARP usando **Scapy**.

3. **Aprendizaje ARP**

   * Mantiene una estructura interna que asocia direcciones IP con direcciones MAC y puertos.
   * Aprende esta información a partir de los paquetes ARP recibidos.

4. **Respuesta a solicitudes ARP**

   * Cuando recibe un ARP Request para una IP conocida, genera un ARP Reply.
   * Envía el ARP Reply de vuelta al switch para que sea reenviado al host correspondiente.

5. **Registro y depuración**

   * Guarda información de eventos y tráfico en logs.
   * Permite analizar el comportamiento del escenario mediante los archivos `.pcap`.

---

## Topología

La topología definida en `topology.json` consiste en:

* Dos switches P4.
* Varios hosts conectados a los switches.
* Enlaces simples para facilitar el seguimiento del tráfico ARP.

Este diseño permite observar claramente el intercambio ARP y la intervención del controlador.

---

## Ejecución del escenario

De forma general, el flujo de ejecución es el siguiente:

1. Compilar el programa P4 (`arp_tonto.p4`) para BMv2.
2. Levantar la topología definida.
3. Iniciar el controlador (`micontrolador.py`).
4. Generar tráfico ARP desde los hosts (por ejemplo, usando `ping`).
5. Analizar los resultados mediante logs y capturas `.pcap`.

El `Makefile` automatiza gran parte de estos pasos.

---

## Objetivo didáctico

Este escenario está pensado con fines educativos y demuestra:

* Separación clara entre **plano de datos (P4)** y **plano de control (Python)**.
* Uso de **P4Runtime** para el manejo de paquetes excepcionales.
* Implementación de un ARP “tonto” en el switch y una lógica más rica en el controlador.

No busca ser una implementación óptima de ARP, sino un ejemplo claro y fácil de entender.

---

## Notas finales

* El código puede extenderse fácilmente para soportar más protocolos o reglas de forwarding.
* Las capturas en `pcaps/` son útiles para validar el correcto funcionamiento del escenario.
* Este enfoque es común en entornos SDN donde el control se centraliza y el switch se mantiene simple.
