# Proyecto P4 – Conectividad entre Hosts mediante Túneles

## 1. Descripción general

Este proyecto implementa una arquitectura de red basada en **P4 (v1model / BMv2)** con el objetivo de proporcionar **conectividad extremo a extremo entre múltiples hosts** distribuidos en varios switches y routers programables.

El sistema incluye:

* Programas P4 diferenciados para **switch** y **router**.
* Un **controlador en Python** que gestiona reglas de forwarding, aprendizaje y señalización hacia el plano de control.
* Soporte para **ARP, IPv4 y encapsulación tipo GRE** para crear túneles lógicos entre dominios.

El enfoque principal del diseño es permitir la comunicación entre hosts a través de una red multi‑salto utilizando:

* **Identificación de túneles mediante `tunnel_id` / clave GRE**.
* **Comunicación switch‑controlador** mediante clonación a CPU.
* Posible optimización futura usando **digest messages** en lugar de clones.

---

## 2. Arquitectura del repositorio

```
pre_gns3/
│
├── router.p4            # Lógica de encaminamiento y túneles GRE
├── switch.p4            # Lógica de switching L2/L3 y acceso a hosts
├── micontrolador.py     # Controlador P4Runtime
├── topology.json        # Topología de red (GNS3/BMv2)
├── build/               # Artefactos compilados (.json, p4info)
├── logs/                # Logs de ejecución P4Runtime
└── pcaps/               # Capturas de tráfico por interfaz
```

---

## 3. Plano de datos en P4

El programa `switch.p4` implementa:

* Procesamiento de **Ethernet, ARP e IPv4**.
* Reenvío basado en direcciones MAC/IP.
* Comunicación con el **CPU port (510)** mediante clonación (`clone session 67`).
* Soporte para múltiples hosts (`NUMBER_OF_HOSTS`).

Funcionalidades clave:

* **Aprendizaje de direcciones** asistido por el controlador.
* Manejo de **ARP broadcast** y resolución distribuida.
* Forwarding entre puertos de acceso y enlaces hacia routers.

En esencia, el switch actúa como:

> Un puente L2/L3 con capacidad de notificar eventos relevantes al controlador.

---

## 4. Controlador P4Runtime (`micontrolador.py`)

El controlador realiza varias funciones críticas:

### 4.1 Inicialización

* Establece conexión **gRPC P4Runtime** con cada switch.
* Carga **pipeline P4 compilado**.
* Define constantes globales:

  * `CPU_PORT = 510`
  * `CPU_PORT_CLONE_SESSION_ID = 67`
  * Direcciones MAC de hosts simulados.

### 4.2 Base de datos de conectividad

Se emplean estructuras simplificadas:

* `lookup_table` → alcanzabilidad entre hosts.
* `broadcast_mcast` → dominios de broadcast.
* `tabla_id` → asociación **host ↔ tunnel_id**.

Esto sustituye algoritmos reales de routing, manteniendo el proyecto enfocado en:

> **Mecánica de túneles y control P4Runtime**, no en cálculo óptimo de rutas.

### 4.3 Gestión de eventos desde el plano de datos

Actualmente se usa:

**Clonación a CPU → Packet‑In → Procesamiento en controlador**

Para:

* Aprendizaje de MAC/IP.
* Instalación dinámica de reglas.
* Manejo de ARP y descubrimiento.

---

## 5. Conectividad entre hosts mediante `tunnel_id`

El mecanismo central del proyecto es:

### 5.1 Identificación lógica

Cada comunicación inter‑dominio usa:

```
GRE.key  ≙  tunnel_id
```

Este identificador permite que los routers:

* Sepan **a qué dominio pertenece el paquete**.
* Determinen **dónde desencapsular**.

### 5.2 Flujo de tráfico

1. Host origen envía paquete IPv4.
2. Switch local lo reenvía al router de borde.
3. Router:

   * Consulta tabla de destino.
   * **Encapsula en GRE con `tunnel_id`** si es remoto.
4. Red intermedia transporta el paquete encapsulado.
5. Router remoto:

   * Detecta `tunnel_id`.
   * **Desencapsula y reinyecta** hacia el switch destino.
6. Switch entrega al host final.

Resultado:

> Conectividad transparente entre hosts en diferentes segmentos L2.

---

## 6. Clone vs Digest hacia el controlador

### 6.1 Enfoque actual: Clone

Ventajas:

* Implementación sencilla.
* Compatible con BMv2 sin configuración extra.
* Permite enviar **paquete completo** al controlador.

Desventajas:

* Alto consumo de ancho de banda CPU.
* Latencia innecesaria.
* No escalable en redes grandes.

---

### 6.2 Mejora propuesta: Digest

Uso de:

```
digest<T>() → notificación ligera al controlador
```

Beneficios:

* Solo se envían **metadatos relevantes**.
* Menor carga en CPU y canal gRPC.
* Escalabilidad realista tipo **data‑center fabrics**.

Arquitectura futura:

1. Switch genera **digest** con info de flujo nuevo.
2. Controlador instala regla directamente.
3. **Sin necesidad de clonar paquetes completos**.

Esto alinea el diseño con:

> Buenas prácticas de control en redes programables modernas.

---

## 7. Posibles extensiones del proyecto

* Sustituir tablas estáticas por:

  * **Algoritmos de routing dinámico**.
  * **Controlador SDN centralizado** con cálculo de caminos.
* Implementar:

  * **Digest‑based learning** completo.
  * **ECMP sobre túneles GRE**.
  * **Aislamiento multi‑tenant mediante `tunnel_id`**.
* Migración a:

  * **PSA architecture**.
  * **Tofino / hardware targets**.

---

## 8. Conclusión

El proyecto demuestra cómo P4 permite:

* Construir **planos de datos personalizados**.
* Implementar **túneles L3 sobre infraestructuras L2/L3 programables**.
* Integrar **controladores inteligentes** para aprendizaje dinámico.

La transición de **clone → digest** representa el siguiente paso natural hacia:

> **Escalabilidad, eficiencia y diseño SDN realista**.

---
