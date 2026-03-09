# P4 Network Digestion Project

Este proyecto implementa una red definida por software utilizando **P4** y **P4Runtime**, junto con un controlador en **Python** para gestionar el comportamiento de los switches.

El objetivo es definir y probar diferentes comportamientos de red mediante programas P4 y controlar la lógica de forwarding desde un controlador externo.

---

## Estructura del proyecto

```

digestion/
│
├── build/                # Archivos compilados de los programas P4
│   ├── router.json
│   ├── router.p4.p4info.txtpb
│   ├── switch.json
│   ├── switch.p4.p4info.txtpb
│   ├── tonto.json
│   └── tonto.p4.p4info.txtpb
│
├── logs/                 # Logs de ejecución de los switches
│
├── pcaps/                # Capturas de tráfico de cada interfaz
│
├── router.p4             # Implementación P4 de router
├── switch.p4             # Implementación P4 de switch
├── tonto.p4              # Implementación P4 simple
│
├── topology.json         # Definición de la topología de red
│
├── micontrolador.py      # Controlador principal en Python
├── mycontrol.py          # Lógica de control adicional
│
├── Makefile              # Automatización de compilación y ejecución
│
└── README.md

````

---

# Requisitos

Para ejecutar el proyecto se necesitan:

- **P4C compiler**
- **BMv2 (Behavioral Model)**
- **Mininet**
- **Python 3**
- **P4Runtime**

Entornos típicos donde funciona:

- VM oficial de P4
- Ubuntu 20.04 / 22.04 con entorno P4 instalado

---

# Compilación

Los programas P4 se compilan utilizando el `Makefile`.

```bash
make
````

Esto generará en el directorio `build/`:

* JSON del pipeline
* Archivos `p4info` necesarios para P4Runtime

---

# Ejecución de la topología

La red se define en:

```
topology.json
```

Para lanzar el entorno:

```bash
sudo make run
```

Esto normalmente:

1. Inicia **Mininet**
2. Carga los programas **P4** en los switches
3. Conecta el controlador Python

---

# Controlador

El comportamiento dinámico de la red se gestiona mediante:

```
micontrolador.py
```

y

```
mycontrol.py
```

El controlador utiliza **P4Runtime** para:

* Instalar reglas en las tablas
* Gestionar forwarding
* Procesar eventos de los switches

---

# Captura de tráfico

El directorio:

```
pcaps/
```

contiene capturas `.pcap` por interfaz de switch.

Se pueden analizar con:

```
wireshark
```

o

```
tcpdump
```

Ejemplo:

```bash
wireshark pcaps/s1-eth1_in.pcap
```

---

# Logs

Los logs generados durante la ejecución se almacenan en:

```
logs/
```

Incluyen:

* logs de switches
* peticiones P4Runtime
* debugging del pipeline

---

# Programas P4 incluidos

### `switch.p4`

Implementación de un switch programable.

### `router.p4`

Implementación de lógica de enrutamiento IP.

### `tonto.p4`

Versión simplificada usada para pruebas o comportamiento base.

---

# Flujo de funcionamiento

1. Se compilan los programas P4
2. Se inicia la topología en Mininet
3. Los switches cargan el pipeline P4
4. El controlador instala reglas mediante P4Runtime
5. Se captura tráfico en las interfaces para análisis

---

# Posibles usos del proyecto

* Prácticas de **SDN**
* Experimentación con **P4**
* Implementación de pipelines de forwarding personalizados
* Análisis de tráfico con PCAP

---

# Autor

Proyecto académico para experimentación con **P4 y redes definidas por software**.
