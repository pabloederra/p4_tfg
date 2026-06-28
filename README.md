# p4_tfg

Este proyecto corresponde al desarrollo de un **Trabajo Fin de Grado (TFG) basado en P4 y redes programables**.

El objetivo principal es el diseño, despliegue y validación de diferentes escenarios de red y protocolos utilizando planos de datos programables. En este espacio se centralizan las pruebas, topologías y configuraciones relacionadas con:

- Lenguaje de programación P4
- Emulación de redes con Mininet
- Integración en entornos virtuales con GNS3
- Implementación de protocolos de red (ARP, GRE, DSCP)
- Desarrollo de lógica personalizada para routers y switches programables

---

# Requisitos del Entorno

Para trabajar con los archivos de este proyecto, se requiere el siguiente software y herramientas de desarrollo:

## Software de Emulación y Redes
- **Mininet:** Entorno de emulación para desplegar los switches virtuales P4 (BMv2).
- **GNS3:** Plataforma de simulación para integrar los escenarios P4 con otros elementos de red virtuales.
- **Compilador P4 (p4c):** Necesario para compilar el código fuente P4 en JSON ejecutable por el software switch.

## Entorno de Desarrollo (IDE)
- **Visual Studio Code**

### Extensiones recomendadas para VSCode:
- **P4 Language Support:** Para el coloreado de sintaxis y autocompletado de código P4.
- **Python:** Esencial para ejecutar y editar los scripts de control y generación de tráfico.

---

# Configuración y Uso en Visual Studio Code

Para trabajar en el proyecto de forma local:

1. Asegúrate de tener la carpeta del proyecto (`p4_tfg`) descargada en tu equipo.
2. Abre **Visual Studio Code**.
3. En el menú superior, selecciona **File → Open Folder...** (Archivo → Abrir carpeta).
4. Selecciona la carpeta raíz `p4_tfg`.

Desde el entorno podrás modificar tanto la lógica de los planos de datos (`.p4`) como las topologías asociadas.

---

# Estructura del Proyecto

El proyecto se compone de varios módulos independientes que representan la evolución y los distintos experimentos del TFG:


```

p4_tfg
│
├── 2hosts_2switch   # Escenario inicial de pruebas con dos hosts y dos switches.
├── ARP              # Implementación de la resolución y manejo del protocolo ARP.
├── DSCP             # Pruebas de clasificación y marcado de paquetes usando DSCP.
├── GRE              # Despliegue de un escenario de red con encapsulación de túneles GRE.
├── router           # Prototipo inicial de enrutamiento (en desarrollo).
├── digestion        # Experimentación con el mecanismo de "Digest" (analizando latencias de control).
├── pre_gns3         # Configuración previa de topología orientada a la migración.
├── gns3             # Entorno de Mininet preparado específicamente para la integración con GNS3.
├── P4_GNS3          # Entorno principal activo y actualizado en GNS3.
├── utils            # Scripts auxiliares y herramientas de soporte (incluye lógica de digests para switch.py).
└── p4include        # Cabeceras y archivos de inclusión estándar de P4.

```

Cada carpeta contiene sus propios archivos de definición P4, scripts de control en Python y archivos de configuración topológica.

---

# Autor

Proyecto desarrollado por **Pablo Ederra** como parte de un **Trabajo Fin de Grado (TFG)** relacionado con **redes programables y P4**.
