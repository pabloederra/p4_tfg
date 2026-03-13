# p4_tfg

Repositorio del proyecto **TFG basado en P4 y redes programables**.

Este repositorio contiene diferentes pruebas y configuraciones relacionadas con:

- P4
- Mininet
- GNS3
- Protocolos de red (ARP, GRE, DSCP)
- Implementaciones de routers y switches programables

---

# Requisitos

Antes de trabajar con el repositorio necesitas instalar:

- **Git**
- **Visual Studio Code**
- Extensión **Git** (ya viene integrada en VSCode)

Opcional pero recomendado:

- Extensión **GitLens**
- Extensión **Python**
- Extensión **P4 Language Support**

---

# 1. Descargar el repositorio con Git

Primero copia la URL del repositorio desde GitHub:

```

https://github.com/pabloederra/p4_tfg.git

````

Luego abre una terminal y ejecuta:

```bash
git clone https://github.com/pabloederra/p4_tfg.git
````

Esto descargará el repositorio en tu ordenador.

Se creará una carpeta llamada:

```
p4_tfg
```

---

# 2. Abrir el proyecto en Visual Studio Code

Una vez descargado el repositorio:

```bash
cd p4_tfg
code .
```

Esto abrirá el proyecto completo en **Visual Studio Code**.

También puedes hacerlo manualmente:

1. Abrir **Visual Studio Code**
2. Seleccionar **File → Open Folder**
3. Elegir la carpeta `p4_tfg`

---

# 3. Flujo básico de trabajo con Git

El flujo normal de trabajo es:

```
Editar → Añadir → Commit → Push
```

---

# 4. Ver el estado del repositorio

Para ver qué archivos han cambiado:

```bash
git status
```

Git mostrará:

* archivos modificados
* archivos nuevos
* archivos preparados para commit

---

# 5. Añadir archivos al commit

Para añadir un archivo concreto:

```bash
git add archivo.py
```

Para añadir todos los cambios:

```bash
git add .
```

---

# 6. Crear un commit

Un **commit** guarda un punto de control en el repositorio.

```bash
git commit -m "Descripción de los cambios"
```

Ejemplo:

```bash
git commit -m "Añadido soporte GRE"
```

---

# 7. Subir cambios a GitHub

Después del commit, sube los cambios al repositorio remoto:

```bash
git push
```

Esto enviará los cambios a GitHub.

---

# 8. Actualizar el repositorio local

Si hay cambios nuevos en GitHub puedes descargarlos con:

```bash
git pull
```

Esto sincroniza tu copia local con el repositorio remoto.

---

# 9. Uso de Git dentro de Visual Studio Code

Visual Studio Code tiene integración directa con Git.

Pasos:

1. Abrir el panel **Source Control** (icono de ramas)
2. Ver los archivos modificados
3. Pulsar **+** para hacer `stage`
4. Escribir mensaje de commit
5. Pulsar **Commit**
6. Pulsar **Push**

Esto realiza los mismos comandos:

```
git add
git commit
git push
```

---

# 10. Crear ramas (branch)

Las ramas permiten trabajar en nuevas funcionalidades sin romper el código principal.

Crear una rama:

```bash
git checkout -b nueva_funcionalidad
```

Cambiar de rama:

```bash
git checkout nombre_rama
```

Ver todas las ramas:

```bash
git branch
```

---

# 11. Estructura del repositorio

El proyecto contiene varios módulos de pruebas con P4:

```
p4_tfg
│
├── 2hosts_2switch (primer escenario que hice)
├── ARP          (implementacion de ARP)
├── DSCP         (marcado en DSCP)
├── GRE          (escenario con GRE)
├── router       (deadend sin terminar)
├── digestion    (intento de digest que tiene retraso NO SE POR QUE)
├── pre_gns3     (como el de gns3 pero creo que no tan bien)
├── gns3         (entorno de mininet para dejar preparado para gns3)
├── P4_GNS3      (el último que se va modificando en gns3)
├── utils        (porque en switch.py hay que meter el digest)
└── p4include
```

Cada carpeta contiene diferentes configuraciones y experimentos relacionados con redes programables.

---

# 12. Buenas prácticas con Git

Recomendaciones:

* Hacer commits pequeños y frecuentes
* Escribir mensajes claros en los commits
* Hacer `git pull` antes de empezar a trabajar
* No subir archivos innecesarios

---

# 13. Líneas futuras

Poner un único puerto de salida, un único puerto de entrada y generar una cabecera propia que tenga el marcado del túnel a través de nuestra red. Intentar cambiar el tunel_id y puertos para ponerlo en hexadecimal en lugar de decimal para poder ver si hacer reglas con lpm o mask en los match fields.

# Autor

Proyecto desarrollado por **Pablo Ederra** como parte de un **Trabajo Fin de Grado (TFG)** relacionado con **redes programables y P4**.
