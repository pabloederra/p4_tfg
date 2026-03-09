ESCENARIO PRELIMINAR DE GNS3:

CARPETA make_p4sdnwn
-------------------------
- build_docker: contiene los Dockerfile y carpeta /deps para crear los contenedores:
  docker build -t p4node -f Dockerfile.p4ode .
  para que "cuadre" con GNS3, renombrar la imagen
  docker tag p4node p4sdwn/p4node:latest

  Los contenedores se crean con el volumen /lab, que incluye /lab/config, /lab/p4 y /lab/logs
  Una vez creados los contenedores docker al ejecutar en GNS3, se pueden copiar allí los archivos necesarios

- config: contiene todos los sXstart.sh a ejecutar en los nodos
- p4: contiene los archivos necesarios en el controlador o el debugger (este último, solo debug_cli.sh)

Si modificamos archivos de /p4 o de /config, para copiarlos y no hacerlo uno a uno, ejecutar
  ./copytogns3.sh (modificable si cambiamos escenario)

CARPETA p4sdwn2
-------------------------
- es el escenario de GNS3. Lo mejor es importarlo desde p4sdwn2.gns3project, pero si da algún error, se puede copiar la carpeta y modificar manualmente el contenido del archivo p4sdwn2.gns3 (por ejemplo, cambiar la imagen docker de cada nodo si cambiamos)

EJECUCIÓN EN GNS3:
-------------------------
una vez arrancamos los equipos en GNS3, se ejecuta:
 
# en los switches
( cd config && sh s1start.sh ) [para cada switch, su sXstart.sh]

# en controlador
cd p4
python3 micontrolador.py / test_logs.py
