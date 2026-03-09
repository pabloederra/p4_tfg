1º: INSTALAR DOCKER
	sudo apt update
	sudo apt install -y docker.io python3 python3-pip

     - Para que gns3 pueda usar docker sin permisos de sudo:
	sudo usermod -aG docker $USER

2º: INSTALAR GNS3

	sudo add-apt-repository ppa:gns3/ppa
	sudo apt update
	sudo apt install -y gns3-gui gns3-server


3º: CARPETA make_p4sdnwn

- cd /a/la/carpeta/build_docker: contiene los Dockerfile y carpeta /deps para crear los contenedores:
  	docker build -t p4node -f Dockerfile.p4node .
	docker build -t p4router -f Dockerfile.p4router .
	docker build -t p4ctrlp4c -f Dockerfile.p4controller .

  para que "cuadre" con GNS3, renombrar la imagen (es la que pone en la "image" en el project si lo abres con vcode):

	docker tag p4node p4sdwn/p4node:latest
	docker tag p4router p4sdwn/p4router:latest
	docker tag p4ctrlp4c p4sdwn/p4ctrlp4c:latest

Reinicias para que se guarde lo de sudo usermod -aG docker $USER y gns3 pueda acceder a Docker

4º ABRES GNS3

Lo mejor es importarlo desde p4sdwn2.gns3project, pero si da algún error, se puede copiar la carpeta y modificar manualmente el contenido del archivo p4sdwn2.gns3 (por ejemplo, cambiar la imagen docker de cada nodo si cambiamos).

Una vez arrancamos los equipos en GNS3, se ejecuta:
 
	# en los switches
	( bash -c "cd /lab/config && sh sXstart.sh & exec /bin/bash" ) [para cada switch, su sXstart.sh]

	# en controlador
	cd p4
	python3 micontrolador.py / test_logs.py (el que sea)


TIPS MARÍA:

  Los contenedores se crean con el volumen /lab, que incluye /lab/config, /lab/p4 y /lab/logs
  Una vez creados los contenedores docker al ejecutar en GNS3, se pueden copiar allí los archivos necesarios

- config: contiene todos los sXstart.sh a ejecutar en los nodos
- p4: contiene los archivos necesarios en el controlador o el debugger (este último, solo debug_cli.sh)

Si modificamos archivos de /p4 o de /config, para copiarlos y no hacerlo uno a uno, ejecutar
  ./copytogns3.sh (modificable si cambiamos escenario)