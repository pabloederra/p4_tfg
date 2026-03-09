
BUILD_DIR = .
LOG_DIR = ../logs
P4C = p4c-bm2-ss
P4C_ARGS = --p4v 16 --p4runtime-files $(BUILD_DIR)/$*.p4.p4info.txtpb

# Buscar archivos .p4 en el directorio actual
source := $(wildcard *.p4)

# Definir los objetivos: <nombre>.json para cada <nombre>.p4
compiled_json := $(patsubst %.p4,$(BUILD_DIR)/%.json,$(source))

# Objetivo por defecto: crea directorios y compila todos los JSONs
all: dirs $(compiled_json)

# Regla patrón: Cómo crear <nombre>.json desde <nombre>.p4
$(BUILD_DIR)/%.json: %.p4
	$(P4C) $(P4C_ARGS) -o $@ $<

dirs:
	mkdir -p $(LOG_DIR)

clean:
	rm -rf $(BUILD_DIR)/*.json $(BUILD_DIR)/*.p4info.txtpb $(LOG_DIR)
