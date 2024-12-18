#!/usr/bin/python3
import os
import sys
import json
import datetime
import subprocess
from pathlib import PureWindowsPath, PurePosixPath
# Definir archivo de logs dependiendo del sistema operativo
if os.name == 'nt':
    LOG_FILE = "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"
ADD_COMMAND = 0
DELETE_COMMAND = 1
CONTINUE_COMMAND = 2
ABORT_COMMAND = 3
OS_SUCCESS = 0
OS_INVALID = -1
ITOP_API_URL = "xxx"
ITOP_API_USER = "x"
ITOP_API_PASS = "x"
class message:
    def _init_(self):
        self.alert = ""
        self.command = 0
def write_debug_file(ar_name, msg):
    """Escribir en el archivo de logs"""
    with open(LOG_FILE, mode="a") as log_file:
        ar_name_posix = str(PurePosixPath(PureWindowsPath(ar_name[ar_name.find("active-response"):])))
        if msg=="Iniciado":
            log_file.write(str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')) +  msg + "\n")
        else:    
            log_file.write(str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')) + " " + ar_name_posix + ": " + msg + "\n")
def setup_and_check_message(argv):
    """Procesar la alerta de stdin"""
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break
    write_debug_file(argv[0], input_str)
    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Error al decodificar JSON')
        message.command = OS_INVALID
        return message
    message.alert = data
    command = data.get("command")
    if command == "add":
        message.command = ADD_COMMAND
    elif command == "delete":
        message.command = DELETE_COMMAND
    else:
        message.command = OS_INVALID
        write_debug_file(argv[0], 'Comando no válido: ' + command)

    return message

def create_itop_incident(alert):
    """Crear un incidente en iTop mediante curl"""
    json_data = {
        "operation": "core/create",
        "comment": "Sincronización desde alerta Wazuh",
        "class": "Incident",
        "output_fields": "id, friendlyname",
        "fields": {
            "org_id": "SELECT Organization WHERE name = 'TESTCORP'",
            "caller_id": {
                "name": "x",
                "first_name": "x"
            },
            "title": f"Alerta: {alert.get('rule', {}).get('id', 'Desconocido')}",
            "description": f"Wazuh Alerta: {alert.get('rule', {}).get('description', 'Sin descripción disponible')} "
        }
    }

    # Escribir el archivo JSON temporalmente
    with open('/tmp/itop_incident.json', 'w') as json_file:
        json.dump(json_data, json_file)
    # Llamar a la API de iTop mediante curl
    curl_command = [
        "curl", "-X", "POST",
        "-F", f"version=x",
        "-F", f"auth_user={ITOP_API_USER}",
        "-F", f"auth_pwd={ITOP_API_PASS}",
        "-F", "json_data=@/tmp/itop_incident.json",
        ITOP_API_URL
    ]

    try:
        result = subprocess.run(curl_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        if result.returncode == 0:
            write_debug_file("create_itop_incident", f"Incidente creado en iTop: {result.stdout}")
        else:
            write_debug_file("create_itop_incident", f"Error al crear el incidente: {result.stderr}")
    except Exception as e:
        write_debug_file("create_itop_incident", f"Error al ejecutar curl: {e}")

def main(argv):
    """Función principal para manejar la alerta de Wazuh"""
    write_debug_file(argv[0], "Iniciado")
    # Procesar y validar el mensaje JSON desde stdin
    msg = setup_and_check_message(argv)
    if msg.command < 0:
        sys.exit(OS_INVALID)
    if msg.command == ADD_COMMAND:
        alert = msg.alert.get("parameters", {}).get("alert", {})
        # Enviar la alerta a iTop
        create_itop_incident(alert)
    elif msg.command == DELETE_COMMAND:
        write_debug_file(argv[0], "No hay acción para eliminar")
    write_debug_file(argv[0], "Terminado")
    sys.exit(OS_SUCCESS)
if __name__ == "_main_":
    main(sys.argv)