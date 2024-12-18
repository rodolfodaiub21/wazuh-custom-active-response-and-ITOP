
# Wazuh Alert to iTop Incident Synchronization

## Overview

This script integrates Wazuh alerts with iTop by creating incidents in iTop based on received alert data. It processes JSON input from Wazuh, validates the content, and uses the iTop API to create incidents. Logs are written to a file for debugging and tracking purposes.

## Features

- Reads and processes JSON alert data from stdin.
- Validates commands (`add`, `delete`, etc.).
- Logs all actions and errors to a specified log file.
- Creates incidents in iTop using its API with customizable fields.

## Requirements

- **Python 3**
- **cURL** installed on the system.
- Access to the iTop API with valid credentials.
- Wazuh active-response configured to call this script.

## Configuration

### Log File Path

The log file path is defined based on the operating system:

- **Windows**: `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log`
- **Linux**: `/var/ossec/logs/active-responses.log`

### API Configuration

Replace the placeholders in the script with your iTop API details:

- `ITOP_API_URL`: URL of the iTop API.
- `ITOP_API_USER`: API username.
- `ITOP_API_PASS`: API password.

## How It Works

1. **Alert Input**: The script reads JSON input from stdin, which contains alert information.
2. **Command Validation**: The script checks the command type (`add`, `delete`) and logs invalid commands.
3. **Incident Creation**: For `add` commands, the script constructs an incident JSON object and sends it to the iTop API using `curl`.
4. **Logging**: All actions, including errors, are logged to the specified log file.

## Usage

### Running the Script

The script is intended to be invoked by Wazuh as part of its active-response mechanism.

To run manually (for testing purposes):

```bash
python3 script_name.py < input.json
or implement the documentation on the wazuh documentation: https://documentation.wazuh.com/4.8/user-manual/capabilities/active-response/custom-active-response-scripts.html
