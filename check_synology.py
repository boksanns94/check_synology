#!/usr/bin/env python3

import argparse
import sys
import math
import re
import easysnmp

AUTHOR = "Frederic Werner"
VERSION = "1.1.0"

parser = argparse.ArgumentParser()
parser.add_argument("-H", "--hostname", help="the hostname", type=str, required=True)
parser.add_argument("-u", "--security-username", help="the snmp user name", type=str, required=True)
parser.add_argument("-o", "--auth-protocol", help="the authentication protocol", default="MD5", choices=["MD5", "SHA"])
parser.add_argument("-a", "--auth-password", help="the authentication key", type=str, required=True)
parser.add_argument("-s", "--security-level", help="security level type", type=str, default="auth_with_privacy", choices=["auth_with_privacy", "auth_without_privacy", "no_auth_or_privacy"])
parser.add_argument("-e", "--privacy-protocol", help="SNMP privacy protocol encryption", type=str, default="AES128", choices=["AES128", "DES"])
parser.add_argument("-k", "--privacy-password", help="the privacy key", type=str, default="")
parser.add_argument("-m", "--mode", help="the mode", type=str, choices=["load", "memory", "disk", "storage", "update", "status"], required=True)
parser.add_argument("-w", "--warning", help="warning value for selected mode", type=int)
parser.add_argument("-c", "--critical", help="critical value for selected mode", type=int)
parser.add_argument("-p", "--remote-port", help="the snmp port", type=int, default=161)
parser.add_argument("-t", "--timeout", help="timeout for snmp connection", type=int, default=10)
parser.add_argument("-r", "--retries", help="retries for snmp connection if timeout occurs", type=int, default=3)
args = parser.parse_args()

hostname = args.hostname
user_name = args.security_username
auth_prot = args.auth_protocol
auth_key = args.auth_password
priv_protocol = args.privacy_protocol
priv_key = args.privacy_password
mode = args.mode
warning = args.warning
critical = args.critical
port = args.remote_port
snmp_timeout = args.timeout
snmp_retries = args.retries
sec_lvl = args.security_level

state = 'OK'


def exit_code():
    if state == 'OK':
        sys.exit(0)
    if state == 'WARNING':
        sys.exit(1)
    if state == 'CRITICAL':
        sys.exit(2)
    if state == 'UNKNOWN':
        sys.exit(3)


def croak(message=None):
    """
    Exit program with `UNKNOWN` state and error message.
    """
    global state
    state = 'UNKNOWN'
    message = message and str(message) or "unknown error"
    print(f"{state} - {message}")
    exit_code()


def snmp_get(oid):
    """
    Return value from single OID.
    """
    try:
        res = session.get(oid)
        return res.value
    except Exception as err:
        croak(err)


def snmp_walk(oid):
    """
    Walk the given OID and return all child OIDs as a list of tuples of OID and value.
    """
    res = []
    try:
        res = session.walk(oid)
    except Exception as err:
        croak(err)
    return res


try:
    session = easysnmp.Session(
        hostname=hostname,
        remote_port=port,
        version=3,
        timeout=snmp_timeout,
        retries=snmp_retries,
        security_level=sec_lvl,
        security_username=user_name,
        auth_password=auth_key,
        auth_protocol=auth_prot,
        privacy_password=priv_key,
        privacy_protocol=priv_protocol
    )
except Exception as e:
    croak(e)

if mode == 'load':
    load1 = str(float(snmp_get('1.3.6.1.4.1.2021.10.1.5.1')) / 100)
    load5 = str(float(snmp_get('1.3.6.1.4.1.2021.10.1.5.2')) / 100)
    load15 = str(float(snmp_get('1.3.6.1.4.1.2021.10.1.5.3')) / 100)

    if warning and warning < int(math.ceil(float(load1))):
        state = 'WARNING'
    if critical and critical < int(math.ceil(float(load1))):
        state = 'CRITICAL'

    print(f"{state} - load average: {load1}, {load5}, {load15} | load1={load1}c load5={load5}c load15={load15}c")
    exit_code()

if mode == 'memory':
    memory_total = float(snmp_get('1.3.6.1.4.1.2021.4.5.0'))
    memory_unused = float(snmp_get('1.3.6.1.4.1.2021.4.6.0'))
    memory_cached = float(snmp_get('1.3.6.1.4.1.2021.4.15.0'))
    memory_usable = memory_unused + memory_cached
    memory_percent = 100 / memory_total * memory_usable

    if warning and warning > int(memory_percent):
        state = 'WARNING'
    if critical and critical > int(memory_percent):
        state = 'CRITICAL'

    print(f"{state} - {memory_percent:.1f}% usable ({memory_unused/1024:.1f} MB free "
          f"and {memory_cached/1024:.1f} MB cached out of {memory_total/1024:.1f} MB) "
          f"| memory_total={memory_total}c memory_unused={memory_unused}c memory_cached={memory_cached}c "
          f"memory_usable={memory_usable}c memory_percent={memory_percent}c%")
    exit_code()

if mode == 'disk':
    """
    Synology Disk MIB (OID: .1.3.6.1.4.1.6574.2)

    OK:       Status from all disks is "Normal" and no temperature threshold is raised.
    WARNING:  Temperature threshold for warning level is reached on any disk.
    CRITICAL: Either the status from any disk is "SystemPartitionFailed" or "Crashed",
              or the temperature threshold for criticality level is reached on any disk.
    UNKNOWN:  No disk states collected via SNMP at all.
    """

    # 1. Retrieve and decode system metrics.
    maxDisk = 0
    states = []
    output = ''
    perf_data = '|'
    for item in snmp_walk('1.3.6.1.4.1.6574.2.1.1.2'):
        i = item.oid_index or item.oid.split('.')[-1]
        disk_name = item.value
        disk_status_nr = snmp_get('1.3.6.1.4.1.6574.2.1.1.5.' + str(i))
        disk_health_status_nr = snmp_get('1.3.6.1.4.1.6574.2.1.1.13.' + str(i))
        disk_temp = snmp_get('1.3.6.1.4.1.6574.2.1.1.6.' + str(i))
        status_translation = {
            '1': "Normal",
            '2': "Initialized",
            '3': "NotInitialized",
            '4': "SystemPartitionFailed",
            '5': "Crashed"
        }
        health_status_translation = {
            '1': "Normal",
            '2': "Warning",
            '3': "Critical",
            '4': "Failing"
        }
        disk_status = status_translation.get(disk_status_nr)
        disk_health_status = health_status_translation.get(disk_health_status_nr)
        disk_name = disk_name.replace(" ", "")

        # 2. Compute textual and perfdata output.
        output += f" - {disk_name}: Status: {disk_status}, Temperature: {disk_temp} C, Health status: {disk_health_status}"
        perf_data += f"temperature {disk_name}={disk_temp}c "

        # 3. Collect outcome for individual sensor state.

        # When state is already "CRITICAL", it can't get worse.
        if 'CRITICAL' in states:
            continue

        # 3.a Evaluate list of disk status flag.
        if disk_status in ["Normal"]:
            states.append('OK')
        elif disk_status in ["SystemPartitionFailed", "Crashed"]:
            states.append('CRITICAL')

        # 3.b Evaluate disk temperature thresholds.
        if warning and warning < int(disk_temp):
            states.append('WARNING')
        if critical and critical < int(disk_temp):
            states.append('CRITICAL')

        # 3.c Evaluate list of disk health status flag.
        if disk_health_status in ["Normal"]:
            states.append('OK')
        elif disk_health_status in ["Warning"]:
            states.append('WARNING')
        elif disk_health_status in ["Critical", "Failing"]:
            states.append('CRITICAL')

    # 4. Compute outcome for overall sensor state.
    state = 'UNKNOWN'
    priorities = ['CRITICAL', 'WARNING', 'UNKNOWN', 'OK']
    for priority in priorities:
        if priority in states:
            state = priority
            break

    # 5. Respond with textual and perfdata output and propagate exit code.
    print(f"{state}{output} {perf_data}")
    exit_code()

if mode == 'storage':
    output = ''
    perf_data = '|'
    for item in snmp_walk('1.3.6.1.2.1.25.2.3.1.3'):
        i = item.oid_index or item.oid.split('.')[-1]
        storage_name = item.value
        if re.match("/volume(?!.+/@docker.*)", storage_name):
            allocation_units = snmp_get('1.3.6.1.2.1.25.2.3.1.4.' + str(i))
            size = snmp_get('1.3.6.1.2.1.25.2.3.1.5.' + str(i))
            used = snmp_get('1.3.6.1.2.1.25.2.3.1.6.' + str(i))

            storage_size = int((int(allocation_units) * int(size)) / 1000000000)
            storage_used = int((int(used) * int(allocation_units)) / 1000000000)
            storage_free = int(storage_size - storage_used)

            # some virtual volume have size zero
            if storage_size == 0:
                continue

            storage_used_percent = int(storage_used * 100 / storage_size)

            if warning and warning < int(storage_used_percent):
                if state != 'CRITICAL':
                    state = 'WARNING'
            if critical and critical < int(storage_used_percent):
                state = 'CRITICAL'

            output += f" - free space: {storage_name} {storage_free} GB ({storage_used} GB of {storage_size} GB used, {storage_used_percent}%)"
            perf_data += f"{storage_name}={storage_used}c "
    print(f"{state}{output} {perf_data}")
    exit_code()

if mode == 'update':
    update_status_nr = snmp_get('1.3.6.1.4.1.6574.1.5.4.0')
    update_dsm_version = snmp_get('1.3.6.1.4.1.6574.1.5.3.0')
    status_translation = {
            '1': "Available",
            '2': "Unavailable",
            '3': "Connecting",
            '4': "Disconnected",
            '5': "Others"
        }
    state_translation = {
        '2': 'OK',
        '1': 'WARNING',
    }

    update_status = status_translation.get(update_status_nr)
    state = state_translation.get(update_status_nr, "UNKNOWN")

    print(f"{state} - DSM Version: {update_dsm_version}, DSM Update: {update_status} | DSMupdate={update_status_nr}c")
    exit_code()

if mode == 'status':

    # 1. Retrieve and decode system metrics.
    status_model = snmp_get('1.3.6.1.4.1.6574.1.5.1.0')
    status_serial = snmp_get('1.3.6.1.4.1.6574.1.5.2.0')
    status_temperature = snmp_get('1.3.6.1.4.1.6574.1.2.0')

    status_system_nr = snmp_get('1.3.6.1.4.1.6574.1.1.0')
    status_system_fan_nr = snmp_get('1.3.6.1.4.1.6574.1.4.1.0')
    status_cpu_fan_nr = snmp_get('1.3.6.1.4.1.6574.1.4.2.0')
    status_power_nr = snmp_get('1.3.6.1.4.1.6574.1.3.0')

    status_translation = {
        '1': "Normal",
        '2': "Failed"
    }

    status_system = status_translation.get(status_system_nr)
    status_system_fan = status_translation.get(status_system_fan_nr)
    status_cpu_fan = status_translation.get(status_cpu_fan_nr)
    status_power = status_translation.get(status_power_nr)

    # 2. Compute outcome for overall sensor state.

    # 2.a Evaluate list of system status flags.
    status_all = [status_system, status_system_fan, status_cpu_fan, status_power]
    if all([status == "Normal" for status in status_all]):
        state = 'OK'
    elif any([status == "Failed" for status in status_all]):
        state = 'CRITICAL'
    else:
        state = 'UNKNOWN'

    # 2.b Evaluate system temperature thresholds.
    # When state is already "CRITICAL", it can't get worse.
    if state != 'CRITICAL':
        if warning and warning < int(status_temperature):
            state = 'WARNING'
        if critical and critical < int(status_temperature):
            state = 'CRITICAL'

    # 3. Respond with textual and perfdata output and propagate exit code.
    print(f"{state} - Model: {status_model}, S/N: {status_serial}, "
          f"System Temperature: {status_temperature} C, System Status: {status_system}, "
          f"System Fan: {status_system_fan}, CPU Fan: {status_cpu_fan}, "
          f"Powersupply : {status_power} | system_temp={status_temperature}c")
    exit_code()
