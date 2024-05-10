#!/usr/bin/env python3

import argparse
import sys
import re
import easysnmp

AUTHOR = "Frederic Werner"
VERSION = "1.1.0"

parser = argparse.ArgumentParser()
parser.add_argument("-H", "--hostname", help="the hostname",
                    type=str, required=True)
parser.add_argument("-u", "--security-username", help="the snmp user name",
                    type=str, required=True)
parser.add_argument("-o", "--auth-protocol", help="the authentication protocol",
                    type=str, default="MD5", choices=["MD5", "SHA"])
parser.add_argument("-a", "--auth-password", help="the authentication key",
                    type=str, required=True)
parser.add_argument("-s", "--security-level", help="security level type",
                    type=str, default="auth_with_privacy",
                    choices=["auth_with_privacy", "auth_without_privacy", "no_auth_or_privacy"])
parser.add_argument("-e", "--privacy-protocol", help="SNMP privacy protocol encryption",
                    type=str, default="AES128", choices=["AES128", "DES"])
parser.add_argument("-k", "--privacy-password", help="the privacy key",
                    type=str, default="")
parser.add_argument("-m", "--mode", help="the mode",
                    type=str, choices=["load", "memory", "disk", "storage", "update", "status"], required=True)
parser.add_argument("-w", "--warning", help="warning value for selected mode",
                    type=lambda value: int(value) if value.isdigit() else value)
parser.add_argument("-c", "--critical", help="critical value for selected mode",
                    type=lambda value: int(value) if value.isdigit() else value)
parser.add_argument("-p", "--remote-port", help="the snmp port",
                    type=int, default=161)
parser.add_argument("-t", "--timeout", help="timeout for snmp connection",
                    type=int, default=10)
parser.add_argument("-r", "--retries", help="retries for snmp connection if timeout occurs",
                    type=int, default=3)
parser.add_argument("-n", "--unit-of-measure", help="unit of measure for conversion",
                    type=str, default="")
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
uom = args.unit_of_measure

state_flag = 0
states_translation = {
    0: 'OK',
    1: 'WARNING',
    2: 'CRITICAL',
    3: 'UNKNOWN'
}

# The tuple contains the divisor for calculating the unit of measure in the 1st place
# and the number of decimal digits to print when formatting output
uom_divisors = {
    "TiB": (1099511627776, 1),
    "TB": (1000000000000, 1),
    "GiB": (1073741824, 1),
    "GB": (1000000000, 1),
    "MiB": (1048576, 2),
    "MB": (1000000, 2),
    "KiB": (1024, 0),
    "KB": (1000, 0)
}


def exit_code():
    """
    Send appropriate exit code when terminating program
    """
    global state_flag
    sys.exit(state_flag)


def croak(message=None):
    """
    Exit program with `UNKNOWN` state and error message.
    """
    global state_flag
    state_flag = 3
    message = message and str(message) or "unknown error"
    print(f"{state_translation[state_flag]} - {message}")
    exit_code()


def update_global_state(new_state_flag):
    """
    Update state_flag according to old and new value.
    The priority of statuses is as follows from most priority to least:
    Critical
    Warning
    Ok
    Unknown
    """
    global state_flag
    if state_flag == 3 and new_state_flag in [0, 1, 2]:
        state_flag = new_state_flag
    else:
        state_flag = max(state_flag, new_state_flag)


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
    load1 = float(snmp_get('1.3.6.1.4.1.2021.10.1.5.1')) / 100
    load5 = float(snmp_get('1.3.6.1.4.1.2021.10.1.5.2')) / 100
    load15 = float(snmp_get('1.3.6.1.4.1.2021.10.1.5.3')) / 100

    parse_state_arguments = lambda state_arg: ((state_arg,) * 3 if isinstance(state_arg, int)
                                                else tuple(int(el) for el in state_arg.split(","))
                                                if re.match(r"^\d+,\d+,\d+$", state_arg)
                                                else 0)

    (l1_w, l5_w, l15_w) = parse_state_arguments(warning)
    (l1_c, l5_c, l15_c) = parse_state_arguments(critical)

    if load1 > l1_c or load5 > l5_c or load15 > l15_c:
        state_flag = 2
    elif load1 > l1_w or load5 > l5_w or load15 > l15_w:
        state_flag = 1

    plugin_output = f"{states_translation[state_flag]} - load average: {load1}, {load5}, {load15}"
    perf_data = f"'load1'={load1};{l1_w};{l1_c} 'load5'={load5};{l5_w};{l5_c} 'load15'={load15};{l15_w};{l15_c}"

    print(f"{plugin_output} | {perf_data}")
    exit_code()

if mode == 'memory':
    if not uom:
        uom = "GiB"
    div, dd = uom_divisors.get(uom)

    memory_total = float(snmp_get('1.3.6.1.4.1.2021.4.5.0')) * 1000
    memory_unused = float(snmp_get('1.3.6.1.4.1.2021.4.6.0')) * 1000
    memory_cached = float(snmp_get('1.3.6.1.4.1.2021.4.15.0')) * 1000
    memory_usable = memory_unused + memory_cached
    memory_usable_percent = 100 / memory_total * memory_usable

    if critical and memory_usable_percent < critical:
        state_flag = 2
    elif warning and memory_usable_percent < warning:
        state_flag = 1

    plugin_output = (f"{states_translation[state_flag]} - "
                     f"{memory_usable_percent:.0f}% usable "
                     f"({memory_usable / div:.{dd}f}{uom} out of {memory_total / div:.{dd}f}{uom})")
    perf_data = (f"'usable memory [{uom}]'={memory_usable / div:.{dd}f};"
                 f"{(memory_total / 100 * warning) / div:.{dd}f};"
                 f"{(memory_total / 100 * critical) / div:.{dd}f};0;"
                 f"{memory_total / div:.{dd}f} "
                 f"'usable memory [%]'={memory_usable_percent:.0f};{warning:.0f};{critical:.0f};0;100")
    print(f"{plugin_output} | {perf_data}")
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
    output = ""
    perf_data = ""

    for item in snmp_walk('1.3.6.1.4.1.6574.2.1.1.2'):
        current_state_flag = [3]

        i = item.oid_index or item.oid.split('.')[-1]
        disk_name = item.value
        disk_status_nr = snmp_get('1.3.6.1.4.1.6574.2.1.1.5.' + str(i))
        disk_health_nr = snmp_get('1.3.6.1.4.1.6574.2.1.1.13.' + str(i))
        disk_temp = int(snmp_get('1.3.6.1.4.1.6574.2.1.1.6.' + str(i)))
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
        disk_status = status_translation[disk_status_nr]
        disk_health = health_status_translation[disk_health_nr]

        if disk_status in ["SystemPartitionFailed", "Crashed"]:
            current_state_flag.append(2)
        elif disk_status:
            current_state_flag.append(0)

        if critical and disk_temp > critical:
            current_state_flag.append(2)
        elif warning and disk_temp > warning:
            current_state_flag.append(1)
        elif disk_temp:
            current_state_flag.append(0)

        if disk_health in ["Critical", "Failing"]:
            current_state_flag.append(2)
        elif disk_health in ["Warning"]:
            current_state_flag.append(1)
        elif disk_health in ["Normal"]:
            current_state_flag.append(0)

        disk_state = states_translation[0]
        for s in [2, 1, 0, 3]:
            if s in current_state_flag:
                update_global_state(s)
                disk_state = states_translation[s]
                break
        output += (f"{disk_state} - {disk_name} - "
                   f"Status: {disk_status}, Temperature: {disk_temp}`C, Health: {disk_health}\n")
        perf_data += f"'{disk_name} temperature [`C]'={disk_temp};{warning};{critical};0;61 "

    print(f"{states_translation[state_flag]}\n{output} | {perf_data}")
    exit_code()

if mode == 'storage':
    if not uom:
        uom = "TiB"
    div, dd = uom_divisors.get(uom)

    output = ""
    perf_data = ""
    for item in snmp_walk('1.3.6.1.2.1.25.2.3.1.3'):
        i = item.oid_index or item.oid.split('.')[-1]
        storage_name = item.value
        if re.match("/volume(?!.+/@docker.*)", storage_name):
            allocation_units = int(snmp_get('1.3.6.1.2.1.25.2.3.1.4.' + str(i)))
            size = int(snmp_get('1.3.6.1.2.1.25.2.3.1.5.' + str(i)))
            used = int(snmp_get('1.3.6.1.2.1.25.2.3.1.6.' + str(i)))

            storage_size = size * allocation_units
            storage_used = used * allocation_units
            storage_free = storage_size - storage_used

            # some virtual volume have size zero
            if storage_size == 0:
                continue

            storage_free_percent = storage_free * 100 / storage_size

            if critical and storage_free_percent < critical:
                state_flag = 2
            elif warning and storage_free_percent < warning:
                state_flag = 1
            else:
                state_flag = 0

            update_global_state(state_flag)
            storage_state = states_translation[state_flag]

            output += (f"{storage_state} {storage_name} - "
                       f"free space: {storage_free / div:.{dd}f}{uom} of {storage_size / div:.{dd}f}{uom} free"
                       f" - {storage_free_percent:.0f}%\n")
            if perf_data:
                perf_data += ' '
            perf_data += (f"'{storage_name} [{uom}]'={storage_free / div:.{dd}f};"
                          f"{(storage_size / 100 * warning) / div:.{dd}f};"
                          f"{(storage_size / 100 * critical) / div:.{dd}f};0;"
                          f"{storage_size / div:.{dd}f} "
                          f"'{storage_name} [%]'={storage_free_percent:.0f}%;{warning};{critical};0;100")

    print(f"{states_translation[state_flag]}\n{output} | {perf_data}")
    exit_code()

if mode == 'update':
    update_status_nr = snmp_get('1.3.6.1.4.1.6574.1.5.4.0')
    update_dsm_version = snmp_get('1.3.6.1.4.1.6574.1.5.3.0')
    status_translation = {
        '1': "Available",
        '2': "Up to date",
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

    print(f"{state} - DSM Version: {update_dsm_version}, DSM Update: {update_status}")
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

    output = (f"{state} - Model: {status_model}, "
              f"S/N: {status_serial}, "
              f"System Temperature: {status_temperature}`C, "
              f"System Status: {status_system}, "
              f"System Fan: {status_system_fan}, "
              f"CPU Fan: {status_cpu_fan}, "
              f"PSU: {status_power}")
    perf_data = f"'System temperature [`C]'={status_temperature};{warning};{critical};0;105"

    print(f"{output} | {perf_data}")
    exit_code()
