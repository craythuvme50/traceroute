#!/usr/bin/python3

import subprocess
import time
from datetime import datetime
import json
import sys
import os
import threading
import platform
import socket
import importlib

# Check OS
def get_os_info():
    return platform.system()

os_name = get_os_info()

# Check module
def install_and_import(module):
    try:
        importlib.import_module(module)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", module])
    finally:
        globals()[module] = importlib.import_module(module)

install_and_import('pika')

# Check config file
default_config = {
    "numberOfDaysToRetainLogs": "30",
    "frequencyOfCheckingTraceRouteInMinutes": "1440",
    "port": "33434",
    "Maximumhop": "25",
    "protocol": "icmp",
    "maximum_msg_in_rmq": "100"
}

def load_config(config_file):
    try:
        with open(config_file, 'r') as config_file:
            config = json.load(config_file)
        return config
    except FileNotFoundError:
        print(f"{config_file} not found. Creating config file with default settings.")
        with open(config_file, 'w') as new_config_file:
            json.dump(default_config, new_config_file, indent=4)
            os.chmod(config_file, 0o666)
            return default_config
    except json.JSONDecodeError:
        print("Error: Invalid JSON format in config file.")
        sys.exit(1)

config_file = "config.json"
config = load_config(config_file)

# Read hostnames
def read_hostnames_from_file(destinationHostnames):
    # Check if the file exists
    if not os.path.exists(destinationHostnames):
        print(f"{destinationHostnames} not found. Creating an empty file.")
        with open(destinationHostnames, 'w') as d:
            d.write("")  # Create an empty file
            os.chmod(destinationHostnames, 0o666)
        print("Empty file has been created. Please put your destination in this file and run this script again.")
        sys.exit(1)
    # Check if the file is empty
    elif os.stat(destinationHostnames).st_size == 0:
        print(f"{destinationHostnames} is empty. No hostnames to process. Please put your destination in this file and run this script again.")
        sys.exit(1)
    # Read hostnames from file
    with open(destinationHostnames, 'r') as f:
        destinations = [line.strip() for line in f]
    return destinations

destinationHostnames = "destinationHostnames"
destinations = read_hostnames_from_file(destinationHostnames)

# Set frequency
def set_frequency(config):
    try:
        frequency_of_checking = int(config.get('frequencyOfCheckingTraceRouteInMinutes', 1440))
        if frequency_of_checking < 1:
            raise ValueError("Frequency of checking must be a positive integer.")
        return frequency_of_checking * 60  # Convert minutes to seconds
    except ValueError as e:
        print("Error:", e)
        sys.exit(1)

frequency = set_frequency(config)

# Set maximum hop
def set_maximum_hop(config):
    try:
        maximum_hop = int(config.get('Maximumhop', 25))
        if maximum_hop < 1 or maximum_hop > 30:
            raise ValueError("Hop range is 1-30.")
        return maximum_hop
    except ValueError as e:
        print("Error:", e)
        sys.exit(1)

maximum_hop = str(set_maximum_hop(config))

# Set Port
def set_port(config):
    try:
        port_of_checking = int(config.get('port', 33434))
        if port_of_checking < 1 or port_of_checking > 65535:
            raise ValueError("Port range is 1-65535.")
        return str(port_of_checking)
    except ValueError as e:
        print("Error:", e)
        sys.exit(1)

port = str(set_port(config))

# Set protocol
def set_protocol(config):
    try:
        protocol = config.get('protocol', "icmp")
        if protocol not in ["icmp", "tcp", "udp"]:
            raise ValueError("Protocol must be 'icmp', 'tcp', or 'udp'.")
        return protocol    
    except ValueError as e:
        print("Error:", e)
        sys.exit(1)

protocol = str(set_protocol(config))
rhel_protocol = f"--{protocol}"

# Set Days of retain logs
def set_days(config):
    try:
        days_of_checking = int(config.get('numberOfDaysToRetainLogs', 30))
        if days_of_checking < 1:
            raise ValueError("Days must be positive integer.")
        return days_of_checking
    except ValueError as e:
        print("Error:", e)
        sys.exit(1)

days = set_days(config)

# Set Max logs in RMQ
def set_maximum_msg_in_rmq(config):
    try:
        days_of_checking = int(config.get('maximum_msg_in_rmq', 100))
        if days_of_checking < 1:
            raise ValueError("Days must be positive integer.")
        return days_of_checking
    except ValueError as e:
        print("Error:", e)
        sys.exit(1)

maximum_msg_in_rmq = set_maximum_msg_in_rmq(config)

# Get hostname
def get_hostname():
    return socket.gethostname()

hostname = get_hostname()

# Set RMQ connection
connection = pika.BlockingConnection(pika.ConnectionParameters('192.168.50.9', 5672, '/', pika.PlainCredentials('traceroute_log', '+|wjhWFksmHIoPTq<<>J')))
channel = connection.channel()

channel.exchange_declare(exchange='traceroute.exchange', exchange_type='direct')
channel.queue_declare(queue='traceroute.queue', arguments={'x-max-length': maximum_msg_in_rmq})
channel.queue_bind(exchange='traceroute.exchange', queue='traceroute.queue', routing_key='traceroute.routing_key')

# Run the traceroute command in a loop and capture the output
def run_traceroute(os_name, destinations, maximum_hop, protocol, port, frequency, channel, hostname):
    while True:
        for dst_list in destinations:
            # Execute traceroute command for each destination in the list based on platform
            if os_name == "Darwin":
                try:
                    current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                    result = subprocess.run(['traceroute', '-m', maximum_hop, '-w', '1', "-q", "1", "-P", protocol, "-p", port, "-e", dst_list], capture_output=True, text=True, timeout=120)

                    if result.returncode == 2:
                        print(result.stderr)

                    elif result.returncode == 0:
                        if not os.path.exists(dst_list):
                            os.makedirs(dst_list, exist_ok=True)
                            print(f"Directory '{dst_list}' created successfully.")
                        else:
                            print(f"Directory '{dst_list}' already exists.")

                        filename = f"{dst_list}/{current_datetime}"

                        # Add datime and destination at first line
                        msg = f"{current_datetime} from {hostname} traceroute to {dst_list}:\n" + result.stdout

                        # Write the entire output to the file
                        with open(filename, 'a') as save_to_file:
                            save_to_file.write(result.stdout)
                            save_to_file.write('\n\n')    # Add newline characters to separate outputs
                            print(f"Traceroute to {dst_list} completed. Result has been saved in {filename}")

                        # Send output to RMQ
                        channel.basic_publish(exchange='traceroute.exchange', routing_key='traceroute.routing_key', body=msg)

                    else:
                        print("Traceroute command failed with exit code:", result.returncode)
                        print("Error:", result.stderr)

                except subprocess.TimeoutExpired:
                    # Write the partial output to the file before continuing
                    with open(filename, 'a') as save_to_file:
                        save_to_file.write(f"{current_datetime} from {hostname} traceroute to {dst_list} (partial output):\n")
                        save_to_file.write(result.stdout)  # Write the partial output
                        save_to_file.write('\n\n')         # Add newline characters to separate outputs
                        print("Traceroute command timed out for destination:", dst_list)

                    # Send output to RMQ
                    channel.basic_publish(exchange='traceroute.exchange', routing_key='traceroute.routing_key', body=msg) 

            elif os_name == "Windows":
                try:
                    current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                    result = subprocess.run(['tracert', '-h', maximum_hop, '-w', '500', "-d", dst_list], capture_output=True, text=True, timeout=120)

                    if result.returncode == 1:
                        print(result.stdout)

                    elif result.returncode == 0:
                        if not os.path.exists(dst_list):
                            os.makedirs(dst_list, exist_ok=True)
                            print(f"Directory '{dst_list}' created successfully.")
                        else:
                            print(f"Directory '{dst_list}' already exists.")

                        filename = f"{dst_list}/{current_datetime}"

                        # Add datime and destination at first line
                        msg = f"{current_datetime} from {hostname} traceroute to {dst_list}:\n" + result.stdout

                        # Write the entire output to the file
                        with open(filename, 'a') as save_to_file:
                            save_to_file.write(result.stdout)
                            save_to_file.write('\n\n')    # Add newline characters to separate outputs
                            print(f"Traceroute to {dst_list} completed. Result has been saved in {filename}")

                        # Send output to RMQ
                        channel.basic_publish(exchange='traceroute.exchange', routing_key='traceroute.routing_key', body=msg)

                    else:
                        print("Traceroute command failed with exit code:", result.returncode)
                        print("Error:", result.stderr)

                except subprocess.TimeoutExpired:
                    # Write the partial output to the file before continuing
                    with open(filename, 'a') as save_to_file:
                        save_to_file.write(f"{current_datetime} from {hostname} traceroute to {dst_list} (partial output):\n")
                        save_to_file.write(result.stdout)  # Write the partial output
                        save_to_file.write('\n\n')         # Add newline characters to separate outputs
                        print("Traceroute command timed out for destination:", dst_list)
                    
                    # Send output to RMQ
                    channel.basic_publish(exchange='traceroute.exchange', routing_key='traceroute.routing_key', body=msg) 

            elif os_name == "Linux":
                try:
                    current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                    result = subprocess.run(['traceroute', '-m', maximum_hop, '-w', '1', "-d", rhel_protocol, "-p", port, dst_list], capture_output=True, text=True, timeout=120)

                    # Check if the command executed successfully
                    if result.returncode == 2:
                        print(result.stderr)

                    elif result.returncode == 0:
                        if not os.path.exists(dst_list):
                            os.makedirs(dst_list, exist_ok=True)
                            print(f"Directory '{dst_list}' created successfully.")
                        else:
                            print(f"Directory '{dst_list}' already exists.")

                        filename = f"{dst_list}/{current_datetime}"

                        # Add datime and destination at first line
                        msg = f"{current_datetime} from {hostname} traceroute to {dst_list}:\n" + result.stdout

                        # Write the entire output to the file
                        with open(filename, 'a') as save_to_file:
                            save_to_file.write(result.stdout)
                            save_to_file.write('\n\n')    # Add newline characters to separate outputs
                            print(f"Traceroute to {dst_list} completed. Result has been saved in {filename}")

                        # Send output to RMQ
                        channel.basic_publish(exchange='traceroute.exchange', routing_key='traceroute.routing_key', body=msg)

                    else:
                        print("Traceroute command failed with exit code:", result.returncode)
                        print("Error:", result.stderr)

                except subprocess.TimeoutExpired:
                    # Write the partial output to the file before continuing
                    with open(filename, 'a') as save_to_file:
                        save_to_file.write(f"{current_datetime} from {hostname} traceroute to {dst_list} (partial output):\n")
                        save_to_file.write(result.stdout)  # Write the partial output
                        save_to_file.write('\n\n')         # Add newline characters to separate outputs
                    print("Traceroute command timed out for destination:", dst_list)
                    
                    # Send output to RMQ
                    channel.basic_publish(exchange='traceroute.exchange', routing_key='traceroute.routing_key', body=msg) 

        time.sleep(frequency)

# Delete old logs
def delete_files_created_specific_days_ago(destinations, days, frequency):
    while True:
        current_date = datetime.now()
        for destination in destinations:
            directory_path = os.path.join(os.getcwd(), destination)

            if os.path.exists(directory_path):
                for root, dirs, files in os.walk(directory_path):
                    for filename in files:
                        filepath = os.path.join(root, filename)
                        creation_time = datetime.fromtimestamp(os.path.getctime(filepath))
                        days_difference = (current_date - creation_time).days
                        
                        if days_difference >= days:
                            try:
                                os.remove(filepath)
                                print(f"Deleted file: {filepath}")
                            except Exception as e:
                                print(f"Error deleting file {filepath}: {e}")

        time.sleep(frequency)

if __name__ == '__main__':
    # Create 2 threads to run different tasks
    thread1 = threading.Thread(target=run_traceroute, args=(os_name, destinations, maximum_hop, protocol, port, frequency, channel, hostname))
    thread2 = threading.Thread(target=delete_files_created_specific_days_ago, args=(destinations, days, frequency))

    # Start all threads
    thread1.start()
    thread2.start()
