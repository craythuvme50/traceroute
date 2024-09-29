
import time
from datetime import datetime
import json
import sys
import os
import threading
import socket
import subprocess
import platform

# Function to check and install modules
def check_and_install(module):
    try:
        __import__(module)
    except ModuleNotFoundError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", module])
    finally:
        globals()[module] = __import__(module)

# List of required modules
modules = ['pika', 'scapy']

# Check and install each module
for module in modules:
    check_and_install(module)

# Import
from scapy.all import sr1, IP, ICMP, TCP, UDP, send

# Get hostname
def get_hostname():
    return socket.gethostname()

hostname = get_hostname()

# Check OS
def get_os_info():
    return platform.system()

os_name = get_os_info()

# Default configuration
default_config = {
    "numberOfDaysToRetainLogs": "30",
    "frequencyOfCheckingTraceRouteInMinutes": "1440",
    "maximum_msg_in_rmq": "10"
}

# Load configuration from file
def load_config(config_file, default_config):
    try:
        with open(config_file, 'r') as file:
            config = json.load(file)
        return config
    except FileNotFoundError:
        print(f"{config_file} not found. Creating config file with default settings.")
        with open(config_file, 'w') as new_file:
            json.dump(default_config, new_file, indent=4)
            os.chmod(config_file, 0o666)
        return default_config
    except json.JSONDecodeError:
        print("Error: Invalid JSON format in config file.")
        sys.exit(1)

config_file = "test_config.json"
config = load_config(config_file, default_config)

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

# Set days to retain logs
def set_days(config):
    try:
        days_of_checking = int(config.get('numberOfDaysToRetainLogs', 30))
        if days_of_checking < 1:
            raise ValueError("Days must be a positive integer.")
        return days_of_checking
    except ValueError as e:
        print("Error:", e)
        sys.exit(1)

days = set_days(config)

# Set maximum messages in RMQ
def set_maximum_msg_in_rmq(config):
    try:
        max_msgs = int(config.get('maximum_msg_in_rmq', 10))
        if max_msgs < 1:
            raise ValueError("Maximum messages must be a positive integer.")
        return max_msgs
    except ValueError as e:
        print("Error:", e)
        sys.exit(1)

maximum_msg_in_rmq = set_maximum_msg_in_rmq(config)

# Default destinations
default_destinations = [
    {"destination": "bql-sha-association01.asia.apple.com", "protocols": ["icmp", "udp"], "tcp_port": "80", "udp_port": "33434", "maximum_hop": "30"},
    {"destination": "bql-sha-ocvi01.asia.apple.com", "protocols": ["icmp", "udp", "tcp"], "tcp_port": "80", "udp_port": "33434", "maximum_hop": "30"}
]

# Load destinations from file
def load_destinations(destinations_file, default_destinations):
    try:
        with open(destinations_file, 'r') as file:
            destinations_content = json.load(file)
        return destinations_content
    except FileNotFoundError:
        print(f"{destinations_file} not found. Creating file.")
        with open(destinations_file, 'w') as new_file:
            json.dump(default_destinations, new_file, indent=4)
            os.chmod(destinations_file, 0o666)
        print("destinationHostnames file created, please add the destinations and options then run the script again.")
        sys.exit(1)
    except json.JSONDecodeError:
        print("Error: Invalid JSON format in destinationHostnames file.")
        sys.exit(1)

destinations_file = "destinationHostnames.json"
destinations_content = load_destinations(destinations_file, default_destinations)

# Check TCP Port
def check_tcp_port(tcp_port):
    try:
        if tcp_port < 1 or tcp_port > 65535:
            raise ValueError("TCP port range is 1-65535.")
        return tcp_port
    except ValueError as e:
        print("Error:", e)
        sys.exit(1)

# Check UDP Port
def check_udp_port(udp_port):
    try:
        if udp_port < 1 or udp_port > 65535:
            raise ValueError("UDP port range is 1-65535.")
        return udp_port
    except ValueError as e:
        print("Error:", e)
        sys.exit(1)

# Check protocol
def set_protocol(protocols_list, destinationhostname):
    # Allowed protocols
    allowed_protocols = {'icmp', 'udp', 'tcp'}
    try:
        if not set(protocols_list).issubset(allowed_protocols):
            print(f"Invalid protocols found for {destinationhostname}. Using only allowed protocols.")
            protocols_list = list(set(protocols_list) & allowed_protocols)
        return protocols_list
    except ValueError as e:
        print("Error:", e)
        sys.exit(1)

# Check maximum hop
def check_maximum_hop(maximum_hop):
    try:
        if maximum_hop < 1 or maximum_hop > 30:
            raise ValueError("Hop range is 1-30.")
        return maximum_hop
    except ValueError as e:
        print("Error:", e)
        sys.exit(1)

# Function to check information from file
def get_info_from_file(destinations_content):   
    destinations_info = []
    
    for destination in destinations_content:
        destinationhostname = destination.get('destination')
        protocols_list = destination.get('protocols', ['icmp'])
        tcp_port = destination.get('tcp_port', '80')
        udp_port = destination.get('udp_port', '33434')
        maximum_hop = destination.get('maximum_hop', '30')

        protocols_list = set_protocol(protocols_list, destinationhostname)
        tcp_port = check_tcp_port(int(tcp_port))
        udp_port = check_udp_port(int(udp_port))
        maximum_hop = check_maximum_hop(int(maximum_hop))

        destination_info = {
            'destination': destinationhostname,
            'protocols': protocols_list,
            'tcp_port': tcp_port,
            'udp_port': udp_port,
            'maximum_hop': maximum_hop
        }

        destinations_info.append(destination_info)
    
    return destinations_info

# Function to perform traceroute with ICMP
def icmp_traceroute(destination, maximum_hop):
    results = []
    for ttl in range(1, maximum_hop + 1):
        packet = IP(dst=destination, ttl=ttl) / ICMP()
        response = sr1(packet, timeout=1, verbose=0)
        if response is None:
            results.append((ttl, '*'))
        elif response.type == 0:  # Echo reply
            results.append((ttl, response.src))
            break
        else:
            results.append((ttl, response.src))
    return results

# Function to perform traceroute with UDP
def udp_traceroute(destination, udp_port, maximum_hop):
    results = []
    for ttl in range(1, maximum_hop + 1):
        packet = IP(dst=destination, ttl=ttl) / UDP(dport=udp_port)
        response = sr1(packet, timeout=1, verbose=0)
        if response is None:
            results.append((ttl, '*'))
        elif response.haslayer(ICMP) and response.getlayer(ICMP).type == 3:
            results.append((ttl, response.src))
            break
        else:
            results.append((ttl, response.src))
    return results

# Function to perform traceroute with TCP
def tcp_traceroute(destination, tcp_port, maximum_hop):
    results = []
    for ttl in range(1, maximum_hop + 1):
        packet = IP(dst=destination, ttl=ttl) / TCP(dport=tcp_port, flags='S')
        response = sr1(packet, timeout=1, verbose=0)
        if response is None:
            results.append((ttl, '*'))
        elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:  # SYN-ACK response
            results.append((ttl, response.src))
            send(IP(dst=destination) / TCP(dport=tcp_port, flags='R'), verbose=0)  # Send RST
            break
        else:
            results.append((ttl, response.src))
    return results

def send_msg_to_rmq(msg, destination, maximum_msg_in_rmq):
    # Set RMQ connection
    connection = pika.BlockingConnection(pika.ConnectionParameters('sa20d01nt-batterylapp001.ise.apple.com', 5672, '/', pika.PlainCredentials('traceroute_log', '6QXUyWh$=w-J_uezt4zm')))
    channel = connection.channel()

    # Declare a queue based on the destination
    queue_name = f'tr.{hostname}.{destination}'
    routing_key = f'tr.{hostname}.{destination}'

    channel.exchange_declare(exchange='traceroute', exchange_type='direct', durable=True)
    channel.queue_declare(queue=queue_name, arguments={'x-max-length': maximum_msg_in_rmq})
    channel.queue_bind(exchange='traceroute', queue=queue_name, routing_key=routing_key)

    channel.basic_publish(exchange='traceroute', routing_key=routing_key, body=msg)
    connection.close()

# Run the traceroute command in a loop and capture the output
def run_traceroute(os_name, frequency, hostname):
    while True:
        destinations_info = get_info_from_file(destinations_content)
        for info in destinations_info:
            try:
                destination_ip = socket.gethostbyname(info['destination'])  # Check if hostname can be resolved
                current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

                # Check folder
                if not os.path.exists(info['destination']):
                    os.makedirs(info['destination'], exist_ok=True)
                    print(f"Directory '{info['destination']}' created successfully.")
                else:
                    print(f"Directory '{info['destination']}' already exists.")
                
                filename = f"{info['destination']}/{current_datetime}.txt"
                # Execute traceroute command for each destination in the list based on platform
                if os_name == "Darwin":
                    all_results = []
                    for protocol in info['protocols']:
                        if protocol == 'udp':
                            current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                            result = subprocess.run(['traceroute', '-m', str(info['maximum_hop']), '-w', '1', "-q", "1", "-P", "udp", '-p', str(info['udp_port']), '-e', info['destination']], stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8', timeout=120)
                            result_body = f"{current_datetime} UDP Traceroute from {hostname} to {info['destination']}({destination_ip}) on port {info['udp_port']}:\n" + result.stdout
                            all_results.append(result_body + '\n\n')

                        elif protocol == 'tcp':
                            current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                            result = subprocess.run(['traceroute', '-m', str(info['maximum_hop']), '-w', '1', "-q", "1", "-P", "tcp", '-p', str(info['tcp_port']), '-e', info['destination']], stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8', timeout=120)
                            result_body = f"{current_datetime} TCP Traceroute from {hostname} to {info['destination']}({destination_ip}) on port {info['tcp_port']}:\n" + result.stdout
                            all_results.append(result_body + '\n\n')

                        elif protocol == 'icmp':
                            current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                            result = subprocess.run(['traceroute', '-m', str(info['maximum_hop']), '-w', '1', "-q", "1", "-P", "icmp", info['destination']], stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8', timeout=120)
                            result_body = f"{current_datetime} ICMP Traceroute from {hostname} to {info['destination']}({destination_ip}):\n" + result.stdout
                            all_results.append(result_body + '\n\n')

                    print(f"Traceroute to {info['destination']} completed. Result has been saved in {filename}")
                    
                    msg_body = ''.join(all_results)

                    with open(filename, 'a') as save_to_file:
                        save_to_file.write(msg_body)

                    # Send message to RMQ
                    #send_msg_to_rmq(msg_body, info['destination'], maximum_msg_in_rmq)

                elif os_name == "Linux":
                    all_results = []  
                    for protocol in info['protocols']:
                        if protocol == 'icmp':
                            current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                            result = subprocess.run(['traceroute', '-m', str(info['maximum_hop']), '-w', '1', "-q", "1", '--icmp', info['destination']], stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8', timeout=120)
                            result_header = f"{current_datetime} ICMP Traceroute from {hostname} to {info['destination']}({destination_ip}):\n"
                            all_results.append(result_header + result.stdout + '\n\n')

                        elif protocol == 'udp':
                            current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                            result = subprocess.run(['traceroute', '-m', str(info['maximum_hop']), '-w', '1', "-q", "1", '--udp', '-p', str(info['udp_port']), info['destination']], stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8', timeout=120)
                            result_header = f"{current_datetime} UDP Traceroute from {hostname} to {info['destination']}({destination_ip}) on port {info['udp_port']}:\n"
                            all_results.append(result_header + result.stdout + '\n\n')

                        elif protocol == 'tcp':
                            current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                            result = subprocess.run(['sudo', 'traceroute', '-m', str(info['maximum_hop']), '-w', '1', "-q", "1", '--tcp', '-p', str(info['tcp_port']), info['destination']], stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8', timeout=120)
                            result_header = f"{current_datetime} TCP Traceroute from {hostname} to {info['destination']}({destination_ip}) on port {info['tcp_port']}:\n"
                            all_results.append(result_header + result.stdout + '\n\n')

                    print(f"Traceroute to {info['destination']} completed. Result has been saved in {filename}")

                    msg_body = ''.join(all_results)

                    with open(filename, 'a') as save_to_file:
                        save_to_file.write(msg_body)

                    # Send message to RMQ
                    #send_msg_to_rmq(msg_body, info['destination'], maximum_msg_in_rmq)

                elif os_name == "Windows":
                    all_results = []  # List to accumulate result strings
                    for protocol in info['protocols']:
                        if protocol == 'icmp':
                            result = icmp_traceroute(info['destination'], maximum_hop=int(info['maximum_hop']))
                            current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                            result_header = f"{current_datetime} ICMP Traceroute from {hostname} to {info['destination']}({destination_ip}):\n"
                            all_results.append(result_header)
                            for ttl, hop in result:
                                all_results.append(f'{ttl}  {hop}\n')
                            all_results.append(f'\n\n')

                        elif protocol == 'udp':
                            result = udp_traceroute(info['destination'], maximum_hop=int(info['maximum_hop']), udp_port=int(info['udp_port']))
                            current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                            result_header = f"{current_datetime} UDP Traceroute from {hostname} to {info['destination']}({destination_ip}) on port {info['udp_port']}:\n"
                            all_results.append(result_header)
                            for ttl, hop in result:
                                all_results.append(f'{ttl}  {hop}\n')
                            all_results.append(f'\n\n')

                        elif protocol == 'tcp':
                            result = tcp_traceroute(info['destination'], maximum_hop=int(info['maximum_hop']), tcp_port=int(info['tcp_port']))
                            current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                            result_header = f"{current_datetime} TCP Traceroute from {hostname} to {info['destination']}({destination_ip}) on port {info['tcp_port']}:\n"
                            all_results.append(result_header)
                            for ttl, hop in result:
                                all_results.append(f'{ttl}  {hop}\n')
                            all_results.append(f'\n\n')

                    # Join all results into one string
                    msg_body = ''.join(all_results)

                    # Save results to file
                    with open(filename, 'a') as save_to_file:
                        save_to_file.write(msg_body)

                    print(f"Traceroute to {info['destination']} completed. Result has been saved in {filename}")

                    # Send message to RMQ (assuming you have a function for this)
                    #send_msg_to_rmq(msg_body, info['destination'], maximum_msg_in_rmq)

            except socket.gaierror:
                print(f"Error: Unable to resolve hostname {info['destination']}. Skipping to next destination.")
                continue   

        time.sleep(frequency)

# Delete old logs
def delete_files_created_specific_days_ago(destinations, days, frequency):
    while True:
        for destination in destinations:
            current_date = datetime.now()
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
    # Define the parameters for log deletion
    destinations = [info['destination'] for info in get_info_from_file(destinations_content)]

    # Create threads to run different tasks
    thread1 = threading.Thread(target=run_traceroute, args=(os_name, frequency, hostname))
    thread2 = threading.Thread(target=delete_files_created_specific_days_ago, args=(destinations, days, frequency))

    # Start all threads
    thread1.start()
    thread2.start()