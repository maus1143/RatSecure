import socket
import logging
import time
import threading

end = '\033[0m'
blue = '\033[94m'
green = '\033[92m'
white = '\033[97m'
yellow = '\033[93m'
debug_symbol = '\033[92m[</>]'

print(f"{white}Starting RatSecure...")

selected_ports_input = "all" # Setze auf "all" oder eine Liste von Ports wie "1000,1001,1002"
selected_ports = []

logging.basicConfig(filename="firewall_log.txt", level=logging.INFO, format="%(asctime)s %(message)s")

def monitor_network(port):
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('0.0.0.0', port))
        server_socket.listen(5)
        logging.info(f"Firewall is monitoring port {port}")
        if selected_ports_input is not all:
            return
        if selected_ports_input is not all:
            print(f"{white}RatSecure is monitoring port {yellow}{port}")
        while True:
            try:
                client_socket, address = server_socket.accept()
                logging.info(f"Connection attempt from {address} on port {port}")
                print(f"{blue} {debug_symbol} RatSecure{white}: Connection attempt from {yellow}{address} {white}on port {yellow}{port}")

                if is_suspicious(address[0]):
                    logging.warning(f"Suspicious activity detected from {address} on port {port}")
                    print(f"Suspicious activity detected from {address} on port {port}")
                    block_ip(address[0])
                    time.sleep(5) 
                else:
                    logging.info(f"Connection from {address} allowed on port {port}")
                    print(f"{blue} {debug_symbol} RatSecure{white}: Connection from {yellow}{address} {green}allowed {white}on port {yellow}{port}")
            except socket.error as e:
                logging.error(f"Error with client socket on port {port}: {e}")
                print(f"Error with client socket on port {port}: {e}")
    except socket.error as e:
        logging.error(f"Failed to bind socket on port {port}: {e}")
        print(f"Failed to bind socket on port {port}: {e}")
    except Exception as e:
        logging.error(f"Unexpected error on port {port}: {e}")
        print(f"Unexpected error on port {port}: {e}")

def block_ip(ip_address):
    logging.info(f"Blocking IP: {ip_address}")
    print(f"Blocking IP: {ip_address}")

def is_suspicious(ip_address):
    suspicious_ips = ["192.168.1.100", "10.0.0.2"]
    suspicious_ranges = [("192.168.0.", 255), ("10.0.0.", 255)]
    
    if ip_address in suspicious_ips:
        return True

    for base_ip, range_end in suspicious_ranges:
        for i in range(1, range_end + 1):
            if ip_address == f"{base_ip}{i}":
                return True
    return False

def get_ports():
    global selected_ports
    if selected_ports_input.lower() == "all":
        selected_ports = list(range(1, 65536))
    else:
        selected_ports = [int(port) for port in selected_ports_input.split(',') if port.isdigit()]

if __name__ == "__main__":
    try:
        get_ports()
        threads = []
        for port in selected_ports:
            thread = threading.Thread(target=monitor_network, args=(port,))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        logging.info("Firewall stopped by user")
        print("Firewall stopped by user")
    except Exception as e:
        logging.error(f"Critical error: {e}")
        print(f"Critical error: {e}")

#By Mausi Schmausi