import socket
import logging
import time
import threading
import time
import os

end = '\033[0m'
red = '\033[91m'
blue = '\033[94m'
green = '\033[92m'
white = '\033[97m'
dgreen = '\033[32m'
yellow = '\033[93m'
back = '\033[7;91m'

run = '\033[97m[~]\033[0m'
que = '\033[94m[?]\033[0m'
bad = '\033[91m[!]\033[0m '
info = '\033[93m[i]\033[0m'
debug_symbol = '\033[92m[</>]\033[0m'
good = '\033[92m[🗸]\033[0m'
not_loadet = '\033[91m[✗]\033[0m'
loadet = '\033[92m[🗸]\033[0m'

purple = '\033[95m'
cyan = '\033[96m'
orange = '\033[33m'
brown = '\033[38;5;94m'
pink = '\033[38;5;213m'
light_red = '\033[91m'
light_green = '\033[92m'
light_yellow = '\033[93m'
light_blue = '\033[94m'
light_cyan = '\033[96m'
light_purple = '\033[95m'

bg_black = '\033[40m'
bg_red = '\033[41m'
bg_green = '\033[42m'
bg_yellow = '\033[43m'
bg_blue = '\033[44m'
bg_magenta = '\033[45m'
bg_cyan = '\033[46m'
bg_white = '\033[47m'

bold = '\033[1m'
underline = '\033[4m'
blink = '\033[5m'
reverse = '\033[7m'
hidden = '\033[8m'
strikethrough = '\033[9m'

RatColorsVersion = "0.0.3"

display_load_status = True

def load_status(color_name):
    if display_load_status:
        print(f"{debug_symbol} {white}RatColors:{end} {color_name}{white} erfolgreich geladen{end}")
        time.sleep(0.01)

load_status(f"{red}Rot{end}")
load_status(f"{blue}Blau{end}")
load_status(f"{green}Grün{end}")
load_status(f"{white}Weiß{end}")
load_status(f"{dgreen}Dunkelgrün{end}")
load_status(f"{yellow}Gelb{end}")
load_status(f"{back}Hintergrund Rot{end}")
load_status(f"{purple}Lila{end}")
load_status(f"{cyan}Cyan{end}")
load_status(f"{orange}Orange{end}")
load_status(f"{brown}Braun{end}")
load_status(f"{pink}Rosa{end}")
load_status(f"{light_red}Hellrot{end}")
load_status(f"{light_green}Hellgrün{end}")
load_status(f"{light_yellow}Hellgelb{end}")
load_status(f"{light_blue}Hellblau{end}")
load_status(f"{light_cyan}Hellcyan{end}")
load_status(f"{light_purple}Helltürkis{end}")

load_status(f"{bg_black}{white}Hintergrund Schwarz{end}")
load_status(f"{bg_red}Hintergrund Rot{end}")
load_status(f"{bg_green}Hintergrund Grün{end}")
load_status(f"{bg_yellow}Hintergrund Gelb{end}")
load_status(f"{bg_blue}Hintergrund Blau{end}")
load_status(f"{bg_magenta}Hintergrund Magenta{end}")
load_status(f"{bg_cyan}Hintergrund Cyan{end}")
load_status(f"{bg_white}Hintergrund Weiß{end}")

load_status(f"{white}{bold}Fett{end}")
load_status(f"{white}{underline}Unterstrichen{end}")
load_status(f"{white}{blink}Blinkend{end}")
load_status(f"{white}{reverse}Umgekehrt{end}")
load_status(f"{hidden}Versteckt{end}")
load_status(f"{white}{strikethrough}Durchgestrichen{end}")

load_status(run + f" {yellow}Run-Symbol")
load_status(que + f" {yellow}Frage-Symbol")
load_status(bad + f" {yellow}Fehler-Symbol")
load_status(info + f" {yellow}Info-Symbol")
load_status(debug_symbol + f" {yellow}Debug-Symbol")
load_status(good + f" {yellow}Bestätigt-Symbol")
load_status(not_loadet + f" {yellow}Nicht geladen-Symbol")
load_status(loadet + f" {yellow}Geladen-Symbol")

print(f"{debug_symbol} {white}RatColors Version: {yellow}{RatColorsVersion}{white}")
time.sleep(1.3)
os.system("cls")


print(f"{white}Starting RatSecure...")
time.sleep(1)
print(f"{white}RatSecure Startet")
time.sleep(0.5)

selected_ports_input = "8080,5050,3000" 
selected_ports = []

logging.basicConfig(filename="RatSecure_log.txt", level=logging.INFO, format="%(asctime)s %(message)s")

def monitor_network(port):
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('0.0.0.0', port))
        server_socket.listen(5)
        logging.info(f"Firewall is monitoring port {port}")

        if selected_ports_input.lower() != "all":
            print(f"{white}RatSecure is monitoring port {yellow}{port}")
        
        while True:
            try:
                client_socket, address = server_socket.accept()
                logging.info(f"Connection attempt from {address} on port {port}")
                print(f"{green}{debug_symbol} {light_cyan}RatSecure{white}: Connection attempt from {yellow}{address} {white}on port {yellow}{port}")

                if is_suspicious(address[0]):
                    logging.warning(f"Suspicious activity detected from {address} on port {port}")
                    print(f"{red}{bad}{bold}{underline}Suspicious activity detected{end} {white}from {yellow}{underline}{address}{end}{white} on port {yellow}{port}")
                    block_ip(address[0])
                    time.sleep(5) 
                else:
                    logging.info(f"Connection from {address} allowed on port {port}")
                    print(f"{debug_symbol} {light_green} RatSecure{white}: Connection from {yellow}{address} {green}allowed {white}on port {yellow}{port}")
            except socket.error as e:
                logging.error(f"Error with client socket on port {port}: {e}")
                print(f"{red}{bad}{white}Error with client socket on port {end}{yellow}{port}{white}:{end}{red} {e}{end}")
    except socket.error as e:
        logging.error(f"Failed to bind socket on port {port}: {e}")
        print(f"{red}{bad}{white}Failed to bind socket on port {end}{yellow}{port}{white}:{end}{red} {e}{end}")
    except Exception as e:
        logging.error(f"Unexpected error on port {port}: {e}")
        print(f"{red}{bad}{white}Unexpected error on port {end}{yellow}{port}{white}:{end}{red} {e}{end}")

def block_ip(ip_address):
    logging.info(f"Blocking IP: {ip_address}")
    print(f"{red}{bad}{bold}{underline}Blocking IP:{end} {yellow}{ip_address}")

def is_suspicious(ip_address):
    suspicious_ips = ["192.168.1.100", "10.0.0.2", "127.0.0.1", "142.251.36.195"]
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
        selected_ports = [int(port) for port in selected_ports_input.split(',') if port.isdigit() and 1 <= int(port) <= 65535]

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
        time.sleep(5)
    except Exception as e:
        logging.error(f"Critical error: {e}")
        print(f"{red}{bad}{bold}{underline}Critical error:{end}{yellow} {e}")
        time.sleep(5)

#By Mausi Schmausi
