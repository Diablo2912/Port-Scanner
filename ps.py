import socket
import threading
from queue import Queue

target = input(str("Target IP: "))
queue = Queue()
open_ports = []

port_choice = input("Scan port range from 1-1024 [1] or a specific port [2]: ")

def portscan(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target, port))
        return True
    except:
        return False

def fill_queue(port_list):
    for port in port_list:
        queue.put(port)

if port_choice == "1":
    port_list = range(1, 1025)
    fill_queue(port_list)

elif port_choice == "2":
    specific_port = int(input("Port: ")) #has to be int, as port is int
    fill_queue([specific_port])

def worker():
    while not queue.empty():
        port = queue.get()
        if portscan(port):
            print(f"Port {port} is open!")
            open_ports.append(port)

thread_list = []

for t in range(100):
    thread = threading.Thread(target=worker)
    thread_list.append(thread)

# Start all threads
for thread in thread_list:
    thread.start()

# Wait for all threads to finish
for thread in thread_list:
    thread.join()

# Print out the open ports at the end
print("\nOpen ports:", open_ports)
