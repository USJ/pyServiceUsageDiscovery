#!/usr/bin/env python
"""pyServiceUsageDiscovery.py: Discovers usage of host services based on incoming traffic analysis.


To run this script, just execute it using your python interpreter.
You will be asked to input your sudo password.
Leave the script running for a while (a few days), ideally in its own `screen`.
Press Ctrl-Z to output the current output without stopping the script.
Press Ctrl-C to abort the script and read its output.


This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.
This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses/>.
"""

__author__     = "Daniel Filipe Farinha"
__copyright__  = "Copyright 2019, University of Saint Joseph"
__license__    = "GPLv3"
__version__    = "1.0.2"

import subprocess as sub
import socket
import fcntl
import struct
import re
import socket
import signal
import sys
import operator
import pprint
import time

open_ports = []
clients_logged = {}
packets_processed = 0


print('This script requires running tcpdump as root, so you will be asked for your password for sudo.')

def signal_handler(sig, frame):
     print('\nInterrupt detected. Output:')

     sorted_hosts = sorted(clients_logged.items(), reverse=True, key=lambda kv: kv[1])

     pprint.pprint(sorted_hosts)

     if(sig is signal.SIGINT):
          print('Terminated.')
          sys.exit(0)
     

def process_proc_net_tcp_line(line):
    pattern = re.compile(r""".*: .*:(?P<port>.*?) .*:.* 0A.*""")
    match = pattern.match(line)

    if match:
          port_int = int(match.group("port"), 16)
          port = str(port_int)
          open_ports.append(port)
          

def process_host_port(line):
     pattern = re.compile(r"""(?P<ip>\d*\.\d*\.\d*\.\d*?)\.(?P<port>\d*?)$""")
     match = pattern.match(line)

     if match:
          ip = str(match.group("ip")).strip()
          port = str(match.group("port")).strip()
          return (ip, port)


def process_tcpdump_line(line):
    global packets_processed
    pattern = re.compile(r""".* IP (?P<src>.*?) > (?P<dst>.*?):.*""")
    match = pattern.match(line)

    if match:
          src = str(match.group("src")).strip()
          dst = str(match.group("dst")).strip()

          (src_ip, src_port) = process_host_port(src) or (None, None)
          (dst_ip, dst_port) = process_host_port(dst) or (None, None)

          if src_ip is not None and dst_port is not None:
               packets_processed += 1
               sys.stdout.write("Packets processed: %d  Press Ctrl+C to terminate and display output.\r" % (packets_processed) )
               sys.stdout.flush()

               if dst_port in open_ports:
                    key = src_ip + " -> " + dst_port

                    if key in clients_logged:
                         clients_logged[key] += 1
                    else:
                         clients_logged[key] = 1


# get host ip address
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
local_ip = s.getsockname()[0]
s.close()

# get open ports
p = sub.Popen(('cat', '/proc/net/tcp'), stdout=sub.PIPE)
for row in iter(p.stdout.readline, b''):
     process_proc_net_tcp_line(row.rstrip())

# print IP and ports
print("IP: " + local_ip)
print("Open ports: " + str(open_ports))

# register interrupt handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTSTP, signal_handler)


# prepare tcpdump command
dst = 'dst host ' + local_ip
p = sub.Popen(('sudo', 'tcpdump', '-nqnn', '-l', '-i', 'any', dst), stdout=sub.PIPE,
            preexec_fn = lambda: signal.signal(signal.SIGTSTP, signal.SIG_IGN))

for row in iter(p.stdout.readline, b''):
     process_tcpdump_line(row.rstrip())