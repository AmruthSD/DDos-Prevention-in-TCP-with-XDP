#!/usr/bin/python3
from bcc import BPF
import socket
import os
from time import sleep
import sys
import ctypes

b = BPF(src_file="kernel.c")
interface = "lo"


fx = b.load_func("xdp_tcp_rst", BPF.XDP)
BPF.attach_xdp(interface, fx, 0)

def detach_xdp():
    BPF.remove_xdp(interface)

try:
    b.trace_print()
except KeyboardInterrupt:
    detach_xdp()
    sys.exit(0)

detach_xdp()