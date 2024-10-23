#!/usr/bin/python3
from bcc import BPF
import socket
import os
from time import sleep
import sys
import ctypes


size_of_queue = 10
class MyStruct(ctypes.Structure):
    _fields_ = [("data", ctypes.c_int),
                ("prev", ctypes.c_int),("next", ctypes.c_int),("is_used",ctypes.c_uint8)]

b = BPF(src_file="kernel.c")
interface = "enp0s3"

double_linked = b.get_table("double_linked")
head_tail_size = b.get_table("head_tail_size")
for i in range(10):
    if(i==9):
        entry = MyStruct(data = i,prev = i-1,next = 0,is_used = 0)
    else:
        entry = MyStruct(data = i,prev = i-1,next = i+1,is_used = 0)
        
    double_linked[i] = entry
    

head_tail_size[0] = ctypes.c_int(1)
head_tail_size[1] = ctypes.c_int(size_of_queue - 1)
head_tail_size[2] = ctypes.c_int(0)

'''
zero = 0
initial_spinlock = b'\x00' * sizeof(bpf.spin_lock)
b.get_table("semaphore_for_map").update(zero, initial_spinlock)
'''
fx = b.load_func("xdp_tcp_syn", BPF.XDP)
BPF.attach_xdp(interface, fx, 0)

def detach_xdp():
    BPF.remove_xdp(interface)

try:
    b.trace_print()
except KeyboardInterrupt:
    detach_xdp()
    sys.exit(0)

detach_xdp()