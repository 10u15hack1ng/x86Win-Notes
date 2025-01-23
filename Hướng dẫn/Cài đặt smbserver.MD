Để cài smbserver ([Guide](https://github.com/fortra/impacket/issues/985#issuecomment-722449696)) 

1. Switch to root (sudo -s) if needed.  
2. Uninstall Kali's impacket version ( 0.9.21):  

```
apt-get remove python3-impacket
```

Note this will remove other packages that depend on impacket (e.g. patator, polenum, etc).  

3. Install python3-pip package:

```
apt-get install python3-pip
```


4. Clone impacket's sources:
```
cd /tmp
mkdir git-sources
cd git-sources
git clone https://github.com/SecureAuthCorp/impacket.git
```
    
5. Install dev version from source using pip3:
```
cd impacket
pip3 install . 
```
    
6. Test it!
```
root@kali2020-3:~# cd
root@kali2020-3:~# smbserver.py tmp /tmp
Impacket v0.9.22.dev1+20201105.115159.da48cfe7 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
