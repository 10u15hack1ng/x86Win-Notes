# XÂY DỰNG ROP CHAIN

## Xây dựng stack mẫu
VirtualAlloc:
```
functionAddress = b"AAAA"       # VirtualAllocStub address
shellcodeAddress = b"BBBB"      # Shellcode address
param1 = b"CCCC"                # lpAddress             # shellcode address
param2 = b"DDDD"                # dwSize
param3 = b"EEEE"                # flAllocationType
param4 = b"FFFF"                # flProtect
```
WriteProcessMemory (Tham khảo: https://connormcgarr.github.io/ROP2/)
```
functionAddress = b"AAAA"     # WriteProcessMemory address
shellcodeAddress = b"BBBB"    # shellcode RET address     # Vị trí của vùng code cave tìm ở B5.2
param1 = b"CCCC"              # hProcess                  # Đặt giá trị là -1 tượng trưng cho process hiện tại
param2 = b"DDDD"              # lpBaseAddress             # Vị trí của vùng code cave tìm ở B5.2
param3 = b"EEEE"              # lpBuffer                  # Offset của shellcode tương quan với vị trí hiện tại
param4 = b"FFFF"              # nSize                     # Kích thước của shellcode (Giá trị đủ lớn tùy ý) 
param5 = b"GGGG"              # *lpNumberOfBytesWritten   # Có thể đặt mặc định là NULL
```
