# XÂY DỰNG ROP CHAIN

## Xây dựng stack mẫu
VirtualAlloc:
```
functionAddress = b"AAAA"       # VirtualAllocStub address
shellcodeAddress = b"BBBB"      # Shellcode address
parameter1 = b"CCCC"                # lpAddress             # shellcode address
parameter2 = b"DDDD"                # dwSize
parameter3 = b"EEEE"                # flAllocationType
parameter4 = b"FFFF"                # flProtect
```
WriteProcessMemory (Tham khảo: https://connormcgarr.github.io/ROP2/)
```
functionAddress = b"AAAA"         # WriteProcessMemory address
shellcodeAddress = b"BBBB"        # shellcode RET address     # Vị trí của vùng code cave tìm ở B5.2
parameter1 = b"CCCC"              # hProcess                  # Đặt giá trị là -1 tượng trưng cho process hiện tại
parameter2 = b"DDDD"              # lpBaseAddress             # Vị trí của vùng code cave tìm ở B5.2
parameter3 = b"EEEE"              # lpBuffer                  # Offset của shellcode tương quan với vị trí hiện tại
parameter4 = b"FFFF"              # nSize                     # Kích thước của shellcode (Giá trị đủ lớn tùy ý) 
parameter5 = b"GGGG"              # *lpNumberOfBytesWritten   # Có thể đặt mặc định là NULL
```

## Lưu lại thanh ghi esp
Chúng ta sẽ phải tìm một thanh ghi có ROP gadget mà cho phép chúng ta lưu được giá trị vào địa chỉ bất kì dựa trên thanh ghi đó.
Về cơ bản, chúng ta sẽ cần 1 lệnh tương tự `mov dword [esi], eax ; ret ;`
Sau khi xác định được thanh ghi thì tìm [gadget](https://github.com/Cl0wnK1n9/ShellcodeTemplate-windowx86/blob/main/DEP%20bypass%20note/saveESP.md) để lưu lại esp lên.
```


## Tìm vị trí của pointer và đưa nó về đầu stack mẫu
