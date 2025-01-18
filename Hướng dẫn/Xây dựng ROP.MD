# XÂY DỰNG ROP CHAIN
Lưu ý chụp lại các bước trong code kết hợp với debug.
Buffer gửi đi cuối cùng sẽ có dạng như sau:
```
buffer = overflowfiller + functionstack + eip + ROPchain + NOPs + shellcode

# Trong đó:
# overflowfiller: Ký tự bất kỳ chèn vào để đủ gây ra overflow
# functionstack: Stack xây dựng lại của chúng ta. Ban đầu sẽ là stack mẫu với những ký tự đặt tạm thay thế.
# eip: Điểm đầu vào gây ra overflow. Ở đây sẽ là câu lệnh đầu tiên trước khi vào ROP chính. Sử dụng để lưu lại giá trị esp.
# ROPchain: Xây dựng ROP chain để truyền các giá trị cho stack.
# NOPs: Một chuỗi các ký tự x90 để giúp cho việc trượt vào shellcode dễ dàng hơn không gặp lỗi.
# shellcode: Đoạn shellcode để thực thi (Sẽ là shellcode reverse shell).
```

## Xây dựng stack mẫu
VirtualAlloc:
```
functionAddress = b"AAAA"           # VirtualAllocStub address
shellcodeAddress = b"BBBB"          # Shellcode address
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
Sau khi xác định được thanh ghi thì tìm [gadget đẩy giá trị](https://github.com/Cl0wnK1n9/ShellcodeTemplate-windowx86/blob/main/DEP%20bypass%20note/saveESP.md) hoặc [gadget tráo giá trị](https://github.com/Cl0wnK1n9/ShellcodeTemplate-windowx86/blob/main/DEP%20bypass%20note/swapESP.md) để lưu lại esp lên thanh ghi ta đã chọn.


## Tìm vị trí của pointer và đưa nó về đầu stack mẫu
Sử dụng WinDBG để xác định vị trí của esp lúc xảy ra overflow. Khi đó con trỏ sẽ đang nằm giữa stack mẫu của chúng ta.
Sử dụng các gadget để di chuyển con trỏ về phía đầu stack (Trước AAAA). 
Mục tiêu là sẽ tuần tự ghi đè các giá trị tương ứng lên các tham số trên stack.


## Xây dựng ROPchain 
Sử dụng các gadget để biến đổi các thanh ghi truyền tham số tương ứng.
Lưu ý:
```
# Gadget có lệnh pop cho phép đưa giá trị bất kỳ theo ý muốn lên 1 thanh ghi miễn là không có bad character.
ROP += p32(0x12345678)    # pop eax ; ret ;
ROP += p32(0x11111111)    # Giá trị 0x11111111 sẽ được đẩy vào eax

# Khi gadget có lệnh pop chèn vào thì phải bù lại bằng 4 bytes với mỗi pop tương ứng 
ROP += p32(0x12345678)    # add eax, ecx ; pop esi ; pop ebx ; ret ;
ROP += b"AAAA"            # Bù 1 pop
ROP += b"AAAA"            # Bù 1 pop
```

Để debug trong quá trình xây dựng ROPchain, có thể sử dụng WinDBG với lệnh đặt breakpoint thủ công
```
bp <địa chỉ trong memory>

# VD trong code ta có 
ROP += p32(0x12345678)    # pop eax ; ret ;

# Thì có thể đặt breakpoint như sau:
bp 0x12345678
```

Có thể kiểm tra xem các giá trị được lưu với lệnh `dds <địa chỉ>`
```
# VD: Chúng ta lưu esp vào thanh ghi esi và hiện tại esi đang dừng tại giá trị của functionaddress sau khi đã ghi đè

dds esi L4

# Output sẽ là đoạn địa chỉ và giá trị tương ứng. Bên phải sẽ là giá trị đã disassemble, ở đây nếu các hàm có sẵn symbol trong windows thì sẽ được giải mã thành tên các hàm tương ứng (VD: VirtualAllocStub, WriteProcessMemory...)
```

## Trả lại con trỏ về đầu stack và khôi phục esp
Sau khi đã xây dựng xong stack với những giá trị đúng, ta sẽ dùng các gadget để lùi con trỏ (hiện đang lưu trên thanh ghi đã chọn từ trước) lại về trước stack.
Khi con trỏ đã về đầu stack thì chúng ta sẽ dùng các gadget tương tự như ở bước lưu lại thanh ghi esp để trả lại giá trị của con trỏ về esp.
Có thể sử dụng lệnh `dds esp` để kiểm tra stack đã chứa những giá trị đúng ở bước này.



