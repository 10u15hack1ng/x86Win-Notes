# Các bước cần làm khi đi thi

## Bài 1:

B1: Xác nhận code POC overflow của hãng \
B2: Tìm điểm overflow (offset)  \
B3: Tìm bad characters (ghi lại) \
B4: Tìm module có thể khai thác được (module không có ASLR) \
B5: Tìm API có thể khai thác được (Có thể là VirtualAlloc hoặc là WPM) \
B6: Tìm ROP gadgets để vượt qua DEP \
B7: Xây dựng stack dùng ROP gadget \
B8: Tạo shellcode thủ công \


## Bài 2:

B1: Xác định các hàm cần sử dụng theo yêu cầu của đề bài
B2: Load các thư viện và các hàm cần thiết
B3: Xây dựng địa chỉ dựa trên hàm yêu cầu
B4: Thiết lập và kiểm tra server giao tiếp với máy kali
B5: Test script
