# Danh mục và Đặc tả 44 Đặc trưng (44-Dimensional Feature Vector) trong LotLDetectionV2

Hệ thống **LotLDetectionV2** trích xuất vector đặc trưng **44 chiều cố định** cho mỗi cặp tiến trình **Cha – Con (Parent-Child Process Pair)**. Kiến trúc đặc trưng này được cài đặt chính xác dựa trên Chương 5 (Mục 5.2.3, Bảng 5 & Bảng 7) trong luận văn của **Utz Nisslmueller (2022)**.

---

## 1. Cấu trúc tổng thể của Vector 44 chiều

Vector 44 chiều được phân bổ theo thứ tự nghiêm ngặt sau:

$$\text{Vector (44)} = [\underbrace{\text{Child F1 \dots F18}}_{18} \quad \Vert \quad \underbrace{\text{Parent F1 \dots F18}}_{18} \quad \Vert \quad \underbrace{\text{Context F19 \dots F26}}_{8}]$$

1. **Child Command Line Features (18 chiều):** Đặc trưng $F_1 \to F_{18}$ trích xuất từ dòng lệnh của **Tiến trình Con**.
2. **Parent Command Line Features (18 chiều):** Đặc trưng $F_1 \to F_{18}$ trích xuất từ dòng lệnh của **Tiến trình Cha**.
3. **Contextual Process Features (8 chiều):** Đặc trưng $F_{19} \to F_{26}$ trích xuất từ ngữ cảnh hệ thống của cả cha và con.

---

## 2. Chi tiết 18 Đặc trưng Dòng lệnh ($F_1 \dots F_{18}$)

*(Áp dụng độc lập cho cả dòng lệnh Con và dòng lệnh Cha)*

| ID | Tên Đặc trưng trong Mã nguồn | Loại | Mô tả chi tiết theo Luận văn Nisslmueller (2022) | Mục đích An ninh mạng |
| :---: | :--- | :---: | :--- | :--- |
| **F1** | `no_documentation` | Boolean | `1` nếu tệp thực thi **không có tài liệu** trong từ điển xCyclopedia, ngược lại là `0`. | Phát hiện phần mềm lạ, công cụ của bên thứ 3 chưa từng gặp. |
| **F2** | `documented_usage` | Boolean | `1` nếu tệp có tài liệu và các cờ/đối số chạy **nằm trong tài liệu chuẩn**, ngược lại `0`. | Xác nhận hành vi hợp lệ, bình thường của tiến trình Windows. |
| **F3** | `undocumented_usage` | Boolean | `1` nếu tệp có tài liệu nhưng đối số truyền vào **chưa từng được ghi nhận trong tài liệu**, ngược lại `0`. | Phát hiện cờ ẩn hoặc tham số khai thác LOLBin bất thường. |
| **F4** | `anomalous_argument` | Boolean | `1` nếu có ít nhất 1 tham số dòng lệnh xuất hiện với tần suất **$< 1\%$** trong toàn bộ tập lịch sử (corpus), ngược lại `0`. | Bắt các tham số dị biệt ít khi dùng trong môi trường doanh nghiệp. |
| **F5** | `potential_obfuscation` | Boolean | `1` nếu phát hiện các ký tự làm rối dòng lệnh cmd/powershell: `^`, `""`, `set`, `&&`, `&&for`, `for %`, `;;`, ngược lại `0`. | Phát hiện kỹ thuật làm rối (Command Line Obfuscation) để vượt mặt EDR. |
| **F6** | `potential_hex` | Boolean | `1` nếu phát hiện chuỗi Hex dài $\ge 8$ ký tự (`0x...` hoặc chuỗi hex liền khối), ngược lại `0`. | Phát hiện shellcode dạng hex, địa chỉ bộ nhớ hoặc payload mã hóa. |
| **F7** | `char_ratio_deviation` | Boolean | Kiểm định Chi-square ($\chi^2$) tỷ lệ 5 nhóm ký tự (Hoa, Thường, Số, Khoảng trắng, Ký tự đặc biệt) so với phân phối nền của corpus. | Phát hiện dòng lệnh có mật độ ký tự bất thường (dấu hiệu mã độc). |
| **F8** | `remote_code` | Boolean | `1` nếu URL hoặc đường dẫn mạng UNC (`\\server\share`) trỏ trực tiếp đến tệp thực thi (`.exe`, `.dll`, `.vbs`, `.ps1`...), ngược lại `0`. | Phát hiện kỹ thuật thực thi mã trực tiếp từ xa (Remote Execution). |
| **F9** | `potentially_untrusted_code` | Boolean | `1` nếu tệp mã thực thi nằm **ngoài các thư mục được bảo vệ** (ngoài `C:\Windows`, `%SystemRoot%`), ngược lại `0`. | Phát hiện script/binary chạy từ thư mục tạm (`AppData`, `Temp`, `Downloads`). |
| **F10** | `suspicious_extension` | Boolean | `1` nếu dòng lệnh chứa đuôi file nằm trong danh mục rủi ro của FileSec.io (nhưng không phải là binary thực thi trực tiếp), ngược lại `0`. | Bắt các phần mở rộng đáng ngờ (ví dụ: `.sct`, `.wsc`, `.inf`, `.settingcontent-ms`). |
| **F11** | `untrusted_hostname` | Boolean | `1` nếu dòng lệnh kết nối đến IP công cộng (Global IPv4) hoặc nằm trong danh sách domain bị lạm dụng (LOTS Project), ngược lại `0`. | Phát hiện LOLBin kết nối C2 hoặc tải payload từ GitHub, Pastebin, Discord... |
| **F12** | `url_encoding` | Boolean | `1` nếu dòng lệnh chứa ký tự mã hóa URL (dạng `%20`, `%2f`...), ngược lại `0`. | Phát hiện kỹ thuật né tránh kiểm tra chuỗi (URL Obfuscation). |
| **F13** | `one_hostname_one_path` | Boolean | `1` nếu dòng lệnh chứa đúng **1 hostname/IP và đúng 1 đường dẫn cục bộ**, ngược lại `0`. | Pattern kinh điển của lệnh tải mã độc về đĩa (`bitsadmin`, `certutil -urlcache`). |
| **F14** | `web_remote_keywords` | Boolean | `1` nếu dòng lệnh chứa các từ khóa mạng: `http`, `www.`, `.com`, `html`, `tcp`, `udp`, ngược lại `0`. | Dấu hiệu tiến trình có hành vi tương tác mạng ngoài luồng. |
| **F15** | `potential_encoding` | Boolean | `1` nếu có token là chuỗi Base64 hợp lệ ($\ge 8$ ký tự) HOẶC độ hỗn loạn Shannon Entropy $> 7.0$, ngược lại `0`. | Phát hiện lệnh PowerShell encoded (`-enc`) hoặc payload mã hóa. |
| **F16** | `dump_related_string` | Boolean | `1` nếu dòng lệnh chứa các từ khóa trích xuất bộ nhớ: `lsass`, `samsrv`, `hklm\sam`, `winlogon`, `netlogon`, `kerberos.dll`, `dump`, `.bin`, `ntds`. | Phát hiện kỹ thuật đánh cắp mật khẩu (Credential Dumping). |
| **F17** | `multiple_filesystem_paths` | Boolean | `1` nếu dòng lệnh chứa **từ 2 đường dẫn tệp trở lên** (Local path hoặc UNC), ngược lại `0`. | Bắt các thao tác sao chép, di chuyển hoặc đính tệp độc hại. |
| **F18** | `ads_syntax` | Boolean | `1` nếu dòng lệnh chứa cú pháp Alternate Data Streams (`file.ext:stream.ext`), ngược lại `0`. | Kỹ thuật giấu mã độc vào luồng phụ NTFS của Windows (ADS Evasion). |

---

## 3. Chi tiết 8 Đặc trưng Ngữ cảnh ($F_{19} \dots F_{26}$)

| ID | Tên Đặc trưng trong Mã nguồn | Loại | Mô tả chi tiết | Ý nghĩa Phát hiện |
| :---: | :--- | :---: | :--- | :--- |
| **F19** | `F19_parent_image` | Float | Giá trị nhúng 1 chiều (`FastText dim=1`) của đường dẫn ảnh tiến trình **Cha**. | Mã hóa danh tính phần mềm cha để mô hình phân biệt ai là người gọi. |
| **F20** | `F20_child_image` | Float | Giá trị nhúng 1 chiều (`FastText dim=1`) của đường dẫn ảnh tiến trình **Con**. | Phân biệt hành vi hợp lệ của từng binary cụ thể (ví dụ `cp` vs `extrac32`). |
| **F21** | `F21_parent_filename_mismatch` | Boolean | `1` nếu tên file cha gọi ra khác với `OriginalFileName` trong PE Header, ngược lại `0`. | Bắt kỹ thuật ngụy trang (Masquerading: đổi tên hacker tool thành tên hệ thống). |
| **F22** | `F22_child_filename_mismatch` | Boolean | `1` nếu tên file con gọi ra khác với `OriginalFileName` trong PE Header, ngược lại `0`. | Bắt kỹ thuật đổi tên LOLBin để trốn tránh phát hiện. |
| **F23** | `F23_time_delta` | Float | Độ lệch thời gian sinh giữa cha và con ($\Delta t = t_{child} - t_{parent}$), chuẩn hóa Min-Max về đoạn $[0, 1]$. | Phân biệt tiến trình được gọi tự động bằng script ($\Delta t \approx 0$) hay do người dùng gõ tay. |
| **F24** | `F24_parent_integrity` | Integer | Mức đặc quyền Integrity Level của Cha (Untrusted=1, Low=2, Medium=3, High=4, System=5, Installer=6). | Xác lập mô hình đặc quyền chuẩn giữa cha và con. |
| **F25** | `F25_child_integrity` | Integer | Mức đặc quyền Integrity Level của Con (quy đổi tương tự thang 1..6). | Phát hiện hành vi leo thang đặc quyền bất thường (UAC Bypass, Privilege Escalation). |
| **F26** | `F26_invalid_signature` | Boolean | `1` nếu có ít nhất một tiến trình trong cặp **không có chữ ký Microsoft hợp lệ**, ngược lại `0`. | Xác minh nguồn gốc Authenticode (bộ lọc then chốt của bài toán LOLBin). |

---

## 4. So sánh với bài báo của Utz Nisslmueller (2022)

Hệ thống mã nguồn trong dự án **LotLDetectionV2** tuân thủ **100% logic toán học và kỹ thuật** của bài báo gốc:

1. **Số lượng chiều không gian (Dimensionality):** Hoàn toàn trùng khớp cố định 44 chiều ($18 \times 2 + 8 = 44$).
2. **Chi tiết F7 (`f7_mode`):** Trong bài báo (trang 22), tác giả in nhầm điều kiện $p > 0.05$ cho Chi-square (ngược với chuẩn thống kê là $p < 0.05$). Mã nguồn dự án rất tinh tế khi cung cấp cờ `--f7-mode`:
   - `paper`: Tái lập chuẩn xác 100% bug của bài báo ($p > 0.05$).
   - `statistical`: Sử dụng điều kiện chuẩn kiểm định giả thuyết thống kê ($p < 0.05$).
3. **Chi tiết F15 (Entropy & Base64):** Sử dụng đúng ngưỡng Shannon Entropy $> 7.0$ và hàm kiểm tra `base64.b64decode` chuẩn xác như mô tả ở Trang 25 của luận văn.
4. **Chi tiết F19-F20 (Image Embedder):** Sử dụng FastText n-gram thu gọn về đúng `dim=1` để phản ánh đường dẫn ảnh mà không làm bùng nổ số chiều.
5. **Chi tiết F26 (Signature Filter):** Lọc Authenticode dựa trên định nghĩa LOLBin gốc (Định nghĩa 2.1.1): LOLBin bắt buộc phải là binary chính hãng được ký bởi Microsoft.
