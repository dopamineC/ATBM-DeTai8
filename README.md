# 🛡️ Hệ Thống Gửi CV An Toàn Có Kiểm Tra IP

Dự án môn học **An Toàn Bảo Mật** (Đề tài 8). Đây là một hệ thống mô phỏng việc gửi và nhận hồ sơ (CV) an toàn giữa Ứng viên (Sender) và Nhà tuyển dụng (Receiver) thông qua giao thức truyền file tự xây dựng dựa trên Socket và các thuật toán mã hoá mạnh.

## 🌟 Tính Năng Nổi Bật

- **Kiểm soát Truy cập (Whitelist IP)**: Chỉ những IP được cấp phép mới có thể kết nối và gửi file đến Server.
- **Tính Toàn vẹn (Integrity)**: Sử dụng hàm băm **SHA-512** để đảm bảo file không bị chỉnh sửa trong quá trình truyền tải.
- **Tính Xác thực (Authentication)**: Sử dụng chữ ký điện tử **RSA (1024-bit)** để xác thực danh tính người gửi.
- **Tính Bảo mật (Confidentiality)**: Dữ liệu (file CV) được mã hoá đối xứng bằng **AES-CBC** trước khi truyền qua mạng. Khoá phiên (Session key) của AES được trao đổi an toàn thông qua mã hoá bất đối xứng RSA-OAEP.
- **Giao diện Trực quan (Web UI)**: Cung cấp giao diện web cho cả Sender và Receiver thông qua Flask, cho phép theo dõi log giao dịch theo thời gian thực.

## 🚀 Kiến Trúc Hệ Thống

Dự án bao gồm 2 thành phần chính:
1. **Receiver (Nhà tuyển dụng)**: 
   - Lắng nghe kết nối qua Socket (Cổng 9999).
   - Quản lý giao diện Web (Cổng 5000).
   - Tiếp nhận kết nối, xác minh IP, giải mã file, kiểm tra chữ ký và toàn vẹn dữ liệu.
2. **Sender (Ứng viên)**:
   - Giao diện Web gửi file (Cổng 5001).
   - Đọc file, mã hoá thông điệp (4 bước protocol) và gửi qua Socket tới Receiver.

## ⚙️ Cài Đặt & Chạy Dự Án

### Yêu Cầu Môi Trường
- Python 3.8 trở lên.

### Hướng Dẫn Cài Đặt
1. Clone dự án về máy:
   ```bash
   git clone https://github.com/dopamineC/ATBM-DeTai8.git
   cd ATBM
   ```
2. Cài đặt các thư viện cần thiết:
   ```bash
   pip install -r requirements.txt
   ```

### Chạy Dự Án

Cách nhanh nhất để chạy cả hai dịch vụ (Sender và Receiver) là sử dụng script đã được cấu hình sẵn:

```bash
python run_all.py
```
*(Hoặc click đúp vào file `run.bat` trên Windows).*

Hệ thống sẽ tự động khởi động và mở trình duyệt với 2 địa chỉ:
- 📥 **Receiver Dashboard:** http://localhost:5000
- 📤 **Sender Dashboard:** http://localhost:5001

## 📋 Giao Thức Truyền File (4 Bước)

1. **Handshake (Bắt tay)**: Sender gửi thông báo `hello` và IP. Receiver kiểm tra Whitelist IP, nếu hợp lệ sẽ trả về Public Key của mình.
2. **Key Exchange (Trao đổi khoá)**: Sender tạo khoá phiên AES (Session key), ký metadata bằng RSA Private Key của mình, sau đó mã hoá Session key bằng Public Key của Receiver và gửi đi.
3. **Data Transfer (Truyền dữ liệu)**: File được mã hoá bằng AES-CBC. Tính mã băm SHA-512 của dữ liệu mã hoá và ký bằng RSA. Toàn bộ gói tin được gửi tới Receiver.
4. **Verification (Xác thực)**: Receiver nhận gói tin, kiểm tra tính toàn vẹn bằng Hash, xác thực chữ ký RSA và cuối cùng giải mã file bằng AES để lưu trữ.

## 👨‍💻 Tác Giả

- **Đề tài**: 08 - Gửi CV an toàn có kiểm tra IP.
- **Môn học**: An Toàn Bảo Mật.
