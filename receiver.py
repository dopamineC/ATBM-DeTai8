import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

"""
=============================================================
DE TAI 8: GUI CV AN TOAN CO KIEM TRA IP
Module: receiver.py  (NGƯỜI NHẬN - Hệ thống tuyển dụng)
Chạy:   python receiver.py
Web UI: http://localhost:5000
Socket: port 9999
=============================================================
"""

import os
import json
import time
import socket
import threading
from datetime import datetime
from flask import Flask, render_template, jsonify, request, send_from_directory

# Thêm thư mục hiện tại vào path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crypto_utils import (
    recv_message, send_message, from_b64,
    rsa_decrypt, rsa_verify, rsa_sign,
    aes_cbc_decrypt, integrity_hash, generate_rsa_keys, to_b64
)

# ===================== CẤU HÌNH =====================

SOCKET_HOST = '0.0.0.0'
SOCKET_PORT = 9999
FLASK_PORT = 5000
RECEIVED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'received_files')

# Tạo thư mục lưu file nếu chưa có
os.makedirs(RECEIVED_DIR, exist_ok=True)

# ===================== DỮ LIỆU GLOBAL =====================

# Danh sách IP được phép gửi (whitelist)
ip_whitelist = ['127.0.0.1', 'localhost', '::1']

# Log giao dịch (lưu trong bộ nhớ)
transaction_logs = []

# Danh sách file đã nhận
received_files = []

# Khóa RSA của receiver (tạo khi khởi động)
receiver_private_key, receiver_public_key = generate_rsa_keys()

# Lock cho thread safety
log_lock = threading.Lock()


def add_log(level, message, details=""):
    """Thêm một dòng log với timestamp"""
    with log_lock:
        entry = {
            'id': len(transaction_logs) + 1,
            'time': datetime.now().strftime('%H:%M:%S'),
            'level': level,       # 'info', 'success', 'error', 'warning'
            'message': message,
            'details': details
        }
        transaction_logs.append(entry)
        print(f"[{entry['time']}] [{level.upper()}] {message}")


# ===================== SOCKET SERVER =====================

def handle_client(conn, addr):
    """Xử lý một kết nối từ người gửi - chạy 4 bước protocol"""
    client_ip = addr[0]
    add_log('info', f'[CONNECT] Kết nối mới từ {client_ip}:{addr[1]}')

    try:
        # ========== BƯỚC 1: HANDSHAKE ==========
        add_log('info', '[STEP 1] Handshake - Bắt tay...')

        msg = recv_message(conn)
        if msg.get('type') != 'hello':
            send_message(conn, {'type': 'reject', 'reason': 'Invalid handshake'})
            add_log('error', '[FAIL] Handshake thất bại: message không hợp lệ')
            return

        sender_ip = msg.get('ip', client_ip)
        add_log('info', f'   Nhận "Hello!" từ IP: {sender_ip}')

        # Kiểm tra IP whitelist
        if sender_ip not in ip_whitelist and client_ip not in ip_whitelist:
            send_message(conn, {'type': 'reject', 'reason': f'IP {sender_ip} không được phép'})
            add_log('error', f'[DENIED] IP {sender_ip} KHÔNG có trong whitelist')
            return

        add_log('success', f'[PASSED] IP {sender_ip} hợp lệ (có trong whitelist)')
        send_message(conn, {
            'type': 'ready',
            'receiver_public_key': to_b64(receiver_public_key)
        })
        add_log('info', '   Gửi "Ready!" + Public Key cho người gửi')

        # ========== BƯỚC 2: XÁC THỰC & TRAO KHÓA ==========
        add_log('info', '[STEP 2] Xác thực & Trao khóa...')

        msg = recv_message(conn)
        if msg.get('type') != 'key_exchange':
            send_message(conn, {'type': 'nack', 'reason': 'Invalid key exchange'})
            add_log('error', '[FAIL] Key exchange thất bại')
            return

        # Lấy dữ liệu
        sender_pub_key = from_b64(msg['sender_public_key'])
        signed_metadata = from_b64(msg['signed_metadata'])
        metadata_bytes = msg['metadata'].encode('utf-8')
        encrypted_session_key = from_b64(msg['encrypted_session_key'])

        # Xác minh chữ ký metadata
        if not rsa_verify(metadata_bytes, signed_metadata, sender_pub_key):
            send_message(conn, {'type': 'nack', 'reason': 'Chữ ký metadata không hợp lệ'})
            add_log('error', '[FAIL] Chữ ký metadata KHÔNG hợp lệ → NACK')
            return

        add_log('success', '[VERIFIED] Chữ ký metadata hợp lệ')

        # Hiển thị metadata
        metadata = json.loads(msg['metadata'])
        add_log('info', f'   File: {metadata.get("filename", "?")}')
        add_log('info', f'   Timestamp: {metadata.get("timestamp", "?")}')
        add_log('info', f'   IP: {metadata.get("ip", "?")}')

        # Giải mã session key bằng private key của receiver
        session_key = rsa_decrypt(encrypted_session_key, receiver_private_key)
        add_log('success', f'[DECRYPTED] Session key đã giải mã ({len(session_key)*8}-bit)')

        send_message(conn, {'type': 'key_ok'})

        # ========== BƯỚC 3: NHẬN DỮ LIỆU MÃ HÓA ==========
        add_log('info', '[STEP 3] Nhận dữ liệu mã hóa...')

        msg = recv_message(conn)
        if msg.get('type') != 'encrypted_data':
            send_message(conn, {'type': 'nack', 'reason': 'Invalid data'})
            add_log('error', '[FAIL] Dữ liệu không hợp lệ')
            return

        iv = from_b64(msg['iv'])
        ciphertext = from_b64(msg['cipher'])
        received_hash = msg['hash']
        signature = from_b64(msg['sig'])

        add_log('info', f'   IV: {msg["iv"][:24]}...')
        add_log('info', f'   Cipher size: {len(ciphertext)} bytes')
        add_log('info', f'   Hash: {received_hash[:32]}...')

        # ========== BƯỚC 4: KIỂM TRA & GIẢI MÃ ==========
        add_log('info', '[STEP 4] Kiểm tra toàn vẹn & Giải mã...')

        # 4a. Kiểm tra hash: SHA-512(IV || ciphertext)
        computed_hash = integrity_hash(iv, ciphertext)
        if computed_hash != received_hash:
            send_message(conn, {'type': 'nack', 'reason': 'Hash không khớp (integrity fail)'})
            add_log('error', '[INTEGRITY FAIL] Hash KHÔNG khớp → Dữ liệu bị thay đổi!')
            add_log('error', f'   Nhận:  {received_hash[:32]}...')
            add_log('error', f'   Tính:  {computed_hash[:32]}...')
            return

        add_log('success', '[PASSED] Hash khớp → Dữ liệu toàn vẹn')

        # 4b. Kiểm tra chữ ký
        hash_bytes = received_hash.encode('utf-8')
        if not rsa_verify(hash_bytes, signature, sender_pub_key):
            send_message(conn, {'type': 'nack', 'reason': 'Chữ ký không hợp lệ'})
            add_log('error', '[FAIL] Chữ ký KHÔNG hợp lệ → NACK')
            return

        add_log('success', '[VERIFIED] Chữ ký hợp lệ → Xác thực thành công')

        # 4c. Giải mã file bằng AES-CBC
        plaintext = aes_cbc_decrypt(ciphertext, session_key, iv)
        add_log('success', f'[DECRYPTED] Giải mã AES-CBC thành công ({len(plaintext)} bytes)')

        # 4d. Lưu file
        filename = metadata.get('filename', 'received_file.pdf')
        # Thêm timestamp vào tên file để tránh trùng
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_name = f"{timestamp}_{filename}"
        filepath = os.path.join(RECEIVED_DIR, safe_name)
        with open(filepath, 'wb') as f:
            f.write(plaintext)

        add_log('success', f'[SAVED] File đã lưu: {safe_name}')

        # Thêm vào danh sách file đã nhận
        with log_lock:
            received_files.append({
                'filename': safe_name,
                'original_name': filename,
                'size': len(plaintext),
                'sender_ip': sender_ip,
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'hash': received_hash[:16] + '...'
            })

        # Gửi ACK
        send_message(conn, {'type': 'ack', 'message': 'File nhận thành công!'})
        add_log('success', '[ACK SENT] Giao dịch hoàn tất thành công')

    except Exception as e:
        add_log('error', f'[ERROR] {str(e)}')
        try:
            send_message(conn, {'type': 'nack', 'reason': str(e)})
        except:
            pass
    finally:
        conn.close()
        add_log('info', f'[CLOSED] Đã đóng kết nối với {client_ip}')
        add_log('info', '— — — — — — — — — — — — — — — — — — — —')


def socket_server():
    """Chạy socket server lắng nghe kết nối"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((SOCKET_HOST, SOCKET_PORT))
    server.listen(5)
    add_log('info', f'🖥️  Socket server đang lắng nghe trên port {SOCKET_PORT}')

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        thread.start()


# ===================== FLASK WEB APP =====================

app = Flask(__name__)


@app.route('/')
def dashboard():
    """Trang dashboard chính"""
    return render_template('receiver.html')


@app.route('/api/logs')
def get_logs():
    """API lấy danh sách log"""
    with log_lock:
        return jsonify(transaction_logs)


@app.route('/api/files')
def get_files():
    """API lấy danh sách file đã nhận"""
    with log_lock:
        return jsonify(received_files)


@app.route('/api/whitelist', methods=['GET', 'POST', 'DELETE'])
def manage_whitelist():
    """API quản lý IP whitelist"""
    if request.method == 'GET':
        return jsonify(ip_whitelist)
    elif request.method == 'POST':
        ip = request.json.get('ip', '').strip()
        if ip and ip not in ip_whitelist:
            ip_whitelist.append(ip)
            add_log('info', f'➕ Đã thêm IP {ip} vào whitelist')
        return jsonify(ip_whitelist)
    elif request.method == 'DELETE':
        ip = request.json.get('ip', '').strip()
        if ip in ip_whitelist:
            ip_whitelist.remove(ip)
            add_log('info', f'➖ Đã xóa IP {ip} khỏi whitelist')
        return jsonify(ip_whitelist)


@app.route('/api/stats')
def get_stats():
    """API lấy thống kê"""
    with log_lock:
        total = len(received_files)
        success = sum(1 for l in transaction_logs if l['level'] == 'success' and 'ACK' in l['message'])
        errors = sum(1 for l in transaction_logs if l['level'] == 'error')
    return jsonify({'total': total, 'success': success, 'errors': errors})


@app.route('/download/<filename>')
def download_file(filename):
    """Download file đã nhận"""
    return send_from_directory(RECEIVED_DIR, filename, as_attachment=True)


@app.route('/api/clear-logs', methods=['POST'])
def clear_logs():
    """Xóa tất cả log"""
    with log_lock:
        transaction_logs.clear()
    return jsonify({'status': 'ok'})


# ===================== MAIN =====================

if __name__ == '__main__':
    print("=" * 50)
    print("  ĐỀ TÀI 8: GỬI CV AN TOÀN CÓ KIỂM TRA IP")
    print("  RECEIVER - Hệ thống tuyển dụng")
    print("=" * 50)
    print(f"  Web UI:  http://localhost:{FLASK_PORT}")
    print(f"  Socket:  port {SOCKET_PORT}")
    print(f"  IP Whitelist: {ip_whitelist}")
    print("=" * 50)

    # Chạy socket server trong thread riêng
    socket_thread = threading.Thread(target=socket_server, daemon=True)
    socket_thread.start()

    # Chạy Flask web server
    app.run(host='0.0.0.0', port=FLASK_PORT, debug=False)
