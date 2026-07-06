import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

"""
=============================================================
DE TAI 8: GUI CV AN TOAN CO KIEM TRA IP
Module: sender.py  (NGƯỜI GỬI - Ứng viên)
Chạy:   python sender.py
Web UI: http://localhost:5001
=============================================================
"""

import os

import json
import time
import socket
from datetime import datetime
from flask import Flask, render_template, jsonify, request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crypto_utils import (
    send_message, recv_message, to_b64, from_b64,
    generate_rsa_keys, generate_session_key,
    rsa_encrypt, rsa_sign,
    aes_cbc_encrypt, integrity_hash
)

# ===================== CẤU HÌNH =====================

FLASK_PORT = 5001
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ===================== FLASK APP =====================

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Max 16MB


@app.route('/')
def upload_page():
    """Trang upload CV"""
    return render_template('sender.html')


@app.route('/send', methods=['POST'])
def send_file():
    """
    API gửi file. Nhận file từ form, chạy 4 bước protocol qua socket.
    Trả về JSON chứa kết quả từng bước để hiển thị trên UI.
    """
    # Lấy thông tin từ request
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'Chưa chọn file!'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'Chưa chọn file!'}), 400

    server_ip = request.form.get('server_ip', '127.0.0.1')
    server_port = int(request.form.get('server_port', '9999'))

    # Đọc file
    file_data = file.read()
    filename = file.filename

    # Chạy protocol và trả về kết quả từng bước
    result = run_protocol(file_data, filename, server_ip, server_port)
    return jsonify(result)


def run_protocol(file_data, filename, server_ip, server_port):
    """
    Chạy 4 bước protocol gửi file an toàn.
    Trả về dict chứa kết quả từng bước để hiển thị trên giao diện.
    """
    steps = []          # Danh sách các bước đã thực hiện
    crypto_info = {}    # Thông tin mã hóa chi tiết

    try:
        # Kết nối socket tới receiver
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect((server_ip, server_port))

        my_ip = sock.getsockname()[0]

        # ========== BƯỚC 1: HANDSHAKE ==========
        step1_start = time.time()

        send_message(sock, {
            'type': 'hello',
            'ip': my_ip
        })

        response = recv_message(sock)

        if response.get('type') == 'reject':
            steps.append({
                'step': 1, 'name': 'Handshake',
                'status': 'error',
                'details': f'Bị từ chối: {response.get("reason", "IP không hợp lệ")}'
            })
            sock.close()
            return {'success': False, 'steps': steps, 'error': 'IP bị từ chối'}

        receiver_pub_key = from_b64(response['receiver_public_key'])

        steps.append({
            'step': 1, 'name': 'Handshake (Bắt tay)',
            'status': 'success',
            'time_ms': round((time.time() - step1_start) * 1000),
            'details': f'Gửi "Hello!" + IP ({my_ip}) → Nhận "Ready!" từ server'
        })

        # ========== BƯỚC 2: XÁC THỰC & TRAO KHÓA ==========
        step2_start = time.time()

        # Tạo cặp khóa RSA cho sender
        sender_private_key, sender_public_key = generate_rsa_keys()

        # Tạo session key cho AES
        session_key = generate_session_key()

        # Tạo metadata
        metadata = {
            'filename': filename,
            'timestamp': datetime.now().isoformat(),
            'ip': my_ip
        }
        metadata_json = json.dumps(metadata)
        metadata_bytes = metadata_json.encode('utf-8')

        # Ký metadata bằng RSA/SHA-512
        signed_metadata = rsa_sign(metadata_bytes, sender_private_key)

        # Mã hóa session key bằng RSA-OAEP (dùng public key của RECEIVER)
        encrypted_session_key = rsa_encrypt(session_key, receiver_pub_key)

        # Gửi key exchange
        send_message(sock, {
            'type': 'key_exchange',
            'sender_public_key': to_b64(sender_public_key),
            'metadata': metadata_json,
            'signed_metadata': to_b64(signed_metadata),
            'encrypted_session_key': to_b64(encrypted_session_key)
        })

        response = recv_message(sock)
        if response.get('type') != 'key_ok':
            steps.append({
                'step': 2, 'name': 'Xác thực & Trao khóa',
                'status': 'error',
                'details': f'Thất bại: {response.get("reason", "Lỗi không xác định")}'
            })
            sock.close()
            return {'success': False, 'steps': steps, 'error': 'Key exchange thất bại'}

        crypto_info['rsa_key_size'] = '1024-bit'
        crypto_info['session_key'] = to_b64(session_key)[:16] + '...'
        crypto_info['metadata'] = metadata

        steps.append({
            'step': 2, 'name': 'Xác thực & Trao khóa',
            'status': 'success',
            'time_ms': round((time.time() - step2_start) * 1000),
            'details': (
                f'RSA 1024-bit keys generated | '
                f'Metadata signed (SHA-512) | '
                f'Session key encrypted (OAEP)'
            )
        })

        # ========== BƯỚC 3: MÃ HÓA & GỬI DỮ LIỆU ==========
        step3_start = time.time()

        # Mã hóa file bằng AES-CBC
        iv, ciphertext = aes_cbc_encrypt(file_data, session_key)

        # Tính hash toàn vẹn: SHA-512(IV || ciphertext)
        hash_hex = integrity_hash(iv, ciphertext)

        # Ký hash
        signature = rsa_sign(hash_hex.encode('utf-8'), sender_private_key)

        # Tạo gói tin theo đúng format đề bài
        packet = {
            'type': 'encrypted_data',
            'iv': to_b64(iv),
            'cipher': to_b64(ciphertext),
            'hash': hash_hex,
            'sig': to_b64(signature)
        }

        send_message(sock, packet)

        crypto_info['algorithm'] = 'AES-CBC'
        crypto_info['iv'] = to_b64(iv)
        crypto_info['hash'] = hash_hex
        crypto_info['signature'] = to_b64(signature)[:32] + '...'
        crypto_info['original_size'] = len(file_data)
        crypto_info['encrypted_size'] = len(ciphertext)

        steps.append({
            'step': 3, 'name': 'Mã hóa & Gửi dữ liệu',
            'status': 'success',
            'time_ms': round((time.time() - step3_start) * 1000),
            'details': (
                f'AES-CBC: {len(file_data)} → {len(ciphertext)} bytes | '
                f'Hash: SHA-512(IV||cipher) | '
                f'Signature: RSA/SHA-512'
            )
        })

        # ========== BƯỚC 4: CHỜ XÁC NHẬN ==========
        step4_start = time.time()

        response = recv_message(sock)

        if response.get('type') == 'ack':
            steps.append({
                'step': 4, 'name': 'Xác nhận',
                'status': 'success',
                'time_ms': round((time.time() - step4_start) * 1000),
                'details': f'Nhận ACK ✅: {response.get("message", "Thành công!")}'
            })
            sock.close()
            return {
                'success': True,
                'steps': steps,
                'crypto': crypto_info,
                'message': 'File đã gửi thành công và an toàn!'
            }
        else:
            steps.append({
                'step': 4, 'name': 'Xác nhận',
                'status': 'error',
                'time_ms': round((time.time() - step4_start) * 1000),
                'details': f'Nhận NACK ❌: {response.get("reason", "Lỗi")}'
            })
            sock.close()
            return {
                'success': False,
                'steps': steps,
                'crypto': crypto_info,
                'error': response.get('reason', 'Server từ chối')
            }

    except ConnectionRefusedError:
        steps.append({
            'step': 1, 'name': 'Kết nối',
            'status': 'error',
            'details': f'Không thể kết nối tới {server_ip}:{server_port}. Hãy chạy receiver.py trước!'
        })
        return {'success': False, 'steps': steps, 'error': 'Không kết nối được server'}

    except socket.timeout:
        steps.append({
            'step': len(steps) + 1, 'name': 'Timeout',
            'status': 'error',
            'details': 'Hết thời gian chờ phản hồi từ server'
        })
        return {'success': False, 'steps': steps, 'error': 'Timeout'}

    except Exception as e:
        steps.append({
            'step': len(steps) + 1, 'name': 'Lỗi',
            'status': 'error',
            'details': str(e)
        })
        return {'success': False, 'steps': steps, 'error': str(e)}


# ===================== MAIN =====================

if __name__ == '__main__':
    print("=" * 50)
    print("  ĐỀ TÀI 8: GỬI CV AN TOÀN CÓ KIỂM TRA IP")
    print("  SENDER - Ứng viên gửi CV")
    print("=" * 50)
    print(f"  Web UI: http://localhost:{FLASK_PORT}")
    print("=" * 50)

    app.run(host='0.0.0.0', port=FLASK_PORT, debug=False)
