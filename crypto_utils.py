"""
=============================================================
ĐỀ TÀI 8: GỬI CV AN TOÀN CÓ KIỂM TRA IP
Module: crypto_utils.py
Chức năng: Tất cả hàm mã hóa (AES-CBC, RSA 1024-bit, SHA-512)
           + Hàm truyền/nhận message qua socket
=============================================================
"""

import json
import base64
import hashlib
import struct
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# ===================== AES-CBC =====================

def generate_session_key():
    """Tạo session key ngẫu nhiên 256-bit (32 bytes) cho AES"""
    return get_random_bytes(32)


def aes_cbc_encrypt(plaintext_bytes, key):
    """
    Mã hóa dữ liệu bằng AES-CBC.
    Input:  plaintext_bytes (bytes), key (32 bytes)
    Output: (iv, ciphertext) - cả hai đều là bytes
    """
    iv = get_random_bytes(16)                       # IV ngẫu nhiên 16 bytes
    cipher = AES.new(key, AES.MODE_CBC, iv)         # Tạo cipher AES-CBC
    padded = pad(plaintext_bytes, AES.block_size)   # Padding PKCS7
    ciphertext = cipher.encrypt(padded)             # Mã hóa
    return iv, ciphertext


def aes_cbc_decrypt(ciphertext, key, iv):
    """
    Giải mã dữ liệu bằng AES-CBC.
    Input:  ciphertext (bytes), key (32 bytes), iv (16 bytes)
    Output: plaintext_bytes (bytes)
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)         # Tạo cipher AES-CBC
    padded = cipher.decrypt(ciphertext)              # Giải mã
    plaintext = unpad(padded, AES.block_size)        # Bỏ padding
    return plaintext


# ===================== RSA 1024-bit =====================

def generate_rsa_keys():
    """
    Tạo cặp khóa RSA 1024-bit.
    Output: (private_key_pem, public_key_pem) - cả hai là bytes PEM
    """
    key = RSA.generate(1024)
    private_key_pem = key.export_key()
    public_key_pem = key.publickey().export_key()
    return private_key_pem, public_key_pem


def rsa_encrypt(data, public_key_pem):
    """
    Mã hóa dữ liệu bằng RSA-OAEP (dùng để mã hóa session key).
    Lưu ý: OAEP với RSA 1024-bit dùng SHA-1 nội bộ (mặc định).
           SHA-512 được dùng cho chữ ký số (hàm rsa_sign bên dưới).
    """
    pub_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(pub_key)               # OAEP padding
    return cipher.encrypt(data)


def rsa_decrypt(encrypted_data, private_key_pem):
    """Giải mã dữ liệu bằng RSA-OAEP"""
    priv_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(priv_key)
    return cipher.decrypt(encrypted_data)


def rsa_sign(data, private_key_pem):
    """
    Ký số dữ liệu bằng RSA + SHA-512.
    Input:  data (bytes), private_key_pem (bytes)
    Output: signature (bytes)
    """
    priv_key = RSA.import_key(private_key_pem)
    h = SHA512.new(data)                            # Hash SHA-512
    signature = pkcs1_15.new(priv_key).sign(h)      # Ký bằng PKCS#1 v1.5
    return signature


def rsa_verify(data, signature, public_key_pem):
    """
    Xác minh chữ ký số RSA/SHA-512.
    Output: True nếu hợp lệ, False nếu không
    """
    try:
        pub_key = RSA.import_key(public_key_pem)
        h = SHA512.new(data)
        pkcs1_15.new(pub_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


# ===================== SHA-512 =====================

def sha512_hash(data):
    """Tính SHA-512 hash, trả về chuỗi hex"""
    return hashlib.sha512(data).hexdigest()


def integrity_hash(iv, ciphertext):
    """
    Tính hash toàn vẹn theo đề bài: SHA-512(IV || ciphertext)
    '||' nghĩa là nối (concatenate) hai chuỗi bytes lại
    """
    return sha512_hash(iv + ciphertext)


# ===================== Base64 Helpers =====================

def to_b64(data):
    """Chuyển bytes → chuỗi Base64"""
    return base64.b64encode(data).decode('utf-8')


def from_b64(s):
    """Chuyển chuỗi Base64 → bytes"""
    return base64.b64decode(s.encode('utf-8'))


# ===================== Socket Protocol Helpers =====================

def send_message(sock, data_dict):
    """
    Gửi một message JSON qua socket.
    Format: [4 bytes chiều dài] + [JSON data]
    """
    json_bytes = json.dumps(data_dict).encode('utf-8')
    length = len(json_bytes)
    sock.sendall(struct.pack('>I', length) + json_bytes)


def recv_message(sock):
    """
    Nhận một message JSON từ socket.
    Đọc 4 bytes đầu để biết chiều dài, rồi đọc đủ dữ liệu.
    """
    # Đọc 4 bytes chiều dài
    length_bytes = _recv_exact(sock, 4)
    length = struct.unpack('>I', length_bytes)[0]
    # Đọc dữ liệu JSON
    json_bytes = _recv_exact(sock, length)
    return json.loads(json_bytes.decode('utf-8'))


def _recv_exact(sock, n):
    """Đọc chính xác n bytes từ socket"""
    data = b''
    while len(data) < n:
        chunk = sock.recv(min(n - len(data), 65536))
        if not chunk:
            raise ConnectionError("Mất kết nối!")
        data += chunk
    return data
