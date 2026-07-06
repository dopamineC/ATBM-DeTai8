"""
=============================================================
ĐỀ TÀI 8: GỬI CV AN TOÀN CÓ KIỂM TRA IP
Script: run_all.py - Chạy cả Sender + Receiver trong 1 lệnh
Cách dùng: python run_all.py
=============================================================
"""

import subprocess
import sys
import os
import time
import webbrowser
import signal

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def main():
    print("=" * 55)
    print("  ĐỀ TÀI 8: GỬI CV AN TOÀN CÓ KIỂM TRA IP")
    print("  Khởi động cả 2 server...")
    print("=" * 55)

    processes = []

    try:
        # Chạy receiver trước (cần socket server sẵn sàng)
        print("\n[1/2] Đang khởi động Receiver (port 5000, socket 9999)...")
        receiver = subprocess.Popen(
            [sys.executable, os.path.join(SCRIPT_DIR, "receiver.py")],
            cwd=SCRIPT_DIR,
        )
        processes.append(("Receiver", receiver))
        time.sleep(1.5)  # Đợi receiver sẵn sàng

        # Chạy sender
        print("[2/2] Đang khởi động Sender (port 5001)...")
        sender = subprocess.Popen(
            [sys.executable, os.path.join(SCRIPT_DIR, "sender.py")],
            cwd=SCRIPT_DIR,
        )
        processes.append(("Sender", sender))
        time.sleep(1)

        print("\n" + "=" * 55)
        print("  ✅ Đã khởi động thành công!")
        print(f"  📥 Receiver: http://localhost:5000")
        print(f"  📤 Sender:   http://localhost:5001")
        print("=" * 55)

        # Mở trình duyệt
        webbrowser.open("http://localhost:5000")
        time.sleep(0.5)
        webbrowser.open("http://localhost:5001")

        print("\n  Nhấn Ctrl+C để dừng cả 2 server.\n")

        # Chờ cho đến khi user nhấn Ctrl+C
        while True:
            # Kiểm tra xem process nào bị crash
            for name, proc in processes:
                if proc.poll() is not None:
                    print(f"\n  ⚠️  {name} đã dừng (exit code: {proc.returncode})")
            time.sleep(2)

    except KeyboardInterrupt:
        print("\n\n  Đang dừng tất cả server...")
    finally:
        for name, proc in processes:
            if proc.poll() is None:
                print(f"  Dừng {name}...")
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
        print("  ✅ Đã dừng tất cả. Tạm biệt!\n")


if __name__ == "__main__":
    main()
