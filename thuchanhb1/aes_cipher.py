from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import time
import hashlib

class AESCipher:
    def __init__(self, key_size=32):  # 32 bytes = 256 bits
        self.key_size = key_size
        self.block_size = AES.block_size  # 16 bytes
        
    def generate_key(self, password=None):
        if password:
            # Tạo key từ password sử dụng SHA256
            return hashlib.sha256(password.encode()).digest()[:self.key_size]
        else:
            # Tạo key ngẫu nhiên
            return get_random_bytes(self.key_size)
    
    def encrypt_data(self, data, key):
        # Tạo IV ngẫu nhiên
        iv = get_random_bytes(self.block_size)
        
        # Tạo cipher object
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Padding dữ liệu và mã hóa
        padded_data = pad(data, self.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        
        return encrypted_data, iv
    
    def decrypt_data(self, encrypted_data, key, iv):
        # Tạo cipher object
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Giải mã và unpad
        decrypted_padded = cipher.decrypt(encrypted_data)
        decrypted_data = unpad(decrypted_padded, self.block_size)
        
        return decrypted_data

def encrypt_text_file(input_file, output_file, password, key_size=32):
    cipher = AESCipher(key_size)
    key = cipher.generate_key(password)  # tạo key từ password với key = 32 tương đương AES-256
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            text_data = f.read()
        
        data_bytes = text_data.encode('utf-8')
        encrypted_data, iv = cipher.encrypt_data(data_bytes, key)
        
        with open(output_file, 'wb') as f:
            f.write(iv + encrypted_data)
        
        print(f"✓ File '{input_file}' đã được mã hóa thành '{output_file}'")
        print(f"✓ Sử dụng AES-{key_size * 8}")
        return True
    except Exception as e:
        print(f"✗ Lỗi mã hóa file: {e}")
        return False

def decrypt_text_file(input_file, output_file, password, key_size=32):
    cipher = AESCipher(key_size)
    key = cipher.generate_key(password)
    
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
        
        iv = data[:cipher.block_size]
        encrypted_data = data[cipher.block_size:]
        
        decrypted_data = cipher.decrypt_data(encrypted_data, key, iv)
        text_data = decrypted_data.decode('utf-8')
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(text_data)
        
        print(f"✓ File '{input_file}' đã được giải mã thành '{output_file}'")
        return True
    except Exception as e:
        print(f"✗ Lỗi giải mã file: {e}")
        return False

def performance_test():
    print("\n=== Test hiệu năng AES ===")
    key_sizes = [16, 24, 32]  # AES-128, AES-192, AES-256
    
    for key_size in key_sizes:
        print(f"\nTesting AES-{key_size * 8}...")
        cipher = AESCipher(key_size)
        
        # Tạo dữ liệu test 1MB
        test_data = os.urandom(1024 * 1024)
        key = cipher.generate_key("test_password")
        
        # Test mã hóa
        start_time = time.time()
        encrypted_data, iv = cipher.encrypt_data(test_data, key)
        encryption_time = time.time() - start_time
        
        # Test giải mã
        start_time = time.time()
        decrypted_data = cipher.decrypt_data(encrypted_data, key, iv)
        decryption_time = time.time() - start_time
        
        # Kiểm tra tính đúng đắn
        is_correct = test_data == decrypted_data
        throughput = 2 / (encryption_time + decryption_time)  # 2MB (encrypt + decrypt) / total time
        
        print(f"Encryption Time: {encryption_time:.4f}s")
        print(f"Decryption Time: {decryption_time:.4f}s")
        print(f"Throughput: {throughput:.2f} MB/s")
        print(f"Correct: {is_correct}")

def main():
    print("=== AES Cipher - Mã hóa File Text ===")
    print("Hỗ trợ AES-128, AES-192, AES-256")
    
    while True:
        print("\n" + "="*40)
        print("1. Mã hóa file text")
        print("2. Giải mã file text")
        print("3. Test hiệu năng")
        print("4. Tạo file text mẫu")
        print("5. Thoát")
        print("="*40)
        
        choice = input("Chọn tùy chọn (1-5): ").strip()
        
        if choice == '1':
            input_file = input("Nhập tên file cần mã hóa: ").strip()
            if not os.path.exists(input_file):
                print(f"✗ File '{input_file}' không tồn tại!")
                continue
                
            output_file = input("Nhập tên file đầu ra (ví dụ: encrypted.bin): ").strip()
            password = input("Nhập mật khẩu: ").strip()
            
            print("\nChọn độ mạnh mã hóa:")
            print("1. AES-128 (nhanh)")
            print("2. AES-192 (cân bằng)")
            print("3. AES-256 (bảo mật cao)")
            key_choice = input("Chọn (1-3): ").strip()
            
            key_sizes = {'1': 16, '2': 24, '3': 32}
            key_size = key_sizes.get(key_choice, 32)
            
            start_time = time.time()
            if encrypt_text_file(input_file, output_file, password, key_size):
                end_time = time.time()
                print(f"✓ Thời gian mã hóa: {end_time - start_time:.4f}s")
            
        elif choice == '2':
            input_file = input("Nhập tên file cần giải mã: ").strip()
            if not os.path.exists(input_file):
                print(f"✗ File '{input_file}' không tồn tại!")
                continue
                
            output_file = input("Nhập tên file đầu ra: ").strip()
            password = input("Nhập mật khẩu: ").strip()
            
            print("\nChọn độ mạnh mã hóa đã sử dụng:")
            print("1. AES-128")
            print("2. AES-192")
            print("3. AES-256")
            key_choice = input("Chọn (1-3): ").strip()
            
            key_sizes = {'1': 16, '2': 24, '3': 32}
            key_size = key_sizes.get(key_choice, 32)
            
            start_time = time.time()
            if decrypt_text_file(input_file, output_file, password, key_size):
                end_time = time.time()
                print(f"✓ Thời gian giải mã: {end_time - start_time:.4f}s")
            
        elif choice == '3':
            performance_test()
            
        elif choice == '4':
            # Tạo file text mẫu
            sample_file = "sample_text.txt"
            sample_content = """Đây là file text mẫu để test mã hóa AES.
                                AES (Advanced Encryption Standard) là thuật toán mã hóa đối xứng.
                                Được NIST công nhận làm chuẩn mã hóa năm 2001.
                                Hỗ trợ key size: 128, 192, 256 bits.
                                File này có thể được mã hóa bằng AES cipher.

                                Nội dung tiếng Việt có dấu để test encoding UTF-8.
                                Các ký tự đặc biệt: !@#$%^&*()_+-=[]{}|;':\",./<>?

                                Số: 1234567890
                                Test AES encryption/decryption successfully!"""
            
            with open(sample_file, 'w', encoding='utf-8') as f:
                f.write(sample_content)
            print(f"✓ Đã tạo file mẫu: {sample_file}")
            
        elif choice == '5':
            print("Thoát chương trình AES!")
            break
        else:
            print("Lựa chọn không hợp lệ!")

if __name__ == "__main__":
    main()