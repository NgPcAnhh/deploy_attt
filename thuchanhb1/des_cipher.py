from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import time
import hashlib

class DESCipher:
    def __init__(self):
        self.key_size = 8  # 8 bytes = 64 bits
        self.block_size = DES.block_size  # 8 bytes
        
    def generate_key(self, password=None):
        if password:
            # Tạo key từ password sử dụng SHA256, lấy 8 bytes đầu
            hash_key = hashlib.sha256(password.encode()).digest()
            return hash_key[:self.key_size]
        else:
            # Tạo key ngẫu nhiên
            return get_random_bytes(self.key_size)
    
    def encrypt_data(self, data, key):
        # Tạo IV ngẫu nhiên
        iv = get_random_bytes(self.block_size)
        
        # Tạo cipher object
        cipher = DES.new(key, DES.MODE_CBC, iv)
        
        # Padding dữ liệu và mã hóa
        padded_data = pad(data, self.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        
        return encrypted_data, iv
    
    def decrypt_data(self, encrypted_data, key, iv):
        # Tạo cipher object
        cipher = DES.new(key, DES.MODE_CBC, iv)
        
        # Giải mã và unpad
        decrypted_padded = cipher.decrypt(encrypted_data)
        decrypted_data = unpad(decrypted_padded, self.block_size)
        
        return decrypted_data

def encrypt_text_file(input_file, output_file, password):
    cipher = DESCipher()
    key = cipher.generate_key(password)
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            text_data = f.read()
        
        data_bytes = text_data.encode('utf-8')
        encrypted_data, iv = cipher.encrypt_data(data_bytes, key)
        
        with open(output_file, 'wb') as f:
            f.write(iv + encrypted_data)
        
        print(f"✓ File '{input_file}' đã được mã hóa thành '{output_file}'")
        print("⚠️ CẢNH BÁO: DES có độ bảo mật thấp (56-bit key)!")
        return True
    except Exception as e:
        print(f"✗ Lỗi mã hóa file: {e}")
        return False

def decrypt_text_file(input_file, output_file, password):
    cipher = DESCipher()
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
    print("\n=== Test hiệu năng DES ===")
    cipher = DESCipher()
    
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
    throughput = 2 / (encryption_time + decryption_time)
    
    print(f"Key Size: 64 bits (56-bit hiệu quả)")
    print(f"Encryption Time: {encryption_time:.4f}s")
    print(f"Decryption Time: {decryption_time:.4f}s")
    print(f"Throughput: {throughput:.2f} MB/s")
    print(f"Correct: {is_correct}")
    print("⚠️ DES có độ bảo mật thấp - không nên sử dụng!")

def main():
    print("=== DES Cipher - Mã hóa File Text ===")
    print("DES có độ bảo mật thấp (56-bit key) - đã lỗi thời")
    
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
                
            output_file = input("Nhập tên file đầu ra (ví dụ: encrypted_des.bin): ").strip()
            password = input("Nhập mật khẩu: ").strip()
            
            confirm = input("⚠️ DES không an toàn! Tiếp tục? (y/n): ").strip().lower()
            if confirm == 'y':
                start_time = time.time()
                if encrypt_text_file(input_file, output_file, password):
                    end_time = time.time()
                    print(f"✓ Thời gian mã hóa: {end_time - start_time:.4f}s")
            
        elif choice == '2':
            input_file = input("Nhập tên file cần giải mã: ").strip()
            if not os.path.exists(input_file):
                print(f"✗ File '{input_file}' không tồn tại!")
                continue
                
            output_file = input("Nhập tên file đầu ra: ").strip()
            password = input("Nhập mật khẩu: ").strip()
            
            start_time = time.time()
            if decrypt_text_file(input_file, output_file, password):
                end_time = time.time()
                print(f"✓ Thời gian giải mã: {end_time - start_time:.4f}s")
            
        elif choice == '3':
            performance_test()
            
        elif choice == '4':
            # Tạo file text mẫu
            sample_file = "sample_text_des.txt"
            sample_content = """File text mẫu cho DES encryption test.
                                DES (Data Encryption Standard) sử dụng key 64-bit.
                                Chỉ có 56-bit hiệu quả do 8-bit parity.
                                DES đã bị coi là không an toàn từ những năm 1990s.

                                ⚠️ CẢNH BÁO BẢO MẬT:
                                - Key quá ngắn (56-bit)
                                - Có thể bị brute force attack
                                - Block size nhỏ (64-bit)
                                - Được thay thế bởi AES

                                Chỉ sử dụng cho mục đích học tập!
                                Nội dung tiếng Việt có dấu.
                                Số: 1234567890"""
            
            with open(sample_file, 'w', encoding='utf-8') as f:
                f.write(sample_content)
            print(f"✓ Đã tạo file mẫu: {sample_file}")
            
        elif choice == '5':
            print("Thoát chương trình DES!")
            break
        else:
            print("Lựa chọn không hợp lệ!")

if __name__ == "__main__":
    main()