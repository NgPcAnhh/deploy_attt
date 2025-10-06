"""
3DES (Triple DES) Cipher Implementation
Mã hóa và giải mã file text sử dụng thuật toán 3DES (Triple Data Encryption Standard)
"""

from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import time
import hashlib

class TripleDESCipher:
    def __init__(self, key_variant="3DES-EDE3"):
        """
        Khởi tạo 3DES cipher
        Args:
            key_variant: Loại key 3DES
                - "3DES-EDE2": 2 key (16 bytes) - K1, K2, K1
                - "3DES-EDE3": 3 key (24 bytes) - K1, K2, K3
        """
        self.key_variant = key_variant
        if key_variant == "3DES-EDE2":
            self.key_size = 16  # 16 bytes = 128 bits
        else:  # 3DES-EDE3
            self.key_size = 24  # 24 bytes = 192 bits
        
        self.block_size = DES3.block_size  # 8 bytes
        
    def generate_key(self, password=None):
        """
        Tạo key từ password hoặc random
        """
        if password:
            # Tạo key từ password sử dụng SHA256
            hash_key = hashlib.sha256(password.encode()).digest()
            key = hash_key[:self.key_size]
            
            # Đảm bảo key hợp lệ cho 3DES
            if self.key_variant == "3DES-EDE2":
                # Cho EDE2: K1, K2, K1
                k1 = key[:8]
                k2 = key[8:16]
                return k1 + k2 + k1
            else:
                # Cho EDE3: sử dụng trực tiếp 24 bytes
                return key
        else:
            # Tạo key ngẫu nhiên
            if self.key_variant == "3DES-EDE2":
                k1 = get_random_bytes(8)
                k2 = get_random_bytes(8)
                return k1 + k2 + k1
            else:
                return get_random_bytes(self.key_size)
    
    def encrypt_data(self, data, key):
        """
        Mã hóa dữ liệu
        Args:
            data: Dữ liệu cần mã hóa (bytes)
            key: Key mã hóa
        Returns:
            tuple: (encrypted_data, iv)
        """
        # Tạo IV ngẫu nhiên
        iv = get_random_bytes(self.block_size)
        
        # Tạo cipher object
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        
        # Padding dữ liệu và mã hóa
        padded_data = pad(data, self.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        
        return encrypted_data, iv
    
    def decrypt_data(self, encrypted_data, key, iv):
        """
        Giải mã dữ liệu
        Args:
            encrypted_data: Dữ liệu đã mã hóa
            key: Key giải mã
            iv: Initialization Vector
        Returns:
            bytes: Dữ liệu đã giải mã
        """
        # Tạo cipher object
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        
        # Giải mã và unpad
        decrypted_padded = cipher.decrypt(encrypted_data)
        decrypted_data = unpad(decrypted_padded, self.block_size)
        
        return decrypted_data

def encrypt_text_file(input_file, output_file, password, variant="3DES-EDE3"):
    """
    Mã hóa file text bằng 3DES
    """
    cipher = TripleDESCipher(variant)
    key = cipher.generate_key(password)
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            text_data = f.read()
        
        data_bytes = text_data.encode('utf-8')
        encrypted_data, iv = cipher.encrypt_data(data_bytes, key)
        
        with open(output_file, 'wb') as f:
            f.write(iv + encrypted_data)
        
        print(f"✓ File '{input_file}' đã được mã hóa thành '{output_file}'")
        print(f"✓ Sử dụng {variant} (112-bit bảo mật hiệu quả)")
        return True
    except Exception as e:
        print(f"✗ Lỗi mã hóa file: {e}")
        return False

def decrypt_text_file(input_file, output_file, password, variant="3DES-EDE3"):
    """
    Giải mã file text bằng 3DES
    """
    cipher = TripleDESCipher(variant)
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
    """
    Test hiệu năng 3DES
    """
    print("\n=== Test hiệu năng 3DES ===")
    variants = ["3DES-EDE2", "3DES-EDE3"]
    
    for variant in variants:
        print(f"\nTesting {variant}...")
        cipher = TripleDESCipher(variant)
        
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
        
        key_bits = len(key) * 8
        effective_bits = 112  # 3DES có 112-bit bảo mật hiệu quả
        
        print(f"Algorithm: {variant}")
        print(f"Key Size: {key_bits} bits")
        print(f"Effective Security: {effective_bits} bits")
        print(f"Encryption Time: {encryption_time:.4f}s")
        print(f"Decryption Time: {decryption_time:.4f}s")
        print(f"Throughput: {throughput:.2f} MB/s")
        print(f"Correct: {is_correct}")

def main():
    """
    Giao diện chính cho 3DES cipher
    """
    print("=== 3DES Cipher - Mã hóa File Text ===")
    print("3DES có bảo mật trung bình (112-bit hiệu quả)")
    print("Khuyến nghị: Chỉ dùng cho tương thích hệ thống cũ")
    
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
                
            output_file = input("Nhập tên file đầu ra (ví dụ: encrypted_3des.bin): ").strip()
            password = input("Nhập mật khẩu: ").strip()
            
            print("\nChọn variant 3DES:")
            print("1. 3DES-EDE2 (2 key, nhanh hơn)")
            print("2. 3DES-EDE3 (3 key, khuyến nghị)")
            variant_choice = input("Chọn (1-2): ").strip()
            
            variant = "3DES-EDE2" if variant_choice == '1' else "3DES-EDE3"
            
            start_time = time.time()
            if encrypt_text_file(input_file, output_file, password, variant):
                end_time = time.time()
                print(f"✓ Thời gian mã hóa: {end_time - start_time:.4f}s")
            
        elif choice == '2':
            input_file = input("Nhập tên file cần giải mã: ").strip()
            if not os.path.exists(input_file):
                print(f"✗ File '{input_file}' không tồn tại!")
                continue
                
            output_file = input("Nhập tên file đầu ra: ").strip()
            password = input("Nhập mật khẩu: ").strip()
            
            print("\nChọn variant 3DES đã sử dụng:")
            print("1. 3DES-EDE2")
            print("2. 3DES-EDE3")
            variant_choice = input("Chọn (1-2): ").strip()
            
            variant = "3DES-EDE2" if variant_choice == '1' else "3DES-EDE3"
            
            start_time = time.time()
            if decrypt_text_file(input_file, output_file, password, variant):
                end_time = time.time()
                print(f"✓ Thời gian giải mã: {end_time - start_time:.4f}s")
            
        elif choice == '3':
            performance_test()
            
        elif choice == '4':
            # Tạo file text mẫu
            sample_file = "sample_text_3des.txt"
            sample_content = """File text mẫu cho 3DES encryption test.
3DES (Triple DES) sử dụng DES 3 lần liên tiếp.
Có hai variant chính: EDE2 và EDE3.

3DES-EDE2: Encrypt-Decrypt-Encrypt với 2 key (K1-K2-K1)
3DES-EDE3: Encrypt-Decrypt-Encrypt với 3 key (K1-K2-K3)

Bảo mật hiệu quả: 112-bit (không phải 168-bit)
Tốc độ: Chậm hơn AES khoảng 3 lần
Ứng dụng: Hệ thống legacy, tương thích ngược

Khuyến nghị: Nâng cấp lên AES cho hệ thống mới.
Nội dung tiếng Việt có dấu để test UTF-8.
Số: 0123456789"""
            
            with open(sample_file, 'w', encoding='utf-8') as f:
                f.write(sample_content)
            print(f"✓ Đã tạo file mẫu: {sample_file}")
            
        elif choice == '5':
            print("Thoát chương trình 3DES!")
            break
        else:
            print("Lựa chọn không hợp lệ!")

if __name__ == "__main__":
    main()