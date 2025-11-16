from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import time
import hashlib

class TripleDESCipher:
    # Lớp mã hóa/giải mã Triple DES với 2 variant: EDE2 và EDE3
    def __init__(self, key_variant="3DES-EDE3"):
        # Khởi tạo với variant, xác định kích thước key
        self.key_variant = key_variant
        if key_variant == "3DES-EDE2": # 1 key cho giải mã và 1 key cho mã hóa
            self.key_size = 16  # 16 bytes = 128 bits
        else:  # 3DES-EDE3, 3 key cho 3 bước
            self.key_size = 24  # 24 bytes = 192 bits
        
        self.block_size = DES3.block_size  # 8 bytes
        
    def generate_key(self, password=None):
        # Sinh key từ password hoặc ngẫu nhiên, đảm bảo hợp lệ cho 3DES
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
                return key # Cho EDE3: sử dụng trực tiếp 24 bytes
        else:
            # Tạo key ngẫu nhiên
            if self.key_variant == "3DES-EDE2":
                k1 = get_random_bytes(8)
                k2 = get_random_bytes(8)
                return k1 + k2 + k1
            else:
                return get_random_bytes(self.key_size)
    
    def encrypt_data(self, data, key):
        # Tạo IV ngẫu nhiên
        iv = get_random_bytes(self.block_size)
        
        # Tạo cipher object
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        
        # Padding dữ liệu và mã hóa
        padded_data = pad(data, self.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        
        return encrypted_data, iv
    
    def decrypt_data(self, encrypted_data, key, iv):
        # Tạo cipher object
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        
        # Giải mã và unpad
        decrypted_padded = cipher.decrypt(encrypted_data)
        decrypted_data = unpad(decrypted_padded, self.block_size)
        
        return decrypted_data

def encrypt_text_file(input_file, output_file, password, variant="3DES-EDE3"):
    # Đọc file text, mã hóa và ghi ra file nhị phân
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
    # Đọc file mã hóa, giải mã và ghi ra file text
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
    # Đo hiệu năng mã hóa/giải mã với dữ liệu 1MB cho cả 2 variant
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

def print_explanation(operation_type, variant, file_size, elapsed_time, password_strength):
    """In giải thích chi tiết về kết quả mã hóa/giải mã 3DES"""
    print("\n" + "="*70)
    print("📊 BẢNG CHỈ SỐ ĐÁNH GIÁ VÀ PHÂN TÍCH KẾT QUẢ")
    print("="*70)
    
    key_size = 24 if variant == "3DES-EDE3" else 16
    effective_bits = 112  # 3DES luôn có 112-bit bảo mật hiệu quả
    
    # Thông tin cơ bản
    print(f"\n🔧 THÔNG SỐ ĐẦU VÀO:")
    print(f"  • Loại thao tác: {operation_type}")
    print(f"  • Thuật toán: {variant} (Triple DES)")
    print(f"  • Key Size: {key_size} bytes = {key_size * 8} bits")
    print(f"  • Độ bảo mật hiệu quả: {effective_bits} bits")
    print(f"  • Block Size: 8 bytes = 64 bits")
    print(f"  • Kích thước file: {file_size:,} bytes = {file_size / 1024:.2f} KB")
    print(f"  • Độ mạnh mật khẩu: {password_strength}")
    
    # Kết quả hiệu năng
    print(f"\n⚡ KẾT QUẢ HIỆU NĂNG:")
    print(f"  • Thời gian xử lý: {elapsed_time:.4f} giây")
    if elapsed_time > 0:
        throughput = (file_size / 1024 / 1024) / elapsed_time
        print(f"  • Tốc độ xử lý: {throughput:.2f} MB/s")
    print(f"  • Số block xử lý: {(file_size + 7) // 8} blocks (mỗi block 8 bytes)")
    print(f"  • Số vòng mã hóa: 48 rounds (16 rounds × 3 lần)")
    
    # Giải thích ý nghĩa
    print(f"\n📖 GIẢI THÍCH CHI TIẾT:")
    print(f"\n  1️⃣  THUẬT TOÁN 3DES:")
    print(f"     → Tên đầy đủ: Triple Data Encryption Algorithm")
    print(f"     → Nguyên lý: Áp dụng DES 3 lần liên tiếp (Encrypt-Decrypt-Encrypt)")
    print(f"     → Ra đời: 1998 (thay thế DES yếu)")
    print(f"     → Mục đích: Tăng độ bảo mật từ 56-bit lên 112-bit")
    
    print(f"\n  2️⃣  VARIANT: {variant}")
    if variant == "3DES-EDE2":
        print(f"     → Sử dụng 2 key: K1, K2, K1 (16 bytes = 128 bits)")
        print(f"     → Quá trình: E(K1) → D(K2) → E(K1)")
        print(f"     → K1 được dùng 2 lần (encrypt đầu và cuối)")
        print(f"     → Nhanh hơn EDE3 một chút")
        print(f"     → Độ bảo mật: 112 bits hiệu quả")
    else:  # 3DES-EDE3
        print(f"     → Sử dụng 3 key độc lập: K1, K2, K3 (24 bytes = 192 bits)")
        print(f"     → Quá trình: E(K1) → D(K2) → E(K3)")
        print(f"     → Mỗi key khác nhau hoàn toàn")
        print(f"     → An toàn hơn EDE2 (khuyến nghị)")
        print(f"     → Độ bảo mật: 112 bits hiệu quả (không phải 168 bits!)")
    
    print(f"\n  3️⃣  TẠI SAO 112-BIT CHỨ KHÔNG PHẢI 168-BIT?")
    print(f"     → Key dài 168 bits nhưng bị tấn công meet-in-the-middle")
    print(f"     → Tấn công này giảm độ phức tạp xuống 2^112")
    print(f"     → Do đó độ bảo mật thực tế chỉ 112 bits")
    print(f"     → Vẫn tốt hơn nhiều so với DES (56 bits)")
    
    print(f"\n  4️⃣  MẬT KHẨU:")
    print(f"     → Mật khẩu được băm bằng SHA-256 trước khi tạo key")
    print(f"     → Với EDE2: Lấy 16 bytes đầu, sắp xếp thành K1-K2-K1")
    print(f"     → Với EDE3: Lấy 24 bytes đầu làm K1-K2-K3")
    print(f"     → Cùng mật khẩu → Cùng key → Nên dùng mật khẩu mạnh")
    
    print(f"\n  5️⃣  HIỆU NĂNG:")
    if elapsed_time < 0.01:
        print(f"     → Rất nhanh cho file nhỏ!")
    elif elapsed_time < 0.1:
        print(f"     → Tốt! Chấp nhận được cho hầu hết ứng dụng")
    elif elapsed_time < 1:
        print(f"     → Chậm hơn AES do phải mã hóa 3 lần")
    else:
        print(f"     → Khá chậm! 3DES chậm hơn AES khoảng 3 lần")
    print(f"     → 3DES chậm vì: Block nhỏ (64-bit) + Phải encrypt 3 lần")
    
    print(f"\n  6️⃣  SO SÁNH VỚI CÁC THUẬT TOÁN KHÁC:")
    print(f"     ┌─────────────┬────────────┬──────────────┬─────────────┐")
    print(f"     │ Thuật toán  │ Key Size   │ Độ bảo mật   │ Tốc độ     │")
    print(f"     ├─────────────┼────────────┼──────────────┼─────────────┤")
    print(f"     │ DES         │ 56-bit     │ ❌ Rất yếu   │ Nhanh      │")
    print(f"     │ 3DES-EDE2   │ 112-bit    │ ⚠️  TB       │ Chậm       │")
    print(f"     │ 3DES-EDE3   │ 112-bit    │ ⚠️  TB+      │ Chậm       │")
    print(f"     │ AES-128     │ 128-bit    │ ✅ Tốt       │ Rất nhanh  │")
    print(f"     │ AES-256     │ 256-bit    │ ✅ Xuất sắc  │ Rất nhanh  │")
    print(f"     └─────────────┴────────────┴──────────────┴─────────────┘")
    
    print(f"\n  7️⃣  ẢNH HƯỞNG CỦA THAM SỐ:")
    print(f"     → Variant EDE3 an toàn hơn EDE2 nhưng không khác biệt nhiều")
    print(f"     → File lớn hơn → Thời gian tăng tuyến tính")
    print(f"     → Mật khẩu mạnh → Khó bị tấn công dictionary/brute force")
    print(f"     → Chế độ CBC → An toàn, mỗi block phụ thuộc block trước")
    
    print(f"\n  8️⃣  BẢO MẬT VÀ KHUYẾN NGHỊ:")
    print(f"     → 3DES đã bị NIST đưa vào danh sách deprecate (2017)")
    print(f"     → Dự kiến ngừng hỗ trợ hoàn toàn vào 2023-2024")
    print(f"     → Chỉ nên dùng cho: Tương thích với hệ thống cũ")
    print(f"     → ✅ KHUYẾN NGHỊ: Nâng cấp lên AES-256 nếu có thể")
    print(f"     → Block size nhỏ (64-bit) có thể bị tấn công với dữ liệu lớn")
    
    print(f"\n  9️⃣  KẾT LUẬN CHI TIẾT VỀ KẾT QUẢ:")
    print(f"     📌 VỀ THUẬT TOÁN {variant}:")
    print(f"        • 3DES là 'GIA CỐ' của DES yếu kém")
    print(f"        • Nguyên lý: Mã hóa 3 lần để tăng độ an toàn")
    print(f"        • Ra đời 1998 như giải pháp TẠM THỜI thay DES")
    print(f"        • Độ bảo mật: 112-bit (gấp 65,536 lần DES)")
    print(f"        • Trạng thái hiện tại: DEPRECATED (đã lỗi thời)")
    
    if variant == "3DES-EDE2":
        print(f"        ")
        print(f"        🔹 Về variant EDE2 bạn đang dùng:")
        print(f"           • Dùng 2 key (K1, K2) - K1 lặp lại 2 lần")
        print(f"           • Nhanh hơn EDE3 khoảng 10-15%")
        print(f"           • Ít an toàn hơn EDE3 một chút")
        print(f"           • Phù hợp khi cần tương thích với hệ thống cũ")
    else:
        print(f"        ")
        print(f"        🔹 Về variant EDE3 bạn đang dùng:")
        print(f"           • Dùng 3 key độc lập (K1, K2, K3)")
        print(f"           • An toàn hơn EDE2 (khuyến nghị hơn)")
        print(f"           • Được chuẩn hóa rộng rãi hơn")
        print(f"           • Đây là LỰA CHỌN TỐT NHẤT trong 3DES")
    
    print(f"\n     📌 ĐÁNH GIÁ KẾT QUẢ MÃ HÓA CỦA BẠN:")
    # Đánh giá hiệu năng
    if elapsed_time > 0:
        throughput = (file_size / 1024 / 1024) / elapsed_time
        print(f"        • Tốc độ đạt được: {throughput:.2f} MB/s")
        if throughput > 30:
            print(f"          → TỐT! Hiệu năng chấp nhận được")
        elif throughput > 15:
            print(f"          → TRUNG BÌNH! 3DES chậm hơn AES đáng kể")
        else:
            print(f"          → CHẬM! 3DES thực sự chậm so với AES")
        
        # So sánh với AES
        estimated_aes_speed = throughput * 3  # AES nhanh gấp ~3 lần
        print(f"          → Nếu dùng AES: Ước tính ~{estimated_aes_speed:.1f} MB/s (nhanh gấp 3 lần)")
    
    # Kích thước file
    if file_size < 1024:
        print(f"        • File: {file_size} bytes - Rất nhỏ, phù hợp với 3DES")
    elif file_size < 1024 * 1024:
        print(f"        • File: {file_size / 1024:.1f} KB - Kích thước OK")
    elif file_size < 10 * 1024 * 1024:
        print(f"        • File: {file_size / (1024*1024):.1f} MB - Hơi lớn, nên dùng AES")
    else:
        print(f"        • File: {file_size / (1024*1024):.1f} MB - Quá lớn, KHUYẾN NGHỊ dùng AES!")
    
    print(f"\n     📌 MỨC ĐỘ BẢO MẬT ĐẠT ĐƯỢC:")
    print(f"        • Thuật toán: ⭐⭐⭐ (3/5) - 3DES là trung bình khá")
    print(f"          → Độ bảo mật: 112-bit")
    print(f"          → Thời gian phá: ~2^112 phép tính")
    print(f"          → Ước tính: Hàng NGHÌN NĂM với công nghệ hiện tại")
    print(f"          → Nhưng: Block 64-bit có thể bị tấn công với >32GB dữ liệu")
    
    if password_strength.startswith("Mạnh"):
        print(f"        • Mật khẩu: ⭐⭐⭐⭐⭐ (5/5) - Mật khẩu mạnh")
        print(f"          → KẾT HỢP: Bảo mật KHẤP KHỂNH TỐT")
        print(f"          → File của bạn TƯƠNG ĐỐI AN TOÀN")
        print(f"          → Nhưng vẫn NÊN NÂNG CẤP lên AES")
    elif password_strength.startswith("Trung bình"):
        print(f"        • Mật khẩu: ⭐⭐⭐ (3/5) - Mật khẩu trung bình")
        print(f"          → KẾT HỢP: Bảo mật TRUNG BÌNH")
        print(f"          → Nên dùng mật khẩu mạnh hơn")
    else:
        print(f"        • Mật khẩu: ⭐ (1/5) - Mật khẩu yếu")
        print(f"          → KẾT HỢP: Bảo mật YẾU")
        print(f"          → ⚠️  CẢNH BÁO: Dễ bị tấn công dictionary")
    
    print(f"\n     📌 SO SÁNH 3DES VỚI CÁC LỰA CHỌN KHÁC:")
    print(f"        ┌────────────┬──────────┬────────────┬──────────┬─────────────┐")
    print(f"        │ Thuật toán │ Bảo mật  │ Tốc độ    │ Khuyến   │ Sử dụng    │")
    print(f"        │            │ (bit)    │ (tương đối)│ nghị     │            │")
    print(f"        ├────────────┼──────────┼────────────┼──────────┼─────────────┤")
    print(f"        │ DES        │ 56       │ Nhanh     │ ❌ Không │ Lỗi thời   │")
    print(f"        │ 3DES-EDE2  │ 112      │ Chậm      │ ⚠️  Tạm  │ Legacy     │")
    print(f"        │ 3DES-EDE3  │ 112      │ Chậm      │ ⚠️  Tạm  │ Legacy     │")
    print(f"        │ AES-128    │ 128      │ Rất nhanh │ ✅ Tốt   │ Chuẩn      │")
    print(f"        │ AES-256    │ 256      │ Rất nhanh │ ✅ Tốt   │ Khuyến cáo │")
    print(f"        └────────────┴──────────┴────────────┴──────────┴─────────────┘")
    
    print(f"\n     📌 TẠI SAO NÊN NÂNG CẤP LÊN AES:")
    print(f"        1️⃣  TỐC ĐỘ:")
    print(f"           • AES nhanh hơn 3DES gấp 2-3 lần")
    print(f"           • AES có hỗ trợ phần cứng (AES-NI) → Nhanh hơn 5-10 lần")
    print(f"           • 3DES chậm vì phải mã hóa 3 lần")
    
    print(f"        2️⃣  BẢO MẬT:")
    print(f"           • AES-128: 128-bit > 3DES: 112-bit")
    print(f"           • AES-256: 256-bit >> 3DES rất nhiều")
    print(f"           • AES block 128-bit > 3DES block 64-bit")
    print(f"           • 3DES có giới hạn 32GB dữ liệu (birthday attack)")
    
    print(f"        3️⃣  TƯƠNG LAI:")
    print(f"           • 3DES bị NIST ngưng khuyến nghị từ 2017")
    print(f"           • Nhiều tiêu chuẩn (PCI-DSS) cấm 3DES từ 2023")
    print(f"           • Các trình duyệt ngừng hỗ trợ 3DES")
    print(f"           • AES là chuẩn hiện tại và tương lai")
    
    print(f"\n     📌 HÀNH ĐỘNG KHUYẾN NGHỊ:")
    if operation_type == "MÃ HÓA":
        print(f"        ✅ BẠN VỪA MÃ HÓA VỚI 3DES - TẠM CHẤP NHẬN")
        print(f"        ")
        print(f"        💡 KHUYẾN NGHỊ:")
        print(f"           • Nếu có thể: MÃ HÓA LẠI bằng AES-256")
        print(f"           • File nhỏ (<100MB): 3DES tạm ổn")
        print(f"           • File lớn (>100MB): NÊN dùng AES")
        print(f"           • Dữ liệu rất quan trọng: BẮT BUỘC dùng AES-256")
        print(f"           • Chỉ dùng 3DES nếu: Phải tương thích hệ thống cũ")
        print(f"        ")
        print(f"        📝 Cách chuyển sang AES:")
        print(f"           1. Giải mã file 3DES này")
        print(f"           2. Chạy aes_cipher.py")
        print(f"           3. Chọn AES-256")
        print(f"           4. Mã hóa với cùng/khác mật khẩu")
    else:  # GIẢI MÃ
        print(f"        ✅ BẠN VỪA GIẢI MÃ FILE 3DES THÀNH CÔNG")
        print(f"        ")
        print(f"        💡 KHUYẾN NGHỊ TIẾP THEO:")
        print(f"           • Nếu cần mã hóa lại: Dùng AES-256")
        print(f"           • Kiểm tra nội dung file đã giải mã")
        print(f"           • Xóa file 3DES nếu không cần")
        print(f"           • Backup file quan trọng")
    
    print(f"\n     📌 TÌNH HUỐNG SỬ DỤNG 3DES:")
    print(f"        ✅ PHÙ HỢP KHI:")
    print(f"           • Tương thích với hệ thống legacy cũ")
    print(f"           • Không thể nâng cấp lên AES")
    print(f"           • Quy định buộc phải dùng 3DES")
    print(f"           • Dữ liệu nhỏ (<1GB) và không quá nhạy cảm")
    print(f"        ")
    print(f"        ❌ KHÔNG PHÙ HỢP KHI:")
    print(f"           • Dữ liệu rất quan trọng/nhạy cảm")
    print(f"           • File lớn (>10GB)")
    print(f"           • Cần hiệu năng cao")
    print(f"           • Xây dựng hệ thống mới")
    
    print(f"\n     📌 KẾT LUẬN CUỐI CÙNG:")
    if password_strength.startswith("Mạnh"):
        conclusion = "KHẤP KHỂNH TỐT"
        emoji = "👍"
    else:
        conclusion = "TRUNG BÌNH"
        emoji = "⚠️"
    
    print(f"        {emoji} Mức độ bảo mật tổng thể: {conclusion}")
    print(f"        • 3DES vẫn còn TẠM AN TOÀN cho mục đích học tập")
    print(f"        • Nhưng ĐÃ LỖI THỜI và nên nâng cấp lên AES")
    print(f"        • File của bạn: {'An toàn tạm thời' if password_strength.startswith('Mạnh') else 'Cần cải thiện'}")
    print(f"        ")
    print(f"        🎯 KHUYẾN CÁO CUỐI: Chuyển sang AES-256 càng sớm càng tốt!")
    
    print("="*70 + "\n")

def assess_password_strength(password):
    """Đánh giá độ mạnh của mật khẩu"""
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    score = sum([length >= 8, length >= 12, has_upper, has_lower, has_digit, has_special])
    
    if score >= 5:
        return "Mạnh (Strong) ✓"
    elif score >= 3:
        return "Trung bình (Medium) ⚠"
    else:
        return "Yếu (Weak) ✗"

def main():
    print("╔" + "="*68 + "╗")
    print("║" + " "*13 + "3DES CIPHER - MÃ HÓA FILE TEXT" + " "*25 + "║")
    print("║" + " "*8 + "Hỗ trợ 3DES-EDE2 và 3DES-EDE3 (112-bit)" + " "*21 + "║")
    print("╚" + "="*68 + "╝")
    
    while True:
        print("\n" + "┌" + "─"*68 + "┐")
        print("│" + " "*25 + "MENU CHÍNH" + " "*33 + "│")
        print("├" + "─"*68 + "┤")
        print("│  1. 🔒 Mã hóa file" + " "*49 + "│")
        print("│  2. 🔓 Giải mã file" + " "*48 + "│")
        print("│  3. 🚪 Thoát" + " "*55 + "│")
        print("└" + "─"*68 + "┘")
        
        choice = input("\n👉 Chọn chức năng (1-3): ").strip()
        
        if choice == '1':
            print("\n" + "="*70)
            print("🔒 CHỨC NĂNG MÃ HÓA FILE - 3DES")
            print("="*70)
            
            # Nhập các tham số
            print("\n📝 Nhập các tham số đầu vào:")
            
            # Chọn variant
            print("\n🔑 Chọn variant 3DES:")
            print("  1. 3DES-EDE2 (2 key, nhanh hơn)")
            print("  2. 3DES-EDE3 (3 key, an toàn hơn - khuyến nghị)")
            variant_choice = input("👉 Variant (1-2, mặc định 2): ").strip()
            variant = "3DES-EDE2" if variant_choice == '1' else "3DES-EDE3"
            
            # File đầu vào
            input_file = input("\n📄 Tên file đầu vào: ").strip()
            if not os.path.exists(input_file):
                print(f"❌ File '{input_file}' không tồn tại!")
                continue
            
            # Lấy kích thước file
            file_size = os.path.getsize(input_file)
            
            # File đầu ra
            output_file = input("📁 Tên file đầu ra: ").strip()
            if not output_file:
                output_file = input_file + ".3des.encrypted"
                print(f"   → Sử dụng tên mặc định: {output_file}")
            
            # Mật khẩu
            password = input("🔐 Mật khẩu: ").strip()
            if not password:
                print("❌ Mật khẩu không được để trống!")
                continue
            
            password_strength = assess_password_strength(password)
            
            # Xác nhận
            print(f"\n✅ Xác nhận mã hóa:")
            print(f"   • Variant: {variant}")
            print(f"   • Input: {input_file} ({file_size:,} bytes)")
            print(f"   • Output: {output_file}")
            print(f"   • Độ mạnh mật khẩu: {password_strength}")
            
            # Thực hiện mã hóa
            print("\n⏳ Đang mã hóa...")
            start_time = time.time()
            
            cipher = TripleDESCipher(variant)
            key = cipher.generate_key(password)
            
            try:
                with open(input_file, 'r', encoding='utf-8') as f:
                    text_data = f.read()
                
                data_bytes = text_data.encode('utf-8')
                encrypted_data, iv = cipher.encrypt_data(data_bytes, key)
                
                with open(output_file, 'wb') as f:
                    f.write(iv + encrypted_data)
                
                elapsed_time = time.time() - start_time
                
                print(f"\n✅ Mã hóa thành công!")
                print(f"   → File đầu ra: {output_file}")
                print(f"   → Kích thước: {len(iv + encrypted_data):,} bytes")
                
                # In bảng phân tích
                print_explanation("MÃ HÓA", variant, file_size, elapsed_time, password_strength)
                
            except Exception as e:
                print(f"\n❌ Lỗi mã hóa: {e}")
            
        elif choice == '2':
            print("\n" + "="*70)
            print("🔓 CHỨC NĂNG GIẢI MÃ FILE - 3DES")
            print("="*70)
            
            # Nhập các tham số
            print("\n📝 Nhập các tham số đầu vào:")
            
            # Chọn variant
            print("\n🔑 Chọn variant 3DES đã sử dụng khi mã hóa:")
            print("  1. 3DES-EDE2")
            print("  2. 3DES-EDE3")
            variant_choice = input("👉 Variant (1-2, mặc định 2): ").strip()
            variant = "3DES-EDE2" if variant_choice == '1' else "3DES-EDE3"
            
            # File đầu vào
            input_file = input("\n📄 Tên file đầu vào (file đã mã hóa): ").strip()
            if not os.path.exists(input_file):
                print(f"❌ File '{input_file}' không tồn tại!")
                continue
            
            # Lấy kích thước file
            file_size = os.path.getsize(input_file)
            
            # File đầu ra
            output_file = input("📁 Tên file đầu ra: ").strip()
            if not output_file:
                output_file = input_file + ".decrypted"
                print(f"   → Sử dụng tên mặc định: {output_file}")
            
            # Mật khẩu
            password = input("🔐 Mật khẩu: ").strip()
            if not password:
                print("❌ Mật khẩu không được để trống!")
                continue
            
            password_strength = assess_password_strength(password)
            
            # Xác nhận
            print(f"\n✅ Xác nhận giải mã:")
            print(f"   • Variant: {variant}")
            print(f"   • Input: {input_file} ({file_size:,} bytes)")
            print(f"   • Output: {output_file}")
            
            # Thực hiện giải mã
            print("\n⏳ Đang giải mã...")
            start_time = time.time()
            
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
                
                elapsed_time = time.time() - start_time
                
                print(f"\n✅ Giải mã thành công!")
                print(f"   → File đầu ra: {output_file}")
                print(f"   → Kích thước: {len(text_data)} ký tự")
                
                # In bảng phân tích
                print_explanation("GIẢI MÃ", variant, file_size, elapsed_time, password_strength)
                
            except Exception as e:
                print(f"\n❌ Lỗi giải mã: {e}")
                print(f"   → Có thể do: Sai mật khẩu, sai variant, hoặc file bị hỏng")
            
        elif choice == '3':
            print("\n👋 Cảm ơn bạn đã sử dụng 3DES Cipher!")
            print("💡 Khuyến nghị: Nâng cấp lên AES cho bảo mật tốt hơn!")
            break
        else:
            print("\n❌ Lựa chọn không hợp lệ! Vui lòng chọn 1-3.")

if __name__ == "__main__":
    main()