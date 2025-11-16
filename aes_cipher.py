from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import time
import hashlib

class AESCipher:
    def __init__(self, key_size=32):  # 32 bytes = 256 bits
        # Khởi tạo với kích thước key, xác định block size
        self.key_size = key_size
        self.block_size = AES.block_size    # 16 bytes == 128 bits

    # Sinh key từ password hoặc ngẫu nhiên
    def generate_key(self, password=None):
        if password:
            return hashlib.sha256(password.encode()).digest()[:self.key_size]  # Tạo key từ password sử dụng SHA256
        else:
            return get_random_bytes(self.key_size)  # Tạo key ngẫu nhiên
    
    def encrypt_data(self, data, key):
        # Initialization Vector
        iv = get_random_bytes(self.block_size)
        
        # Tạo cipher object
        cipher = AES.new(key, AES.MODE_CBC, iv)  # các thành phần: khóa bí mật, chế độ CBC, và vector khởi tạo
        
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

# Đọc file text, mã hóa và ghi ra file nhị phân
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
    # Đo hiệu năng mã hóa/giải mã với dữ liệu 1MB cho các key size
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

def print_quick_summary(operation_type, key_size, input_size, output_size, elapsed_time):
    """In nhanh số liệu chính và so sánh các tùy chọn AES"""
    profiles = {
        16: {
            "name": "AES-128",
            "speed": "Nhanh nhất",
            "security": "Tốt (2^128)",
            "rounds": 10,
            "best_for": "Ứng dụng phổ thông, thiết bị hạn chế"
        },
        24: {
            "name": "AES-192",
            "speed": "Trung bình",
            "security": "Rất tốt (2^192)",
            "rounds": 12,
            "best_for": "Hệ thống doanh nghiệp cần cân bằng"
        },
        32: {
            "name": "AES-256",
            "speed": "Chậm hơn ≈20-40%",
            "security": "Xuất sắc (2^256)",
            "rounds": 14,
            "best_for": "Dữ liệu nhạy cảm, yêu cầu tối đa"
        }
    }

    print("\n" + "-" * 70)
    print(f"📈 TỔNG KẾT NHANH ({operation_type})")
    print("-" * 70)

    print(f"  • Dữ liệu đầu vào : {input_size:,} bytes ({input_size / 1024:.2f} KB)")
    print(f"  • Dữ liệu đầu ra  : {output_size:,} bytes ({output_size / 1024:.2f} KB)")

    if elapsed_time > 0:
        throughput = (input_size / 1024 / 1024) / elapsed_time if input_size else 0.0
        print(f"  • Thời gian xử lý: {elapsed_time:.4f} giây")
        print(f"  • Tốc độ trung bình: {throughput:.2f} MB/s")
    else:
        print(f"  • Thời gian xử lý: ≈0 giây (dữ liệu rất nhỏ hoặc đã được cache)")
        print("  • Tốc độ trung bình: Không đủ lớn để đo chính xác")

    print("\n🔍 So sánh ba biến thể AES:")
    print("  Thuật toán   | Tốc độ               | Bảo mật            | Vòng | Khuyến nghị sử dụng")
    print("  ------------ | -------------------- | ------------------ | ---- | --------------------")
    for size in (16, 24, 32):
        prefix = "👉" if size == key_size else "  "
        profile = profiles[size]
        print(
            f"{prefix} {profile['name']:<10} | {profile['speed']:<20} | {profile['security']:<16} | "
            f"{profile['rounds']:<4} | {profile['best_for']}"
        )

    print("\n✅ Chọn AES-{} đồng nghĩa với:".format(key_size * 8))
    if key_size == 16:
        print("  • Ưu điểm: Tốc độ cao nhất, tương thích rộng, dùng ít tài nguyên")
        print("  • Nhược điểm: Bảo mật thấp hơn AES-192/256 (nhưng vẫn rất an toàn)")
    elif key_size == 24:
        print("  • Ưu điểm: Cân bằng giữa tốc độ và bảo mật, ít ai khai thác")
        print("  • Nhược điểm: Không được tối ưu phần cứng nhiều như AES-128/256")
    else:
        print("  • Ưu điểm: Bảo mật tối đa, kháng phân tích lượng tử tốt hơn")
        print("  • Nhược điểm: Tốc độ chậm hơn, tốn tài nguyên hơn một chút")

    print("-" * 70)


def print_explanation(operation_type, key_size, file_size, elapsed_time, password_strength):
    """In giải thích chi tiết về kết quả mã hóa/giải mã"""
    print("\n" + "="*70)
    print("📊 BẢNG CHỈ SỐ ĐÁNH GIÁ VÀ PHÂN TÍCH KẾT QUẢ")
    print("="*70)
    
    # Thông tin cơ bản
    print(f"\n🔧 THÔNG SỐ ĐẦU VÀO:")
    print(f"  • Loại thao tác: {operation_type}")
    print(f"  • Key Size: {key_size} bytes = {key_size * 8} bits (AES-{key_size * 8})")
    print(f"  • Kích thước file: {file_size:,} bytes = {file_size / 1024:.2f} KB")
    print(f"  • Độ mạnh mật khẩu: {password_strength}")
    
    # Kết quả hiệu năng
    print(f"\n⚡ KẾT QUẢ HIỆU NĂNG:")
    print(f"  • Thời gian xử lý: {elapsed_time:.4f} giây")
    if elapsed_time > 0:
        throughput = (file_size / 1024 / 1024) / elapsed_time
        print(f"  • Tốc độ xử lý: {throughput:.2f} MB/s")
    print(f"  • Số block xử lý: {(file_size + 15) // 16} blocks (mỗi block 16 bytes)")
    
    # Giải thích ý nghĩa
    print(f"\n📖 GIẢI THÍCH CHI TIẾT:")
    print(f"\n  1️⃣  KEY SIZE (Kích thước khóa):")
    if key_size == 16:
        print(f"     → AES-128: Nhanh nhất, phù hợp cho dữ liệu thông thường")
        print(f"     → Độ bảo mật: Tốt (2^128 khả năng - an toàn với công nghệ hiện tại)")
        print(f"     → Số vòng mã hóa: 10 rounds")
    elif key_size == 24:
        print(f"     → AES-192: Cân bằng giữa tốc độ và bảo mật")
        print(f"     → Độ bảo mật: Rất tốt (2^192 khả năng)")
        print(f"     → Số vòng mã hóa: 12 rounds")
    else:  # 32
        print(f"     → AES-256: Bảo mật cao nhất, dùng cho dữ liệu nhạy cảm")
        print(f"     → Độ bảo mật: Xuất sắc (2^256 khả năng)")
        print(f"     → Số vòng mã hóa: 14 rounds")
    
    print(f"\n  2️⃣  MẬT KHẨU:")
    print(f"     → Mật khẩu được băm bằng SHA-256 trước khi tạo khóa")
    print(f"     → Cùng mật khẩu sẽ tạo ra cùng khóa mã hóa")
    print(f"     → Khuyến nghị: Dùng mật khẩu dài, phức tạp (>12 ký tự)")
    
    print(f"\n  3️⃣  THỜI GIAN XỬ LÝ:")
    if elapsed_time < 0.01:
        print(f"     → Rất nhanh! File nhỏ hoặc CPU mạnh")
    elif elapsed_time < 0.1:
        print(f"     → Tốt! Phù hợp cho hầu hết ứng dụng")
    elif elapsed_time < 1:
        print(f"     → Chấp nhận được cho file có kích thước trung bình")
    else:
        print(f"     → Mất thời gian! File lớn hoặc CPU yếu")
    
    print(f"\n  4️⃣  ẢNH HƯỞNG CỦA THAM SỐ:")
    print(f"     → Key size lớn hơn → Bảo mật cao hơn, chậm hơn một chút")
    print(f"     → File lớn hơn → Thời gian xử lý tăng tỷ lệ tuyến tính")
    print(f"     → Mật khẩu mạnh → Khó bị tấn công brute force hơn")
    print(f"     → Chế độ CBC → An toàn, mỗi block phụ thuộc block trước")
    
    print(f"\n  5️⃣  BẢO MẬT:")
    print(f"     → IV (Initialization Vector) được tạo ngẫu nhiên mỗi lần")
    print(f"     → Cùng nội dung + mật khẩu → Kết quả mã hóa khác nhau")
    print(f"     → Điều này ngăn chặn tấn công phân tích mẫu (pattern analysis)")
    
    print(f"\n  6️⃣  KẾT LUẬN CHI TIẾT VỀ KẾT QUẢ:")
    print(f"     📌 VỀ THUẬT TOÁN AES-{key_size * 8}:")
    if key_size == 16:
        print(f"        • AES-128 là lựa chọn CHUẨN cho hầu hết ứng dụng thương mại")
        print(f"        • Đủ mạnh để bảo vệ: Tài khoản ngân hàng, email, file cá nhân")
        print(f"        • Thời gian phá: >10^18 năm với máy tính hiện đại")
        print(f"        • Được sử dụng bởi: Google, Microsoft, Facebook")
        print(f"        • Tốc độ: Nhanh nhất trong 3 phiên bản AES")
    elif key_size == 24:
        print(f"        • AES-192 là lựa chọn CÂN BẰNG giữa bảo mật và hiệu năng")
        print(f"        • Phù hợp cho: Dữ liệu nhạy cảm của doanh nghiệp")
        print(f"        • Thời gian phá: >10^37 năm (con số khổng lồ)")
        print(f"        • Ít được dùng hơn AES-128 và AES-256")
        print(f"        • Tốc độ: Trung bình, chậm hơn AES-128 ~20%")
    else:  # 32
        print(f"        • AES-256 là lựa chọn CAO CẤP NHẤT, bảo mật tối đa")
        print(f"        • Bắt buộc cho: Dữ liệu mật cấp chính phủ, quân sự")
        print(f"        • Thời gian phá: >10^56 năm (nhiều hơn tuổi vũ trụ!)")
        print(f"        • Được NSA chứng nhận cho tài liệu TOP SECRET")
        print(f"        • Tốc độ: Chậm hơn AES-128 ~40% nhưng vẫn rất nhanh")
    
    print(f"\n     📌 ĐÁNH GIÁ KẾT QUẢ MÃ HÓA CỦA BẠN:")
    # Đánh giá về file size
    if file_size < 1024:  # < 1KB
        print(f"        • File rất nhỏ ({file_size} bytes) - Mã hóa gần như tức thì")
    elif file_size < 1024 * 1024:  # < 1MB
        print(f"        • File nhỏ ({file_size / 1024:.1f} KB) - Mã hóa rất nhanh")
    elif file_size < 10 * 1024 * 1024:  # < 10MB
        print(f"        • File trung bình ({file_size / (1024*1024):.1f} MB) - Mã hóa nhanh")
    else:
        print(f"        • File lớn ({file_size / (1024*1024):.1f} MB) - Cần thời gian xử lý")
    
    # Đánh giá về tốc độ
    if elapsed_time > 0:
        throughput = (file_size / 1024 / 1024) / elapsed_time
        print(f"        • Tốc độ đạt được: {throughput:.2f} MB/s")
        if throughput > 100:
            print(f"          → XUẤT SẮC! CPU của bạn hỗ trợ AES-NI (tăng tốc phần cứng)")
        elif throughput > 50:
            print(f"          → RẤT TỐT! Hiệu năng mã hóa cao")
        elif throughput > 20:
            print(f"          → TỐT! Hiệu năng chấp nhận được")
        else:
            print(f"          → CHẬM! CPU yếu hoặc đang chạy nhiều tác vụ")
    
    # Đánh giá về bảo mật
    print(f"\n     📌 MỨC ĐỘ BẢO MẬT ĐẠT ĐƯỢC:")
    print(f"        • Thuật toán: ⭐⭐⭐⭐⭐ (5/5) - AES là chuẩn vàng")
    
    if password_strength.startswith("Mạnh"):
        print(f"        • Mật khẩu: ⭐⭐⭐⭐⭐ (5/5) - Mật khẩu mạnh")
        print(f"          → File của bạn CỰC KỲ AN TOÀN!")
        print(f"          → Không thể phá được với công nghệ hiện tại")
    elif password_strength.startswith("Trung bình"):
        print(f"        • Mật khẩu: ⭐⭐⭐ (3/5) - Mật khẩu trung bình")
        print(f"          → File KHẤP KHỂNH AN TOÀN")
        print(f"          → Khuyến nghị: Dùng mật khẩu phức tạp hơn (>12 ký tự, hỗn hợp)")
    else:
        print(f"        • Mật khẩu: ⭐ (1/5) - Mật khẩu yếu")
        print(f"          → ⚠️  CẢNH BÁO: Dễ bị tấn công dictionary/brute force")
        print(f"          → KHUYẾN CÁO: Thay đổi mật khẩu ngay!")
    
    print(f"\n     📌 KHUYẾN NGHỊ SỬ DỤNG:")
    if operation_type == "MÃ HÓA":
        print(f"        ✅ LƯU Ý QUAN TRỌNG:")
        print(f"           1. Lưu mật khẩu ở nơi AN TOÀN (password manager)")
        print(f"           2. KHÔNG gửi mật khẩu qua email/tin nhắn thường")
        print(f"           3. File gốc vẫn tồn tại - XÓA AN TOÀN nếu cần")
        print(f"           4. Backup file mã hóa ở nhiều nơi")
        print(f"           5. Test giải mã NGAY sau khi mã hóa")
    else:  # GIẢI MÃ
        print(f"        ✅ HOÀN TẤT GIẢI MÃ:")
        print(f"           1. Kiểm tra nội dung file đã giải mã")
        print(f"           2. File mã hóa vẫn còn - Có thể xóa nếu không cần")
        print(f"           3. Bảo vệ file đã giải mã - Nó không còn mã hóa!")
    
    print(f"\n     📌 SO SÁNH VỚI CÁC TÌNH HUỐNG THỰC TẾ:")
    print(f"        • AES-{key_size * 8} được dùng để bảo vệ:")
    print(f"          → Kết nối HTTPS (duyệt web an toàn)")
    print(f"          → WhatsApp, Signal (mã hóa tin nhắn)")
    print(f"          → BitLocker, FileVault (mã hóa ổ đĩa)")
    print(f"          → VPN (bảo mật kết nối mạng)")
    print(f"        • File của bạn được bảo vệ ở MỨC ĐỘ TƯƠNG TỰ!")
    
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
    print("║" + " "*15 + "AES CIPHER - MÃ HÓA FILE TEXT" + " "*24 + "║")
    print("║" + " "*10 + "Hỗ trợ AES-128, AES-192, AES-256" + " "*26 + "║")
    print("╚" + "="*68 + "╝")
    
    while True:
        print("\n" + "┌" + "─"*68 + "┐")
        print("│" + " "*24 + "MENU CHÍNH" + " "*34 + "│")
        print("├" + "─"*68 + "┤")
        print("│  1. 🔒 Mã hóa file" + " "*49 + "│")
        print("│  2. 🔓 Giải mã file" + " "*48 + "│")
        print("│  3. 🚪 Thoát" + " "*55 + "│")
        print("└" + "─"*68 + "┘")
        
        choice = input("\n👉 Chọn chức năng (1-3): ").strip()
        
        if choice == '1':
            print("\n" + "="*70)
            print("🔒 CHỨC NĂNG MÃ HÓA FILE")
            print("="*70)
            
            # Nhập các tham số
            print("\n📝 Nhập các tham số đầu vào:")
            
            # Key size
            print("\n🔑 Chọn độ mạnh khóa (Key Size):")
            print("  1. AES-128 (16 bytes) - Nhanh, bảo mật tốt")
            print("  2. AES-192 (24 bytes) - Cân bằng")
            print("  3. AES-256 (32 bytes) - Bảo mật cao nhất (khuyến nghị)")
            key_choice = input("👉 Key Size (1-3, mặc định 3): ").strip()
            key_sizes = {'1': 16, '2': 24, '3': 32}
            key_size = key_sizes.get(key_choice, 32)
            
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
                output_file = input_file + ".encrypted"
                print(f"   → Sử dụng tên mặc định: {output_file}")
            
            # Mật khẩu
            password = input("🔐 Mật khẩu: ").strip()
            if not password:
                print("❌ Mật khẩu không được để trống!")
                continue
            
            password_strength = assess_password_strength(password)
            
            # Xác nhận
            print(f"\n✅ Xác nhận mã hóa:")
            print(f"   • Key: AES-{key_size * 8}")
            print(f"   • Input: {input_file} ({file_size:,} bytes)")
            print(f"   • Output: {output_file}")
            print(f"   • Độ mạnh mật khẩu: {password_strength}")
            
            confirm = input("\n⚠️  Tiếp tục? (y/n): ").strip().lower()
            if confirm != 'y':
                print("❌ Đã hủy thao tác!")
                continue
            
            # Thực hiện mã hóa
            print("\n⏳ Đang mã hóa...")
            start_time = time.time()
            
            cipher = AESCipher(key_size)
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
                print(f"   → Kích thước sau mã hóa (kèm IV): {len(iv + encrypted_data):,} bytes")
                
                # Tổng kết nhanh và phân tích chi tiết
                print_quick_summary("MÃ HÓA", key_size, file_size, len(iv + encrypted_data), elapsed_time)
                print_explanation("MÃ HÓA", key_size, file_size, elapsed_time, password_strength)
                
            except Exception as e:
                print(f"\n❌ Lỗi mã hóa: {e}")
            
        elif choice == '2':
            print("\n" + "="*70)
            print("🔓 CHỨC NĂNG GIẢI MÃ FILE")
            print("="*70)
            
            # Nhập các tham số
            print("\n📝 Nhập các tham số đầu vào:")
            
            # Key size
            print("\n🔑 Chọn độ mạnh khóa đã sử dụng khi mã hóa:")
            print("  1. AES-128 (16 bytes)")
            print("  2. AES-192 (24 bytes)")
            print("  3. AES-256 (32 bytes)")
            key_choice = input("👉 Key Size (1-3, mặc định 3): ").strip()
            key_sizes = {'1': 16, '2': 24, '3': 32}
            key_size = key_sizes.get(key_choice, 32)
            
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
            print(f"   • Key: AES-{key_size * 8}")
            print(f"   • Input: {input_file} ({file_size:,} bytes)")
            print(f"   • Output: {output_file}")
            
            confirm = input("\n⚠️  Tiếp tục? (y/n): ").strip().lower()
            if confirm != 'y':
                print("❌ Đã hủy thao tác!")
                continue
            
            # Thực hiện giải mã
            print("\n⏳ Đang giải mã...")
            start_time = time.time()
            
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
                
                elapsed_time = time.time() - start_time
                
                decrypted_size_bytes = len(decrypted_data)
                print(f"\n✅ Giải mã thành công!")
                print(f"   → File đầu ra: {output_file}")
                print(f"   → Kích thước văn bản: {len(text_data)} ký tự (~{decrypted_size_bytes:,} bytes)")
                
                # Tổng kết nhanh và phân tích chi tiết
                print_quick_summary("GIẢI MÃ", key_size, file_size, decrypted_size_bytes, elapsed_time)
                print_explanation("GIẢI MÃ", key_size, file_size, elapsed_time, password_strength)
                
            except Exception as e:
                print(f"\n❌ Lỗi giải mã: {e}")
                print(f"   → Có thể do: Sai mật khẩu, sai key size, hoặc file bị hỏng")
            
        elif choice == '3':
            print("\n👋 Cảm ơn bạn đã sử dụng AES Cipher!")
            print("🔒 Hãy bảo mật mật khẩu của bạn!")
            break
        else:
            print("\n❌ Lựa chọn không hợp lệ! Vui lòng chọn 1-3.")

if __name__ == "__main__":
    main()