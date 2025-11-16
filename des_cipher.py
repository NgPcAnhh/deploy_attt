from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import time
import hashlib

class DESCipher:
    # Lớp mã hóa/giải mã DES (bảo mật thấp)
    def __init__(self):
        # Khởi tạo, xác định kích thước key và block
        self.key_size = 8  # 8 bytes = 64 bits
        self.block_size = DES.block_size  # 8 bytes
        
    def generate_key(self, password=None):
        # Sinh key từ password hoặc ngẫu nhiên
            if password:
                hash_key = hashlib.sha256(password.encode()).digest() # mã hóa password bằng SHA256
                return hash_key[:self.key_size] # Lấy 8 byte đầu làm key DES
            else:
                return get_random_bytes(self.key_size)
            
    def encrypt_data(self, data, key):
        # Initialization Vector
        iv = get_random_bytes(self.block_size)

        # Khởi tạo đối tượng DES với key và IV ở chế độ CBC
        cipher = DES.new(key, DES.MODE_CBC, iv)

        # Thêm padding vào dữ liệu để đủ block size
        padded_data = pad(data, self.block_size)

        # Mã hóa dữ liệu đã padding
        encrypted_data = cipher.encrypt(padded_data)

        # Trả về dữ liệu đã mã hóa và IV để dùng khi giải mã
        return encrypted_data, iv
    
    def decrypt_data(self, encrypted_data, key, iv):
        # Khởi tạo đối tượng DES với key và IV ở chế độ CBC
        cipher = DES.new(key, DES.MODE_CBC, iv)

        # Giải mã dữ liệu
        decrypted_padded = cipher.decrypt(encrypted_data)

        # Loại bỏ padding để lấy dữ liệu gốc
        decrypted_data = unpad(decrypted_padded, self.block_size)

        # Trả về dữ liệu gốc
        return decrypted_data

def encrypt_text_file(input_file, output_file, password):
    # Đọc nội dung file text, mã hóa bằng DES và ghi ra file nhị phân
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
    # Đọc file mã hóa, giải mã và ghi ra file text
    # Đọc file mã hóa, giải mã bằng DES và ghi ra file text
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
    # Đo hiệu năng mã hóa/giải mã với dữ liệu 1MB
    # Đo hiệu năng mã hóa/giải mã với dữ liệu 1MB
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

def print_explanation(operation_type, file_size, elapsed_time, password_strength):
    """In giải thích chi tiết về kết quả mã hóa/giải mã DES"""
    print("\n" + "="*70)
    print("📊 BẢNG CHỈ SỐ ĐÁNH GIÁ VÀ PHÂN TÍCH KẾT QUẢ")
    print("="*70)
    
    # Thông tin cơ bản
    print(f"\n🔧 THÔNG SỐ ĐẦU VÀO:")
    print(f"  • Loại thao tác: {operation_type}")
    print(f"  • Thuật toán: DES (Data Encryption Standard)")
    print(f"  • Key Size: 8 bytes = 64 bits (56 bits hiệu quả)")
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
    print(f"  • Số vòng mã hóa: 16 rounds")
    
    # Giải thích ý nghĩa
    print(f"\n📖 GIẢI THÍCH CHI TIẾT:")
    print(f"\n  1️⃣  THUẬT TOÁN DES:")
    print(f"     → Ra đời: 1977, chuẩn hóa bởi NIST")
    print(f"     → Key size: 64 bits nhưng chỉ 56 bits hiệu quả (8 bits parity)")
    print(f"     → Block size: 64 bits (nhỏ hơn AES - 128 bits)")
    print(f"     → Số vòng: 16 rounds Feistel cipher")
    
    print(f"\n  2️⃣  BẢO MẬT DES:")
    print(f"     ⚠️  CẢNH BÁO: DES ĐÃ LỖI THỜI!")
    print(f"     → Key quá ngắn (56-bit) → Dễ bị brute force attack")
    print(f"     → Năm 1998: DES bị phá trong 56 giờ (Deep Crack)")
    print(f"     → Năm 2008: DES bị phá trong vài giây (COPACOBANA)")
    print(f"     → Hiện tại: Không còn an toàn cho bất kỳ mục đích nào")
    print(f"     → Khuyến nghị: CHỈ dùng cho mục đích học tập!")
    
    print(f"\n  3️⃣  MẬT KHẨU:")
    print(f"     → Mật khẩu được băm bằng SHA-256 → Lấy 8 bytes đầu")
    print(f"     → Dù mật khẩu mạnh, key DES vẫn chỉ 56-bit hiệu quả")
    print(f"     → Mật khẩu tốt không thể bù đắp cho độ yếu của DES")
    
    print(f"\n  4️⃣  HIỆU NĂNG:")
    if elapsed_time < 0.01:
        print(f"     → Nhanh! DES có tốc độ tốt nhờ block size nhỏ")
    elif elapsed_time < 0.1:
        print(f"     → Tốt! Phù hợp cho file kích thước nhỏ/trung bình")
    else:
        print(f"     → Chậm hơn dự kiến cho file lớn")
    print(f"     → So với AES: DES nhanh hơn nhưng kém bảo mật nhiều")
    
    print(f"\n  5️⃣  TẠI SAO DES YẾU:")
    print(f"     → 2^56 = 72 triệu tỷ khả năng (nghe có vẻ nhiều)")
    print(f"     → Nhưng máy tính hiện đại có thể thử hết trong vài giờ/ngày")
    print(f"     → GPU/ASIC hiện đại: Có thể phá trong vài phút!")
    print(f"     → So sánh: AES-128 có 2^128 khả năng (gấp 10^21 lần)")
    
    print(f"\n  6️⃣  KHUYẾN NGHỊ:")
    print(f"     ❌ KHÔNG dùng DES cho dữ liệu thật")
    print(f"     ❌ KHÔNG dùng DES trong sản phẩm thương mại")
    print(f"     ✅ CHỈ dùng để học thuật toán mã hóa")
    print(f"     ✅ Nên nâng cấp lên AES-256 hoặc ít nhất 3DES")
    
    print(f"\n  7️⃣  KẾT LUẬN CHI TIẾT VỀ KẾT QUẢ:")
    print(f"     📌 VỀ THUẬT TOÁN DES:")
    print(f"        • DES là thuật toán LỊCH SỬ (1977-1998)")
    print(f"        • Từng là chuẩn mã hóa của chính phủ Mỹ")
    print(f"        • Năm 1998: Chính thức BỊ PHÁ (56 giờ với Deep Crack)")
    print(f"        • Năm 2008: Bị phá trong VÀI GIÂY với COPACOBANA")
    print(f"        • Hiện tại: Máy tính cá nhân có thể phá trong VÀI NGÀY")
    print(f"        • Trạng thái: ĐÃ LỖI THỜI - Không còn an toàn")
    
    print(f"\n     📌 ĐÁNH GIÁ KẾT QUẢ MÃ HÓA CỦA BẠN:")
    # Đánh giá về hiệu năng
    if elapsed_time > 0:
        throughput = (file_size / 1024 / 1024) / elapsed_time
        print(f"        • Tốc độ: {throughput:.2f} MB/s")
        if throughput > 50:
            print(f"          → Nhanh! DES có tốc độ tốt nhờ thuật toán đơn giản")
        elif throughput > 20:
            print(f"          → Tốt! Hiệu năng chấp nhận được")
        else:
            print(f"          → Chậm hơn dự kiến")
    
    # Kích thước file
    if file_size < 1024:
        print(f"        • File: {file_size} bytes - Rất nhỏ")
    elif file_size < 1024 * 1024:
        print(f"        • File: {file_size / 1024:.1f} KB - File nhỏ")
    else:
        print(f"        • File: {file_size / (1024*1024):.1f} MB - File lớn")
    
    print(f"\n     📌 MỨC ĐỘ BẢO MẬT ĐẠT ĐƯỢC:")
    print(f"        • Thuật toán: ⭐ (1/5) - DES CỰC KỲ YẾU!")
    print(f"          → Key chỉ 56-bit → 72,057,594,037,927,936 (2^56) khả năng")
    print(f"          → Nghe nhiều nhưng máy tính có thể thử HẾT trong vài ngày")
    print(f"          → GPU hiện đại: Có thể phá trong VÀI PHÚT đến VÀI GIỜ")
    
    if password_strength.startswith("Mạnh"):
        print(f"        • Mật khẩu: ⭐⭐⭐⭐⭐ (5/5) - Mật khẩu mạnh")
        print(f"          → Nhưng KHÔNG GIÚP ÍCH GÌ vì DES quá yếu!")
    elif password_strength.startswith("Trung bình"):
        print(f"        • Mật khẩu: ⭐⭐⭐ (3/5) - Mật khẩu trung bình")
        print(f"          → Vẫn không cứu được DES yếu kém")
    else:
        print(f"        • Mật khẩu: ⭐ (1/5) - Mật khẩu yếu")
        print(f"          → Càng tệ hơn khi kết hợp với DES yếu!")
    
    print(f"\n        🚨 KẾT LUẬN CHUNG: FILE KHÔNG AN TOÀN! 🚨")
    print(f"        • Bảo mật tổng thể: ⭐ (1/5)")
    print(f"        • File có thể bị PHÁ trong: VÀI GIỜ đến VÀI NGÀY")
    print(f"        • Chi phí phá: Dưới $100 (thuê cloud GPU)")
    
    print(f"\n     📌 SO SÁNH VỚI CÁC THUẬT TOÁN KHÁC:")
    print(f"        ┌──────────────┬─────────────┬──────────────────────────────┐")
    print(f"        │ Thuật toán   │ Thời gian   │ Mức độ an toàn              │")
    print(f"        │              │ phá (ước)   │                             │")
    print(f"        ├──────────────┼─────────────┼──────────────────────────────┤")
    print(f"        │ DES          │ Vài giờ     │ ❌ KHÔNG AN TOÀN             │")
    print(f"        │ 3DES         │ >1000 năm   │ ⚠️  Tạm chấp nhận           │")
    print(f"        │ AES-128      │ >10^18 năm  │ ✅ An toàn                  │")
    print(f"        │ AES-256      │ >10^56 năm  │ ✅ Cực kỳ an toàn          │")
    print(f"        └──────────────┴─────────────┴──────────────────────────────┘")
    
    print(f"\n     📌 TẠI SAO BẠN NÊN CHUYỂN SANG AES:")
    print(f"        1️⃣  AES NHANH HƠN DES (có hỗ trợ phần cứng AES-NI)")
    print(f"        2️⃣  AES AN TOÀN HƠN 2^72 LẦN (AES-128 vs DES)")
    print(f"        3️⃣  AES là CHUẨN QUỐC TẾ hiện tại")
    print(f"        4️⃣  DES đã bị CẤM trong nhiều tiêu chuẩn bảo mật")
    print(f"        5️⃣  Chuyển sang AES MIỄN PHÍ và DỄ DÀNG")
    
    print(f"\n     📌 HÀNH ĐỘNG KHUYẾN NGHỊ:")
    if operation_type == "MÃ HÓA":
        print(f"        ⚠️  BẠN VỪA MÃ HÓA VỚI DES - KHÔNG AN TOÀN!")
        print(f"        🔄 KHUYẾN CÁO MẠNH MẼ:")
        print(f"           1. MÃ HÓA LẠI file này bằng AES-256 NGAY!")
        print(f"           2. KHÔNG dùng file DES này cho dữ liệu quan trọng")
        print(f"           3. CHỈ dùng DES để HỌC TẬP thuật toán")
        print(f"           4. XÓA file DES sau khi học xong")
        print(f"        ")
        print(f"        📝 Cách chuyển sang AES:")
        print(f"           • Giải mã file DES này")
        print(f"           • Chạy aes_cipher.py")
        print(f"           • Mã hóa lại với AES-256")
    else:  # GIẢI MÃ
        print(f"        ✅ BẠN VỪA GIẢI MÃ FILE DES")
        print(f"        🔄 KHUYẾN NGHỊ TIẾP THEO:")
        print(f"           1. MÃ HÓA LẠI bằng AES-256 nếu cần bảo vệ")
        print(f"           2. KHÔNG tiếp tục dùng DES")
        print(f"           3. XÓA file DES cũ (không còn cần)")
    
    print(f"\n     📌 KẾT LUẬN CUỐI CÙNG:")
    print(f"        ⚠️  DES CHỈ PHÙ HỢP CHO:")
    print(f"           • Học tập về mã hóa cổ điển")
    print(f"           • Hiểu lịch sử phát triển mã hóa")
    print(f"           • So sánh với thuật toán hiện đại")
    print(f"        ")
    print(f"        ❌ DES KHÔNG PHÙ HỢP CHO:")
    print(f"           • Bảo vệ bất kỳ dữ liệu nào có giá trị")
    print(f"           • Sử dụng trong sản phẩm thật")
    print(f"           • Tin tưởng vào tính bảo mật")
    
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
    print("║" + " "*15 + "DES CIPHER - MÃ HÓA FILE TEXT" + " "*24 + "║")
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
            print("🔒 CHỨC NĂNG MÃ HÓA FILE - DES")
            print("="*70)
            
            # Nhập các tham số
            print("\n📝 Nhập các tham số đầu vào:")
            
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
                output_file = input_file + ".des.encrypted"
                print(f"   → Sử dụng tên mặc định: {output_file}")
            
            # Mật khẩu
            password = input("🔐 Mật khẩu: ").strip()
            if not password:
                print("❌ Mật khẩu không được để trống!")
                continue
            
            password_strength = assess_password_strength(password)
            
            # Xác nhận
            print(f"\n✅ Xác nhận mã hóa:")
            print(f"   • Thuật toán: DES (56-bit)")
            print(f"   • Input: {input_file} ({file_size:,} bytes)")
            print(f"   • Output: {output_file}")
            print(f"   • Độ mạnh mật khẩu: {password_strength}")
            
            # Thực hiện mã hóa
            print("\n⏳ Đang mã hóa...")
            start_time = time.time()
            
            cipher = DESCipher()
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
                print_explanation("MÃ HÓA", file_size, elapsed_time, password_strength)
                
            except Exception as e:
                print(f"\n❌ Lỗi mã hóa: {e}")
            
        elif choice == '2':
            print("\n" + "="*70)
            print("🔓 CHỨC NĂNG GIẢI MÃ FILE - DES")
            print("="*70)
            
            # Nhập các tham số
            print("\n📝 Nhập các tham số đầu vào:")
            
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
            print(f"   • Thuật toán: DES (56-bit)")
            print(f"   • Input: {input_file} ({file_size:,} bytes)")
            print(f"   • Output: {output_file}")
            
            # Thực hiện giải mã
            print("\n⏳ Đang giải mã...")
            start_time = time.time()
            
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
                
                elapsed_time = time.time() - start_time
                
                print(f"\n✅ Giải mã thành công!")
                print(f"   → File đầu ra: {output_file}")
                print(f"   → Kích thước: {len(text_data)} ký tự")
                
                # In bảng phân tích
                print_explanation("GIẢI MÃ", file_size, elapsed_time, password_strength)
                
            except Exception as e:
                print(f"\n❌ Lỗi giải mã: {e}")
                print(f"   → Có thể do: Sai mật khẩu hoặc file bị hỏng")
            
        elif choice == '3':
            print("\n👋 Cảm ơn bạn đã sử dụng DES Cipher!")
            print("⚠️  Nhớ rằng: DES không an toàn - Hãy dùng AES!")
            break
        else:
            print("\n❌ Lựa chọn không hợp lệ! Vui lòng chọn 1-3.")

if __name__ == "__main__":
    main()