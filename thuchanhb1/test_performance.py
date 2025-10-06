import os
import time
import psutil
import tracemalloc
from datetime import datetime

# Import các cipher classes
from aes_cipher import AESCipher
from des_cipher import DESCipher
from triple_des_cipher import TripleDESCipher

class PerformanceTester:
    def __init__(self, input_file="input_mahoa.txt"):
        self.input_file = input_file
        self.results = []
        
        # Kiểm tra file input
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"File {input_file} không tồn tại!")
        
        # Lấy thông tin file
        self.file_size = os.path.getsize(input_file)
        print(f"Input file: {input_file}")
        print(f"File size: {self.file_size / 1024:.2f} KB ({self.file_size} bytes)")
    
    def get_system_info(self):
        print("\n=== SYSTEM INFORMATION ===")
        print(f"CPU Count: {psutil.cpu_count()} cores")
        print(f"Memory Total: {psutil.virtual_memory().total / (1024**3):.2f} GB")
        print(f"Memory Available: {psutil.virtual_memory().available / (1024**3):.2f} GB")
        print(f"Python Process PID: {os.getpid()}")
    
    def measure_performance(self, cipher_func, algorithm_name):
        print(f"\n{'='*50}")
        print(f"TESTING {algorithm_name}")
        print(f"{'='*50}")
        
        # Bắt đầu đo memory
        tracemalloc.start()
        
        # Lấy trạng thái CPU và memory ban đầu
        process = psutil.Process()
        cpu_before = process.cpu_percent()
        memory_before = process.memory_info()
        
        # Đọc file input
        with open(self.input_file, 'rb') as f:
            input_data = f.read()
        
        # Test mã hóa
        print("Testing encryption...")
        start_time = time.perf_counter()
        encrypted_data, key, iv = cipher_func['encrypt'](input_data)
        encryption_time = time.perf_counter() - start_time
        
        # Đo memory peak sau mã hóa
        current_memory, peak_memory = tracemalloc.get_traced_memory()
        encryption_memory = peak_memory
        
        # Lấy CPU usage sau mã hóa
        cpu_after_encrypt = process.cpu_percent()
        memory_after_encrypt = process.memory_info()
        
        # Test giải mã
        print("Testing decryption...")
        start_time = time.perf_counter()
        decrypted_data = cipher_func['decrypt'](encrypted_data, key, iv)
        decryption_time = time.perf_counter() - start_time
        
        # Đo memory peak cuối
        current_memory, peak_memory = tracemalloc.get_traced_memory()
        total_memory_peak = peak_memory
        
        # CPU và memory cuối
        cpu_after_decrypt = process.cpu_percent()
        memory_after_decrypt = process.memory_info()
        
        # Dừng đo memory
        tracemalloc.stop()
        
        # Kiểm tra tính đúng đắn
        is_correct = input_data == decrypted_data
        
        # Tính toán metrics
        total_time = encryption_time + decryption_time
        throughput = (len(input_data) * 2) / total_time / (1024*1024)  # MB/s
        
        # Memory usage (RSS - Resident Set Size)
        memory_used_encrypt = memory_after_encrypt.rss - memory_before.rss
        memory_used_decrypt = memory_after_decrypt.rss - memory_after_encrypt.rss
        total_memory_used = memory_after_decrypt.rss - memory_before.rss
        
        # Lưu file mã hóa để kiểm tra
        encrypted_filename = f"encrypted_{algorithm_name.lower().replace('-', '_')}.bin"
        with open(encrypted_filename, 'wb') as f:
            f.write(iv + encrypted_data)  # Lưu IV + encrypted data
        
        # Lưu file giải mã để kiểm tra
        decrypted_filename = f"decrypted_{algorithm_name.lower().replace('-', '_')}.txt"
        with open(decrypted_filename, 'wb') as f:
            f.write(decrypted_data)
        
        # Kết quả
        result = {
            'algorithm': algorithm_name,
            'file_size_bytes': len(input_data),
            'file_size_kb': len(input_data) / 1024,
            'encryption_time': encryption_time,
            'decryption_time': decryption_time,
            'total_time': total_time,
            'throughput_mbps': throughput,
            'encrypted_size': len(encrypted_data),
            'compression_ratio': len(encrypted_data) / len(input_data),
            'is_correct': is_correct,
            # Memory metrics
            'memory_peak_bytes': total_memory_peak,
            'memory_peak_mb': total_memory_peak / (1024*1024),
            'memory_encrypt_bytes': memory_used_encrypt,
            'memory_decrypt_bytes': memory_used_decrypt,
            'memory_total_bytes': total_memory_used,
            # CPU metrics (approximation)
            'cpu_before': cpu_before,
            'cpu_after_encrypt': cpu_after_encrypt,
            'cpu_after_decrypt': cpu_after_decrypt,
            'files_created': [encrypted_filename, decrypted_filename]
        }
        
        # In kết quả
        self.print_result(result)
        self.results.append(result)
        
        return result
    
    def print_result(self, result):
        """
        In kết quả chi tiết
        """
        print(f"\n--- {result['algorithm']} RESULTS ---")
        print(f"File size: {result['file_size_kb']:.2f} KB")
        print(f"Encryption time: {result['encryption_time']:.4f}s")
        print(f"Decryption time: {result['decryption_time']:.4f}s")
        print(f"Total time: {result['total_time']:.4f}s")
        print(f"Throughput: {result['throughput_mbps']:.2f} MB/s")
        print(f"Encrypted size: {result['encrypted_size']} bytes")
        print(f"Size ratio: {result['compression_ratio']:.3f}")
        print(f"Correctness: {'✓ PASS' if result['is_correct'] else '✗ FAIL'}")
        
        print(f"\nMemory Usage:")
        print(f"  Peak memory: {result['memory_peak_mb']:.2f} MB")
        print(f"  Encryption: {result['memory_encrypt_bytes'] / 1024:.2f} KB")
        print(f"  Decryption: {result['memory_decrypt_bytes'] / 1024:.2f} KB")
        print(f"  Total: {result['memory_total_bytes'] / 1024:.2f} KB")
        
        print(f"\nCPU Usage (approximate):")
        print(f"  Before: {result['cpu_before']:.1f}%")
        print(f"  After encrypt: {result['cpu_after_encrypt']:.1f}%")
        print(f"  After decrypt: {result['cpu_after_decrypt']:.1f}%")
        
        print(f"\nFiles created:")
        for file in result['files_created']:
            print(f"  - {file}")
    
    def test_aes(self):
        """
        Test AES-256
        """
        cipher = AESCipher(32)  # AES-256
        key = cipher.generate_key("test_password_aes")
        
        def encrypt_func(data):
            encrypted, iv = cipher.encrypt_data(data, key)
            return encrypted, key, iv
        
        def decrypt_func(encrypted, key, iv):
            return cipher.decrypt_data(encrypted, key, iv)
        
        cipher_funcs = {
            'encrypt': encrypt_func,
            'decrypt': decrypt_func
        }
        
        return self.measure_performance(cipher_funcs, "AES-256")
    
    def test_des(self):
        """
        Test DES
        """
        cipher = DESCipher()
        key = cipher.generate_key("test_password_des")
        
        def encrypt_func(data):
            encrypted, iv = cipher.encrypt_data(data, key)
            return encrypted, key, iv
        
        def decrypt_func(encrypted, key, iv):
            return cipher.decrypt_data(encrypted, key, iv)
        
        cipher_funcs = {
            'encrypt': encrypt_func,
            'decrypt': decrypt_func
        }
        
        return self.measure_performance(cipher_funcs, "DES")
    
    def test_3des(self):
        """
        Test 3DES
        """
        cipher = TripleDESCipher("3DES-EDE3")
        key = cipher.generate_key("test_password_3des")
        
        def encrypt_func(data):
            encrypted, iv = cipher.encrypt_data(data, key)
            return encrypted, key, iv
        
        def decrypt_func(encrypted, key, iv):
            return cipher.decrypt_data(encrypted, key, iv)
        
        cipher_funcs = {
            'encrypt': encrypt_func,
            'decrypt': decrypt_func
        }
        
        return self.measure_performance(cipher_funcs, "3DES-EDE3")
    
    def run_all_tests(self):
        """
        Chạy test cho tất cả thuật toán
        """
        print("=" * 70)
        print("ENCRYPTION ALGORITHMS PERFORMANCE TEST")
        print("=" * 70)
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        self.get_system_info()
        
        # Test từng thuật toán
        print("\n" + "="*70)
        print("RUNNING TESTS...")
        print("="*70)
        
        try:
            # Test AES
            self.test_aes()
            time.sleep(1)  # Nghỉ 1 giây giữa các test
            
            # Test DES
            self.test_des()
            time.sleep(1)
            
            # Test 3DES
            self.test_3des()
            
        except Exception as e:
            print(f"Error during testing: {e}")
            import traceback
            traceback.print_exc()
        
        # Tổng kết
        self.print_summary()
    
    def print_summary(self):
        """
        In tổng kết so sánh
        """
        if not self.results:
            print("No results to display!")
            return
        
        print("\n" + "="*70)
        print("PERFORMANCE COMPARISON SUMMARY")
        print("="*70)
        
        # Bảng so sánh
        print(f"{'Algorithm':<12} {'Time(s)':<8} {'Speed(MB/s)':<12} {'Memory(MB)':<12} {'Correct':<8}")
        print("-" * 60)
        
        for result in self.results:
            print(f"{result['algorithm']:<12} "
                  f"{result['total_time']:<8.4f} "
                  f"{result['throughput_mbps']:<12.2f} "
                  f"{result['memory_peak_mb']:<12.2f} "
                  f"{'YES' if result['is_correct'] else 'NO':<8}")
        
        # Tìm thuật toán nhanh nhất
        fastest = min(self.results, key=lambda x: x['total_time'])
        print(f"\n🏆 Fastest algorithm: {fastest['algorithm']} ({fastest['total_time']:.4f}s)")
        
        # Thuật toán ít memory nhất
        least_memory = min(self.results, key=lambda x: x['memory_peak_mb'])
        print(f"💾 Least memory usage: {least_memory['algorithm']} ({least_memory['memory_peak_mb']:.2f}MB)")
        
        # Khuyến nghị
        print(f"\n📋 RECOMMENDATIONS:")
        print(f"✓ For speed: {fastest['algorithm']}")
        print(f"✓ For memory efficiency: {least_memory['algorithm']}")
        print(f"✓ For security: AES-256 (recommended for production)")
        print(f"⚠ Avoid DES for security reasons (56-bit key)")
        
        print(f"\n🕒 Test completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

def main():
    """
    Main function
    """
    try:
        tester = PerformanceTester("input_mahoa.txt")
        tester.run_all_tests()
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Please make sure 'input_mahoa.txt' exists in the current directory.")
    except Exception as e:
        print(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()