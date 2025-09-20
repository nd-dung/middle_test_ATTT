import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import math


class RSAEncryptor:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Encryptor - Người Gửi")
        self.root.geometry("800x600")

        # Biến lưu trữ khóa
        self.n = None
        self.e = None
        self.d = None
        self.phi_n = None
        self.block_size = None

        self.setup_ui()

    def setup_ui(self):
        # Frame chính
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Phần sinh khóa
        self.setup_key_generation(main_frame)

        # Phần mã hóa
        self.setup_encryption(main_frame)

    def setup_key_generation(self, parent):
        # Phần nhập p, q, e
        input_frame = ttk.LabelFrame(parent, text="Key Generation", padding=10)
        input_frame.pack(fill=tk.X, padx=10, pady=5)

        # Tạo grid layout cho các input
        ttk.Label(input_frame, text="p (nguyên tố):").grid(
            row=0, column=0, sticky=tk.W, padx=5, pady=5
        )
        self.p_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.p_var, width=12).grid(
            row=0, column=1, padx=5, pady=5
        )

        ttk.Label(input_frame, text="q (nguyên tố):").grid(
            row=0, column=2, sticky=tk.W, padx=5, pady=5
        )
        self.q_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.q_var, width=12).grid(
            row=0, column=3, padx=5, pady=5
        )

        ttk.Label(input_frame, text="e (tùy chọn):").grid(
            row=0, column=4, sticky=tk.W, padx=5, pady=5
        )
        self.e_input_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.e_input_var, width=12).grid(
            row=0, column=5, padx=5, pady=5
        )

        ttk.Button(input_frame, text="Sinh khóa", command=self.generate_keys).grid(
            row=0, column=6, padx=10, pady=5
        )

        # Hiển thị khóa đã sinh
        key_display_frame = ttk.Frame(input_frame)
        key_display_frame.grid(
            row=1, column=0, columnspan=7, pady=10, sticky=tk.W + tk.E
        )

        ttk.Label(key_display_frame, text="n:").grid(
            row=0, column=0, sticky=tk.W, padx=5
        )
        self.n_var = tk.StringVar()
        ttk.Entry(
            key_display_frame, textvariable=self.n_var, width=10, state="readonly"
        ).grid(row=0, column=1, padx=5)

        ttk.Label(key_display_frame, text="φ(n):").grid(
            row=0, column=2, sticky=tk.W, padx=5
        )
        self.phi_n_var = tk.StringVar()
        ttk.Entry(
            key_display_frame, textvariable=self.phi_n_var, width=10, state="readonly"
        ).grid(row=0, column=3, padx=5)

        ttk.Label(key_display_frame, text="e:").grid(
            row=0, column=4, sticky=tk.W, padx=5
        )
        self.e_var = tk.StringVar()
        ttk.Entry(
            key_display_frame, textvariable=self.e_var, width=10, state="readonly"
        ).grid(row=0, column=5, padx=5)

        ttk.Label(key_display_frame, text="d:").grid(
            row=0, column=6, sticky=tk.W, padx=5
        )
        self.d_var = tk.StringVar()
        ttk.Entry(
            key_display_frame, textvariable=self.d_var, width=10, state="readonly"
        ).grid(row=0, column=7, padx=5)

        ttk.Label(key_display_frame, text="Block size:").grid(
            row=1, column=0, sticky=tk.W, padx=5
        )
        self.block_size_var = tk.StringVar()
        ttk.Entry(
            key_display_frame,
            textvariable=self.block_size_var,
            width=10,
            state="readonly",
        ).grid(row=1, column=1, padx=5)

    def setup_encryption(self, parent):
        # Frame chính cho encryption
        crypto_frame = ttk.LabelFrame(parent, text="Encryption", padding=10)
        crypto_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Plaintext
        ttk.Label(crypto_frame, text="Plaintext (UTF-8):").pack(
            anchor=tk.W, pady=(0, 5)
        )
        self.plaintext = scrolledtext.ScrolledText(crypto_frame, height=8, wrap=tk.WORD)
        self.plaintext.pack(fill=tk.BOTH, expand=True)

        # Ciphertext
        ttk.Label(crypto_frame, text="Ciphertext (hex):").pack(
            anchor=tk.W, pady=(10, 5)
        )
        self.ciphertext = scrolledtext.ScrolledText(
            crypto_frame, height=8, wrap=tk.WORD
        )
        self.ciphertext.pack(fill=tk.BOTH, expand=True)

        # Nút thao tác
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(button_frame, text="Mã hóa", command=self.encrypt_text).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(
            button_frame, text="Copy khóa công khai (n,e)", command=self.copy_public_key
        ).pack(side=tk.LEFT, padx=5)
        ttk.Button(
            button_frame, text="Copy khóa bí mật (n,d)", command=self.copy_private_key
        ).pack(side=tk.LEFT, padx=5)
        ttk.Button(
            button_frame, text="Copy Ciphertext", command=self.copy_ciphertext
        ).pack(side=tk.LEFT, padx=5)

    def is_prime(self, n):
        if n < 2:
            return False
        for i in range(2, int(math.sqrt(n)) + 1):
            if n % i == 0:
                return False
        return True

    def gcd(self, a, b):
        while b:
            a, b = b, a % b
        return a

    def extended_gcd(self, a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = self.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    def mod_inverse(self, e, phi_n):
        gcd, x, y = self.extended_gcd(e, phi_n)
        if gcd != 1:
            return None
        return x % phi_n

    def generate_keys(self):
        try:
            # Kiểm tra input không rỗng
            if not self.p_var.get().strip():
                messagebox.showerror("Lỗi", "Vui lòng nhập p!")
                return
            if not self.q_var.get().strip():
                messagebox.showerror("Lỗi", "Vui lòng nhập q!")
                return

            p = int(self.p_var.get())
            q = int(self.q_var.get())
            e_input = (
                int(self.e_input_var.get()) if self.e_input_var.get().strip() else 65537
            )

            # Kiểm tra p, q là số nguyên tố
            if not self.is_prime(p):
                messagebox.showerror("Lỗi", "p phải là số nguyên tố!")
                return
            if not self.is_prime(q):
                messagebox.showerror("Lỗi", "q phải là số nguyên tố!")
                return

            # Kiểm tra p, q không quá nhỏ
            if p < 2 or q < 2:
                messagebox.showerror("Lỗi", "p và q phải lớn hơn 1!")
                return

            # Tính n và φ(n)
            self.n = p * q
            self.phi_n = (p - 1) * (q - 1)

            # Kiểm tra e
            if e_input and self.gcd(e_input, self.phi_n) == 1:
                self.e = e_input
            else:
                # Tìm e hợp lệ
                self.e = None
                for i in range(3, min(self.phi_n, 1000), 2):
                    if self.gcd(i, self.phi_n) == 1:
                        self.e = i
                        break
                if not self.e:
                    messagebox.showerror("Lỗi", "Không thể tìm được e hợp lệ!")
                    return

            # Tính d
            self.d = self.mod_inverse(self.e, self.phi_n)
            if not self.d:
                messagebox.showerror("Lỗi", "Không thể tính d!")
                return

            # Tính block size
            self.block_size = (self.n.bit_length() + 7) // 8 - 1

            # Cập nhật giao diện
            self.n_var.set(str(self.n))
            self.phi_n_var.set(str(self.phi_n))
            self.e_var.set(str(self.e))
            self.d_var.set(str(self.d))
            self.block_size_var.set(str(self.block_size))

            messagebox.showinfo("Thành công", "Khóa đã được sinh thành công!")

        except ValueError:
            messagebox.showerror("Lỗi", "Vui lòng nhập số nguyên hợp lệ!")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Có lỗi xảy ra: {str(e)}")

    def encrypt_text(self):
        if not self.n or not self.e:
            messagebox.showerror("Lỗi", "Vui lòng sinh khóa trước!")
            return

        plaintext = self.plaintext.get("1.0", tk.END).strip()
        if not plaintext:
            messagebox.showerror("Lỗi", "Vui lòng nhập văn bản cần mã hóa!")
            return

        try:
            # Chuyển văn bản thành bytes
            text_bytes = plaintext.encode("utf-8")

            # Chia thành các khối
            blocks = []
            for i in range(0, len(text_bytes), self.block_size):
                block = text_bytes[i : i + self.block_size]
                # Pad nếu cần
                if len(block) < self.block_size:
                    block += b"\x00" * (self.block_size - len(block))
                blocks.append(block)

            # Mã hóa từng khối
            encrypted_blocks = []
            for block in blocks:
                # Chuyển bytes thành số nguyên
                m = int.from_bytes(block, byteorder="big")
                # Mã hóa: c = m^e mod n
                c = pow(m, self.e, self.n)
                encrypted_blocks.append(c)

            # Chuyển thành hex và hiển thị
            hex_blocks = [hex(block)[2:].zfill(6) for block in encrypted_blocks]
            ciphertext_str = " ".join(hex_blocks)

            self.ciphertext.delete("1.0", tk.END)
            self.ciphertext.insert("1.0", ciphertext_str)

            messagebox.showinfo("Thành công", "Mã hóa thành công!")

        except Exception as e:
            messagebox.showerror("Lỗi", f"Có lỗi xảy ra khi mã hóa: {str(e)}")

    def copy_public_key(self):
        if self.n and self.e:
            key_str = f"n={self.n}, e={self.e}"
            self.root.clipboard_clear()
            self.root.clipboard_append(key_str)
            messagebox.showinfo("Thành công", "Khóa công khai đã được copy!")
        else:
            messagebox.showerror("Lỗi", "Chưa sinh khóa!")

    def copy_private_key(self):
        if self.n and self.d:
            key_str = f"n={self.n}, d={self.d}"
            self.root.clipboard_clear()
            self.root.clipboard_append(key_str)
            messagebox.showinfo("Thành công", "Khóa bí mật đã được copy!")
        else:
            messagebox.showerror("Lỗi", "Chưa sinh khóa!")

    def copy_ciphertext(self):
        ciphertext = self.ciphertext.get("1.0", tk.END).strip()
        if ciphertext:
            self.root.clipboard_clear()
            self.root.clipboard_append(ciphertext)
            messagebox.showinfo("Thành công", "Ciphertext đã được copy!")
        else:
            messagebox.showerror("Lỗi", "Chưa có ciphertext!")


def main():
    root = tk.Tk()
    app = RSAEncryptor(root)
    root.mainloop()


if __name__ == "__main__":
    main()
