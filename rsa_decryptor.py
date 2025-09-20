import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext


class RSADecryptor:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Decryptor - Người Nhận")
        self.root.geometry("800x600")

        # Biến lưu trữ khóa
        self.n = None
        self.d = None
        self.block_size = None

        self.setup_ui()

    def setup_ui(self):
        # Frame chính
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Phần nhập khóa bí mật
        self.setup_key_input(main_frame)

        # Phần giải mã
        self.setup_decryption(main_frame)

    def setup_key_input(self, parent):
        # Phần nhập khóa bí mật
        key_frame = ttk.LabelFrame(parent, text="Private Key Input", padding=10)
        key_frame.pack(fill=tk.X, padx=10, pady=5)

        # Nhập n
        ttk.Label(key_frame, text="n (modulus):").grid(
            row=0, column=0, sticky=tk.W, padx=5, pady=5
        )
        self.n_var = tk.StringVar()
        ttk.Entry(key_frame, textvariable=self.n_var, width=20).grid(
            row=0, column=1, padx=5, pady=5
        )

        # Nhập d
        ttk.Label(key_frame, text="d (private key):").grid(
            row=0, column=2, sticky=tk.W, padx=5, pady=5
        )
        self.d_var = tk.StringVar()
        ttk.Entry(key_frame, textvariable=self.d_var, width=20).grid(
            row=0, column=3, padx=5, pady=5
        )

        # Nút nhập khóa
        ttk.Button(key_frame, text="Nhập khóa", command=self.load_keys).grid(
            row=0, column=4, padx=10, pady=5
        )
        ttk.Button(key_frame, text="Paste từ clipboard", command=self.paste_keys).grid(
            row=0, column=5, padx=5, pady=5
        )

        # Hiển thị trạng thái khóa
        status_frame = ttk.Frame(key_frame)
        status_frame.grid(row=1, column=0, columnspan=6, pady=10, sticky=tk.W + tk.E)

        ttk.Label(status_frame, text="Trạng thái khóa:").grid(
            row=0, column=0, sticky=tk.W, padx=5
        )
        self.key_status_var = tk.StringVar(value="Chưa có khóa")
        ttk.Label(
            status_frame, textvariable=self.key_status_var, foreground="red"
        ).grid(row=0, column=1, sticky=tk.W, padx=5)

        # Hiển thị block size
        ttk.Label(status_frame, text="Block size:").grid(
            row=0, column=2, sticky=tk.W, padx=5
        )
        self.block_size_var = tk.StringVar()
        ttk.Entry(
            status_frame, textvariable=self.block_size_var, width=10, state="readonly"
        ).grid(row=0, column=3, padx=5)

    def setup_decryption(self, parent):
        # Frame chính cho decryption
        crypto_frame = ttk.LabelFrame(parent, text="Decryption", padding=10)
        crypto_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Ciphertext
        ttk.Label(crypto_frame, text="Ciphertext (hex):").pack(anchor=tk.W, pady=(0, 5))
        self.ciphertext = scrolledtext.ScrolledText(
            crypto_frame, height=8, wrap=tk.WORD
        )
        self.ciphertext.pack(fill=tk.BOTH, expand=True)

        # Plaintext
        ttk.Label(crypto_frame, text="Plaintext (UTF-8):").pack(
            anchor=tk.W, pady=(10, 5)
        )
        self.plaintext = scrolledtext.ScrolledText(crypto_frame, height=8, wrap=tk.WORD)
        self.plaintext.pack(fill=tk.BOTH, expand=True)

        # Nút thao tác
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(button_frame, text="Giải mã", command=self.decrypt_text).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(
            button_frame, text="Paste Ciphertext", command=self.paste_ciphertext
        ).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear All", command=self.clear_all).pack(
            side=tk.LEFT, padx=5
        )

    def load_keys(self):
        try:
            n_str = self.n_var.get().strip()
            d_str = self.d_var.get().strip()

            if not n_str or not d_str:
                messagebox.showerror("Lỗi", "Vui lòng nhập đầy đủ n và d!")
                return

            self.n = int(n_str)
            self.d = int(d_str)

            # Tính block size
            self.block_size = (self.n.bit_length() + 7) // 8 - 1
            self.block_size_var.set(str(self.block_size))

            # Cập nhật trạng thái
            self.key_status_var.set("Đã có khóa")
            self.key_status_var.set("Đã có khóa")

            messagebox.showinfo("Thành công", "Khóa đã được nhập thành công!")

        except ValueError:
            messagebox.showerror("Lỗi", "Vui lòng nhập số nguyên hợp lệ!")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Có lỗi xảy ra: {str(e)}")

    def paste_keys(self):
        try:
            # Lấy dữ liệu từ clipboard
            clipboard_data = self.root.clipboard_get()

            # Parse dữ liệu dạng "n=123, d=456"
            if "n=" in clipboard_data and "d=" in clipboard_data:
                parts = clipboard_data.split(", ")
                for part in parts:
                    if part.startswith("n="):
                        n_value = part[2:].strip()
                        self.n_var.set(n_value)
                    elif part.startswith("d="):
                        d_value = part[2:].strip()
                        self.d_var.set(d_value)

                messagebox.showinfo("Thành công", "Khóa đã được paste từ clipboard!")
            else:
                messagebox.showerror(
                    "Lỗi", "Định dạng clipboard không đúng! Cần: n=123, d=456"
                )

        except tk.TclError:
            messagebox.showerror("Lỗi", "Clipboard trống hoặc không có dữ liệu!")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Có lỗi xảy ra: {str(e)}")

    def paste_ciphertext(self):
        try:
            # Lấy dữ liệu từ clipboard
            clipboard_data = self.root.clipboard_get()

            # Paste vào ô ciphertext
            self.ciphertext.delete("1.0", tk.END)
            self.ciphertext.insert("1.0", clipboard_data)

            messagebox.showinfo("Thành công", "Ciphertext đã được paste từ clipboard!")

        except tk.TclError:
            messagebox.showerror("Lỗi", "Clipboard trống hoặc không có dữ liệu!")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Có lỗi xảy ra: {str(e)}")

    def decrypt_text(self):
        if not self.n or not self.d:
            messagebox.showerror("Lỗi", "Vui lòng nhập khóa bí mật trước!")
            return

        ciphertext = self.ciphertext.get("1.0", tk.END).strip()
        if not ciphertext:
            messagebox.showerror("Lỗi", "Vui lòng nhập văn bản cần giải mã!")
            return

        try:
            # Parse hex blocks
            hex_blocks = ciphertext.split()
            encrypted_blocks = [int(block, 16) for block in hex_blocks]

            # Giải mã từng khối
            decrypted_blocks = []
            for block in encrypted_blocks:
                # Giải mã: m = c^d mod n
                m = pow(block, self.d, self.n)
                # Chuyển số nguyên thành bytes
                decrypted_bytes = m.to_bytes(self.block_size, byteorder="big")
                decrypted_blocks.append(decrypted_bytes)

            # Ghép các khối lại
            all_bytes = b"".join(decrypted_blocks)
            # Loại bỏ padding
            all_bytes = all_bytes.rstrip(b"\x00")

            # Chuyển thành văn bản
            plaintext_str = all_bytes.decode("utf-8")

            self.plaintext.delete("1.0", tk.END)
            self.plaintext.insert("1.0", plaintext_str)

            messagebox.showinfo("Thành công", "Giải mã thành công!")

        except Exception as e:
            messagebox.showerror("Lỗi", f"Có lỗi xảy ra khi giải mã: {str(e)}")

    def clear_all(self):
        # Xóa tất cả dữ liệu
        self.n_var.set("")
        self.d_var.set("")
        self.block_size_var.set("")
        self.key_status_var.set("Chưa có khóa")
        self.ciphertext.delete("1.0", tk.END)
        self.plaintext.delete("1.0", tk.END)

        # Reset biến
        self.n = None
        self.d = None
        self.block_size = None

        messagebox.showinfo("Thành công", "Đã xóa tất cả dữ liệu!")


def main():
    root = tk.Tk()
    app = RSADecryptor(root)
    root.mainloop()


if __name__ == "__main__":
    main()
