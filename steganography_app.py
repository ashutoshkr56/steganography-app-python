"""
Steganography App - Hide secret messages inside images
Requirements: pip install Pillow
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image
import os


class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Steganography Tool")
        self.root.geometry("700x600")
        self.root.configure(bg="#2d1b4e")

        self.image_path = None
        self.mode = tk.StringVar(value="encode")

        self.setup_ui()

    def setup_ui(self):
        # Title
        title = tk.Label(
            self.root,
            text="Steganography Tool",
            font=("Helvetica", 24, "bold"),
            bg="#2d1b4e",
            fg="white"
        )
        title.pack(pady=20)

        subtitle = tk.Label(
            self.root,
            text="Hide secret messages inside images",
            font=("Helvetica", 12),
            bg="#2d1b4e",
            fg="#c4b5fd"
        )
        subtitle.pack(pady=(0, 20))

        # Main frame
        main_frame = tk.Frame(self.root, bg="#4c3575", relief=tk.RAISED, bd=2)
        main_frame.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

        # Mode selection
        mode_frame = tk.Frame(main_frame, bg="#4c3575")
        mode_frame.pack(pady=15, padx=20, fill=tk.X)

        encode_btn = tk.Radiobutton(
            mode_frame,
            text="🔒 Encode Message",
            variable=self.mode,
            value="encode",
            font=("Helvetica", 11, "bold"),
            bg="#7c3aed",
            fg="white",
            selectcolor="#5b21b6",
            activebackground="#6d28d9",
            activeforeground="white",
            indicatoron=False,
            width=20,
            command=self.switch_mode
        )
        encode_btn.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

        decode_btn = tk.Radiobutton(
            mode_frame,
            text="🔓 Decode Message",
            variable=self.mode,
            value="decode",
            font=("Helvetica", 11, "bold"),
            bg="#7c3aed",
            fg="white",
            selectcolor="#5b21b6",
            activebackground="#6d28d9",
            activeforeground="white",
            indicatoron=False,
            width=20,
            command=self.switch_mode
        )
        decode_btn.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

        # Image upload
        upload_frame = tk.Frame(main_frame, bg="#4c3575")
        upload_frame.pack(pady=10, padx=20, fill=tk.X)

        self.image_label = tk.Label(
            upload_frame,
            text="No image selected",
            font=("Helvetica", 10),
            bg="#5b3a7d",
            fg="white",
            relief=tk.SUNKEN,
            pady=10
        )
        self.image_label.pack(fill=tk.X, pady=5)

        upload_btn = tk.Button(
            upload_frame,
            text="📁 Upload Image",
            command=self.upload_image,
            font=("Helvetica", 10, "bold"),
            bg="#8b5cf6",
            fg="white",
            activebackground="#7c3aed",
            cursor="hand2",
            relief=tk.RAISED,
            bd=2
        )
        upload_btn.pack(pady=5)

        # Content frame (changes based on mode)
        self.content_frame = tk.Frame(main_frame, bg="#4c3575")
        self.content_frame.pack(pady=10, padx=20, fill=tk.BOTH, expand=True)

        self.setup_encode_ui()

    def switch_mode(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

        if self.mode.get() == "encode":
            self.setup_encode_ui()
        else:
            self.setup_decode_ui()

    def setup_encode_ui(self):
        # Message input
        tk.Label(
            self.content_frame,
            text="Secret Message:",
            font=("Helvetica", 10, "bold"),
            bg="#4c3575",
            fg="white"
        ).pack(anchor=tk.W, pady=(5, 2))

        self.message_text = tk.Text(
            self.content_frame,
            height=6,
            font=("Helvetica", 10),
            bg="#5b3a7d",
            fg="white",
            insertbackground="white",
            relief=tk.SUNKEN,
            bd=2
        )
        self.message_text.pack(fill=tk.BOTH, expand=True, pady=5)

        # Password input
        tk.Label(
            self.content_frame,
            text="Password (Optional):",
            font=("Helvetica", 10, "bold"),
            bg="#4c3575",
            fg="white"
        ).pack(anchor=tk.W, pady=(10, 2))

        self.password_entry = tk.Entry(
            self.content_frame,
            show="*",
            font=("Helvetica", 10),
            bg="#5b3a7d",
            fg="white",
            insertbackground="white",
            relief=tk.SUNKEN,
            bd=2
        )
        self.password_entry.pack(fill=tk.X, pady=5)

        # Encode button
        encode_btn = tk.Button(
            self.content_frame,
            text="🔒 Encode Message",
            command=self.encode_message,
            font=("Helvetica", 11, "bold"),
            bg="#22c55e",
            fg="white",
            activebackground="#16a34a",
            cursor="hand2",
            relief=tk.RAISED,
            bd=3,
            pady=10
        )
        encode_btn.pack(fill=tk.X, pady=15)

    def setup_decode_ui(self):
        # Password input
        tk.Label(
            self.content_frame,
            text="Password (if protected):",
            font=("Helvetica", 10, "bold"),
            bg="#4c3575",
            fg="white"
        ).pack(anchor=tk.W, pady=(5, 2))

        self.password_entry = tk.Entry(
            self.content_frame,
            show="*",
            font=("Helvetica", 10),
            bg="#5b3a7d",
            fg="white",
            insertbackground="white",
            relief=tk.SUNKEN,
            bd=2
        )
        self.password_entry.pack(fill=tk.X, pady=5)

        # Decode button
        decode_btn = tk.Button(
            self.content_frame,
            text="🔓 Decode Message",
            command=self.decode_message,
            font=("Helvetica", 11, "bold"),
            bg="#3b82f6",
            fg="white",
            activebackground="#2563eb",
            cursor="hand2",
            relief=tk.RAISED,
            bd=3,
            pady=10
        )
        decode_btn.pack(fill=tk.X, pady=15)

        # Result display
        tk.Label(
            self.content_frame,
            text="Decoded Message:",
            font=("Helvetica", 10, "bold"),
            bg="#4c3575",
            fg="white"
        ).pack(anchor=tk.W, pady=(10, 2))

        self.result_text = tk.Text(
            self.content_frame,
            height=8,
            font=("Helvetica", 10),
            bg="#5b3a7d",
            fg="white",
            relief=tk.SUNKEN,
            bd=2,
            state=tk.DISABLED
        )
        self.result_text.pack(fill=tk.BOTH, expand=True, pady=5)

    def upload_image(self):
        file_path = filedialog.askopenfilename(
            title="Select an image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp"), ("All files", "*.*")]
        )
        if file_path:
            self.image_path = file_path
            self.image_label.config(text=os.path.basename(file_path))

    def string_to_binary(self, text):
        return ''.join(format(ord(char), '08b') for char in text)

    def binary_to_string(self, binary):
        chars = [binary[i:i + 8] for i in range(0, len(binary), 8)]
        return ''.join(chr(int(char, 2)) for char in chars)

    def xor_encrypt_decrypt(self, text, key):
        if not key:
            return text
        result = ''
        for i, char in enumerate(text):
            result += chr(ord(char) ^ ord(key[i % len(key)]))
        return result

    def encode_message(self):
        if not self.image_path:
            messagebox.showerror("Error", "Please upload an image first!")
            return

        message = self.message_text.get("1.0", tk.END).strip()
        if not message:
            messagebox.showerror("Error", "Please enter a message to encode!")
            return

        password = self.password_entry.get()

        try:
            img = Image.open(self.image_path)

            # Convert to RGB if necessary
            if img.mode != 'RGB':
                img = img.convert('RGB')

            # Encrypt message if password provided
            encrypted_msg = self.xor_encrypt_decrypt(message, password) if password else message
            message_with_delimiter = encrypted_msg + "###END###"
            binary_message = self.string_to_binary(message_with_delimiter)

            # Get image data
            pixels = list(img.getdata())
            max_capacity = len(pixels) * 3

            if len(binary_message) > max_capacity:
                messagebox.showerror("Error", "Message too large for this image!")
                return

            # Encode message
            new_pixels = []
            bit_index = 0

            for pixel in pixels:
                r, g, b = pixel

                if bit_index < len(binary_message):
                    r = (r & 0xFE) | int(binary_message[bit_index])
                    bit_index += 1

                if bit_index < len(binary_message):
                    g = (g & 0xFE) | int(binary_message[bit_index])
                    bit_index += 1

                if bit_index < len(binary_message):
                    b = (b & 0xFE) | int(binary_message[bit_index])
                    bit_index += 1

                new_pixels.append((r, g, b))

            # Create new image
            encoded_img = Image.new(img.mode, img.size)
            encoded_img.putdata(new_pixels)

            # Save image
            save_path = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[("PNG files", "*.png"), ("All files", "*.*")]
            )

            if save_path:
                encoded_img.save(save_path, "PNG")
                messagebox.showinfo("Success", "Message encoded successfully!\nImage saved.")

        except Exception as e:
            messagebox.showerror("Error", f"Encoding failed: {str(e)}")

    def decode_message(self):
        if not self.image_path:
            messagebox.showerror("Error", "Please upload an image first!")
            return

        password = self.password_entry.get()

        try:
            img = Image.open(self.image_path)

            # Convert to RGB if necessary
            if img.mode != 'RGB':
                img = img.convert('RGB')

            pixels = list(img.getdata())
            binary_message = ''

            # Extract binary data
            for pixel in pixels:
                r, g, b = pixel
                binary_message += str(r & 1)
                binary_message += str(g & 1)
                binary_message += str(b & 1)

            # Convert to text and look for delimiter
            message = ''
            for i in range(0, len(binary_message), 8):
                if i + 8 <= len(binary_message):
                    byte = binary_message[i:i + 8]
                    char = chr(int(byte, 2))
                    message += char

                    if message.endswith("###END###"):
                        decoded = message[:-9]  # Remove delimiter
                        # Decrypt if password provided
                        final_message = self.xor_encrypt_decrypt(decoded, password) if password else decoded

                        self.result_text.config(state=tk.NORMAL)
                        self.result_text.delete("1.0", tk.END)
                        self.result_text.insert("1.0", final_message)
                        self.result_text.config(state=tk.DISABLED)

                        messagebox.showinfo("Success", "Message decoded successfully!")
                        return

            messagebox.showerror("Error", "No hidden message found or incorrect password!")

        except Exception as e:
            messagebox.showerror("Error", f"Decoding failed: {str(e)}")


def main():
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()