import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, simpledialog, messagebox
from ttkbootstrap.scrolled import ScrolledText
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os

SALT_SIZE = 16
IV_SIZE = 12
KEY_LENGTH = 32

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=KEY_LENGTH,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(data: str, password: str) -> bytes:
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    encrypted = aesgcm.encrypt(iv, data.encode(), None)
    return salt + iv + encrypted

def decrypt_data(blob: bytes, password: str) -> str:
    salt = blob[:SALT_SIZE]
    iv = blob[SALT_SIZE:SALT_SIZE+IV_SIZE]
    ciphertext = blob[SALT_SIZE+IV_SIZE:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, None).decode()

class EncryptedNotepad:
    def __init__(self, master):
        self.master = master
        master.title("Encrypted Notepad")

        self.text = ScrolledText(
            master,
            wrap="word",
            font=("Segoe UI", 12),
            padding=10
        )
        self.text.pack(expand=1, fill=BOTH, padx=15, pady=15)

        menubar = ttk.Menu(master)

        filemenu = ttk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Save Encrypted", command=self.save_encrypted)
        filemenu.add_command(label="Open Encrypted", command=self.open_encrypted)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=master.quit)
        menubar.add_cascade(label="File", menu=filemenu)

        editmenu = ttk.Menu(menubar, tearoff=0)
        editmenu.add_command(label="Undo", command=self.text.edit_undo)
        editmenu.add_command(label="Redo", command=self.text.edit_redo)
        editmenu.add_separator()
        editmenu.add_command(label="Cut", command=lambda: self.text.event_generate('<<Cut>>'))
        editmenu.add_command(label="Copy", command=lambda: self.text.event_generate('<<Copy>>'))
        editmenu.add_command(label="Paste", command=lambda: self.text.event_generate('<<Paste>>'))
        editmenu.add_command(label="Delete", command=lambda: self.text.delete("sel.first", "sel.last"))
        editmenu.add_separator()
        editmenu.add_command(label="Select All", command=lambda: self.text.event_generate('<<SelectAll>>'))
        menubar.add_cascade(label="Edit", menu=editmenu)

        master.config(menu=menubar)

    def save_encrypted(self):
        password = simpledialog.askstring("Password", "Enter password to encrypt:", show='*')
        if not password:
            return
        data = self.text.get("1.0", "end-1c")
        encrypted_blob = encrypt_data(data, password)
        filepath = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted Files", "*.enc")])
        if filepath:
            with open(filepath, "wb") as f:
                f.write(encrypted_blob)
            messagebox.showinfo("Saved", "File saved and encrypted successfully.")

    def open_encrypted(self):
        filepath = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
        if not filepath:
            return
        password = simpledialog.askstring("Password", "Enter password to decrypt:", show='*')
        if not password:
            return
        try:
            with open(filepath, "rb") as f:
                blob = f.read()
            decrypted_text = decrypt_data(blob, password)
            self.text.delete("1.0", "end")
            self.text.insert("1.0", decrypted_text)
            messagebox.showinfo("Decrypted", "File decrypted and loaded successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt file: {str(e)}")

if __name__ == '__main__':
    root = ttk.Window(themename="flatly")
    root.iconbitmap("custom_icon.ico")
    root.geometry("700x500")
    app = EncryptedNotepad(root)
    root.mainloop()