import tkinter as tk
from tkinter import filedialog
from cryptography.fernet import Fernet
import hashlib
import os

def generate_key():
    return Fernet.generate_key()

def load_key(key_path='secret.key'):
    return open(key_path, 'rb').read()

def save_key(key, key_path='secret.key'):
    with open(key_path, 'wb') as key_file:
        key_file.write(key)

def calculate_file_hash(file_path):
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hasher.update(chunk)
    return hasher.hexdigest()

def encrypt_file(key, input_file, output_file):
    cipher = Fernet(key)
    with open(input_file, 'rb') as file:
        plaintext = file.read()

    original_hash = calculate_file_hash(input_file)

    encrypted_data = cipher.encrypt(plaintext)
    with open(output_file, 'wb') as file:
        file.write(encrypted_data)

    with open(output_file + '.hash', 'w') as hash_file:
        hash_file.write(original_hash)

def decrypt_file(key, input_file, output_file, hash_file_path):
    cipher = Fernet(key)
    with open(input_file, 'rb') as file:
        encrypted_data = file.read()

    decrypted_data = cipher.decrypt(encrypted_data)
    with open(output_file, 'wb') as file:
        file.write(decrypted_data)

    verification_result = verify_file(output_file, hash_file_path)
    if verification_result:
        print("File decryption and verification successful!")
    else:
        print("File decryption or verification failed.")

def verify_file(input_file, hash_file_path):
    decrypted_hash = calculate_file_hash(input_file)

    with open(hash_file_path, 'r') as hash_file:
        original_hash = hash_file.read().strip()

    return decrypted_hash == original_hash

class FileEncryptorGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("File Encryptor")

        self.key_path = 'secret.key'
        self.key = self.load_or_generate_key()

        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.master, text="Choose operation:").grid(row=0, column=0, columnspan=2, pady=10)

        encrypt_button = tk.Button(self.master, text="Encrypt", command=self.encrypt_file)
        encrypt_button.grid(row=1, column=0, pady=5)

        decrypt_button = tk.Button(self.master, text="Decrypt", command=self.decrypt_file)
        decrypt_button.grid(row=1, column=1, pady=5)

    def load_or_generate_key(self):
        if not os.path.exists(self.key_path):
            key = generate_key()
            save_key(key, self.key_path)
        else:
            key = load_key(self.key_path)
        return key

    def encrypt_file(self):
        input_file = filedialog.askopenfilename(title="Select file to encrypt")
        output_file = filedialog.asksaveasfilename(title="Choose location to save encrypted file")

        if input_file and output_file:
            encrypt_file(self.key, input_file, output_file + '.encrypted')
            print(f'File encrypted: {output_file}.encrypted')

    def decrypt_file(self):
        input_file = filedialog.askopenfilename(title="Select file to decrypt")
        output_file = filedialog.asksaveasfilename(title="Choose location to save decrypted file")
        hash_file_path = filedialog.askopenfilename(title="Select hash file")

        if input_file and output_file and hash_file_path:
            decrypt_file(self.key, input_file, output_file, hash_file_path)

def main():
    root = tk.Tk()
    app = FileEncryptorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
