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

    # Calculate hash of the original file
    original_hash = calculate_file_hash(input_file)

    # Encrypt the file
    encrypted_data = cipher.encrypt(plaintext)
    with open(output_file, 'wb') as file:
        file.write(encrypted_data)

    # Save the hash value in a separate file
    with open(output_file + '.hash', 'w') as hash_file:
        hash_file.write(original_hash)

def decrypt_file(key, input_file, output_file, hash_file_path):
    cipher = Fernet(key)
    with open(input_file, 'rb') as file:
        encrypted_data = file.read()

    # Decrypt the file
    decrypted_data = cipher.decrypt(encrypted_data)
    with open(output_file, 'wb') as file:
        file.write(decrypted_data)

    # Verify the decrypted file
    verification_result = verify_file(output_file, hash_file_path)
    if verification_result:
        print("File decryption and verification successful!")
    else:
        print("File decryption or verification failed.")

def verify_file(input_file, hash_file_path):
    # Calculate hash of the decrypted file
    decrypted_hash = calculate_file_hash(input_file)

    # Read the original hash value
    with open(hash_file_path, 'r') as hash_file:
        original_hash = hash_file.read().strip()

    # Compare hashes
    return decrypted_hash == original_hash

def main():
    # Generate or load encryption key
    key_path = 'secret.key'
    if not os.path.exists(key_path):
        key = generate_key()
        save_key(key, key_path)
    else:
        key = load_key(key_path)

    # User input for encryption or decryption
    choice = input("Do you want to encrypt (e) or decrypt (d) a file? ").lower()

    if choice == 'e':
        # Specify input and output file paths for encryption
        input_file = input(r"Enter the path of the file to encrypt: ")
        output_file = input(r"Enter the path for the encrypted file: ")

        encrypt_file(key, input_file, output_file)
        print(f'File encrypted: {output_file}')

    elif choice == 'd':
        # Specify input and output file paths for decryption
        input_file = input(r"Enter the path of the file to decrypt: ")
        output_file = input(r"Enter the path for the decrypted file: ")
        hash_file_path = input(r"Enter the path of the hash file: ")

        decrypt_file(key, input_file, output_file, hash_file_path)

    else:
        print("Invalid choice. Please enter 'e' for encryption or 'd' for decryption.")

if __name__ == "__main__":
    main()