
#Use Python3.10

#from tanxiangzhong

#chinese

#so Don't 抄袭

#down↓

import os
import base64
import tkinter as tk
import sys
import ctypes
from tkinter import filedialog, messagebox
from Crypto.Cipher import Blowfish
from Crypto.Protocol.KDF import scrypt
def bb():
    def encrypt_file(file_path, key, delete_source=False):
        # Read file content
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Encode data using base64
        encoded_data = base64.b64encode(data)
        
        # Derive key using scrypt
        derived_key = scrypt(key, salt=b'salt', key_len=16, N=2**16, r=8, p=1)
        
        # Initialize Blowfish cipher
        cipher = Blowfish.new(derived_key, Blowfish.MODE_ECB)
        
        # Add padding to make the data length multiple of 8
        padding_length = 8 - len(encoded_data) % 8
        encoded_data += bytes([padding_length]) * padding_length
        
        # Encrypt data
        encrypted_data = cipher.encrypt(encoded_data)
        
        # Write encrypted data to file
        with open(file_path + '.Blowfish', 'wb') as f:
            f.write(encrypted_data)
        
        # Delete source file if specified
        if delete_source:
            os.remove(file_path)

    def decrypt_file(file_path, key, delete_source=False):
        # Read encrypted data from file
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Derive key using scrypt
        derived_key = scrypt(key, salt=b'salt', key_len=16, N=2**16, r=8, p=1)
        
        # Initialize Blowfish cipher
        cipher = Blowfish.new(derived_key, Blowfish.MODE_ECB)
        
        # Decrypt data
        decrypted_data = cipher.decrypt(encrypted_data)
        
        # Remove padding
        padding_length = decrypted_data[-1]
        decrypted_data = decrypted_data[:-padding_length]
        
        # Decode data from base64
        decoded_data = base64.b64decode(decrypted_data)
        
        # Write decrypted data to file
        with open(file_path[:-9], 'wb') as f:
            f.write(decoded_data)
        
        # Delete source file if specified
        if delete_source:
            os.remove(file_path)

    def encrypt_directory(directory_path, key, delete_source=False):
        for dirpath, _, filenames in os.walk(directory_path):
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                encrypt_file(file_path, key, delete_source=delete_source)

    def decrypt_directory(directory_path, key, delete_source=False):
        for dirpath, _, filenames in os.walk(directory_path):
            for filename in filenames:
                if filename.endswith('.Blowfish'):
                    file_path = os.path.join(dirpath, filename)
                    decrypt_file(file_path, key, delete_source=delete_source)

    def select_file():
        file_path = filedialog.askopenfilename()
        if file_path:
            password = password_entry.get()
            if password:
                encrypt_file(file_path, password, delete_source=True)
                messagebox.showinfo("Encryption", "File encrypted successfully.")
            else:
                messagebox.showerror("Error", "Please enter a password.")

    def select_folder():
        folder_path = filedialog.askdirectory()
        if folder_path:
            password = password_entry.get()
            if password:
                encrypt_directory(folder_path, password, delete_source=True)
                messagebox.showinfo("Encryption", "Folder encrypted successfully.")
            else:
                messagebox.showerror("Error", "Please enter a password.")

    def decrypt_file_gui():
        file_path = filedialog.askopenfilename()
        if file_path:
            password = password_entry.get()
            if password:
                decrypt_file(file_path, password, delete_source=True)
                messagebox.showinfo("Decryption", "File decrypted successfully.")
            else:
                messagebox.showerror("Error", "Please enter a password.")

    def decrypt_folder_gui():
        folder_path = filedialog.askdirectory()
        if folder_path:
            password = password_entry.get()
            if password:
                decrypt_directory(folder_path, password, delete_source=True)
                messagebox.showinfo("Decryption", "Folder decrypted successfully.")
            else:
                messagebox.showerror("Error", "Please enter a password.")

    # Create the main window
    root = tk.Tk()
    root.title("File Encryption")
    root.geometry("300x200")

    # Create widgets
    label = tk.Label(root, text="Enter password (2-16 characters):")
    label.pack()

    password_entry = tk.Entry(root, show="*")
    password_entry.pack()

    encrypt_file_button = tk.Button(root, text="Encrypt File", command=select_file)
    encrypt_file_button.pack()

    encrypt_folder_button = tk.Button(root, text="Encrypt Folder", command=select_folder)
    encrypt_folder_button.pack()

    decrypt_file_button = tk.Button(root, text="Decrypt File", command=decrypt_file_gui)
    decrypt_file_button.pack()

    decrypt_folder_button = tk.Button(root, text="Decrypt Folder", command=decrypt_folder_gui)
    decrypt_folder_button.pack()
    root.mainloop()
def get_admin_privileges():
    
    if ctypes.windll.shell32.IsUserAnAdmin():
        bb()
    else:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)

get_admin_privileges()


#end
