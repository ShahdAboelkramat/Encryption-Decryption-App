import hashlib
from Crypto.Cipher import DES
from Crypto.Cipher import AES
from secrets import token_bytes
from tkinter import *
from tkinter import ttk, filedialog
import tkinter as tk
import os

# Affine Cipher Functions
def affine_encrypt(text, a, b):
    result = ""
    for char in text:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            result += chr(((a * (ord(char) - offset) + b) % 26) + offset)
        else:
            result += char
    return result

def affine_decrypt(text, a, b):
    result = ""
    a_inv = pow(a, -1, 26)
    for char in text:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            result += chr(((a_inv * (ord(char) - offset - b)) % 26) + offset)
        else:
            result += char
    return result

# Caesar Cipher Functions
def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            result += chr(((ord(char) - offset + shift) % 26) + offset)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# DES Cipher Functions
key = token_bytes(8)

def des_encrypt(msg):
    cipher = DES.new(key, DES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
    return nonce, ciphertext, tag

def des_decrypt(nonce, ciphertext, tag):
    cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext.decode('ascii')
    except ValueError:
        return "Decryption failed. Integrity check failed."

key2 = token_bytes(16)    
# AES cipher function
def aes_encrypt(msg2):
    cipher2 = AES.new(key2, AES.MODE_EAX)
    nonce2 = cipher2.nonce
    ciphertext2, tag2 = cipher2.encrypt_and_digest(msg2.encode('ascii'))
    return nonce2, ciphertext2, tag2

def aes_decrypt(nonce2, ciphertext2, tag2):
    cipher2 = AES.new(key2, AES.MODE_EAX, nonce=nonce2)
    plaintext = cipher2.decrypt(ciphertext2)
    try:
        cipher2.verify(tag2)
        return plaintext.decode('ascii')
    except ValueError:
        return "Decryption failed. Integrity check failed."


def main_screen():
    Screen = tk.Tk()
    Screen.geometry("375x700")
    Screen.title("Cipher App")
    Screen.configure(bg="white")

    def reset():
        text1.delete(1.0, END)
        result_label.config(state=NORMAL)
        result_label.delete(1.0, END)
        result_label.config(state=DISABLED)
        encrypt_combo.set("Select Encrypt Option")
        decrypt_combo.set("Select Decrypt Option")
        hash_combo.set("Select Hashing Option")
        a_entry.place_forget()
        b_entry.place_forget()
        shift_entry.place_forget()
        key_entry.place_forget()

    def update_key_fields(event):
        a_entry.place_forget()
        b_entry.place_forget()
        shift_entry.place_forget()
        key_entry.place_forget()
        if encrypt_combo.get() == "Affine Encrypt" or decrypt_combo.get() == "Affine Decrypt":
            a_entry.place(x=150, y=230)
            b_entry.place(x=220, y=230)
        elif encrypt_combo.get() == "Caesar Encrypt" or decrypt_combo.get() == "Caesar Decrypt":
            shift_entry.place(x=150, y=230)
        else:
            key_entry.place(x=130, y=270)
    

           
    def process():
        try:
            plaintext = text1.get(1.0, END).strip()
            key_input = key_entry.get().strip()
            # Convert key to bytes if provided
            des_key = bytes.fromhex(key_input) if key_input else token_bytes(8)
            aes_key = bytes.fromhex(key_input) if key_input else token_bytes(16)
            if encrypt_combo.get() == "Affine Encrypt":
                a = int(a_entry.get())
                b = int(b_entry.get())
                result = affine_encrypt(plaintext, a, b)
                update_result(f"Encrypted: {result}", "green")
            elif decrypt_combo.get() == "Affine Decrypt":
                a = int(a_entry.get())
                b = int(b_entry.get())
                result = affine_decrypt(plaintext, a, b)
                update_result(f"Decrypted: {result}", "blue")
            elif encrypt_combo.get() == "Caesar Encrypt":
                shift = int(shift_entry.get())
                result = caesar_encrypt(plaintext, shift)
                update_result(f"Encrypted: {result}", "green")
            elif decrypt_combo.get() == "Caesar Decrypt":
                shift = int(shift_entry.get())
                result = caesar_decrypt(plaintext, shift)
                update_result(f"Decrypted: {result}", "blue")
            elif encrypt_combo.get() == "DES Encrypt":
                global nonce, ciphertext, tag
                nonce, ciphertext, tag = des_encrypt(plaintext)
                if key_input :
                 update_result(f"Encrypted: {ciphertext.hex()}\nKey: {key_input}", "green")
                else:
                 update_result(f"Encrypted: {ciphertext.hex()}\nKey: {key.hex()}", "green")
            elif decrypt_combo.get() == "DES Decrypt":
                if 'nonce' in globals() and 'ciphertext' in globals() and 'tag' in globals():
                    result = des_decrypt(nonce, ciphertext, tag)
                    update_result(f"Decrypted: {result}", "blue")
                else:
                    update_result("No previous DES encryption data available.", "red")
            elif encrypt_combo.get() == "AES Encrypt":
                global nonce2, ciphertext2, tag2
                nonce2, ciphertext2, tag2 = aes_encrypt(plaintext)
                if key_input :
                 update_result(f"Encrypted: {ciphertext2.hex()}\nKey: {key_input}", "green")
                else:
                 update_result(f"Encrypted: {ciphertext2.hex()}\nKey: {key2.hex()}", "green")

            elif decrypt_combo.get() == "AES Decrypt":
                if 'nonce2' in globals() and 'ciphertext2' in globals() and 'tag2' in globals():
                    result = aes_decrypt(nonce2, ciphertext2, tag2)
                    update_result(f"Decrypted: {result}", "blue")
                else:
                    update_result("No previous AES encryption data available.", "red")
            elif hash_combo.get() in ["MD5", "SHA1", "SHA256", "SHA512"]:
                algorithms = {
                    "MD5": hashlib.md5,
                    "SHA1": hashlib.sha1,
                    "SHA256": hashlib.sha256,
                    "SHA512": hashlib.sha512
                                             }
                hash_func = algorithms[hash_combo.get()]()  # Get the appropriate hashing function
                hash_func.update(plaintext.encode('utf-8'))  # Update with the plaintext
                result = hash_func.hexdigest()  # Get the hash as a hex string
                update_result(f"Hashing ({hash_combo.get()}): {result}", "green")
            else:
                update_result("Please select an option to Encrypt or Decrypt.", "red")
        except ValueError:
            update_result("Invalid key values. Enter integers only.", "red")

    def save_result():
        result = result_label.get(1.0, END).strip()
        if result:
            file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
            if file_path:
                with open(file_path, "w") as f:
                    f.write(result)
                update_result("Result saved successfully!", "green")
        else:
            update_result("No result to save.", "red")

    def toggle_theme():
        if Screen["bg"] == "white":
            Screen.config(bg="black")
            text1.config(bg="gray", fg="white")
            result_label.config(bg="gray", fg="white")
            theme_button.config(text="Light Theme", bg="gray", fg="white")
        else:
            Screen.config(bg="white")
            text1.config(bg="white", fg="black")
            result_label.config(bg="white", fg="black")
            theme_button.config(text="Dark Theme", bg="#1089ff", fg="white")

    def upload_file():
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "r") as f:
                text1.delete(1.0, END)
                text1.insert(END, f.read())
            update_result(f"File {os.path.basename(file_path)} uploaded successfully!", "blue")

    Label(text="Enter Encrypt OR Decrypt Message", font=("calibri", 13)).place(x=10, y=10)
    text1 = Text(font="roboto 11", bg="white", wrap=WORD, bd=3)
    text1.place(x=10, y=50, width=355, height=100)

    Label(text="Key", font=("calibri", 13)).place(x=10, y=210)
    a_entry = Entry(Screen, width=5, font=("arial", 15))
    b_entry = Entry(Screen, width=5, font=("arial", 15))
    shift_entry = Entry(Screen, width=5, font=("arial", 15))
    key_label = Label(Screen, text="Key (optional)", font=("calibri", 13)).place(x=10, y=270)
    key_entry = Entry(Screen, font=("arial", 13), width=30)


    encrypt_combo = ttk.Combobox(Screen, values=["Affine Encrypt", "Caesar Encrypt", "DES Encrypt","AES Encrypt"], state="readonly")
    encrypt_combo.set("Select Encrypt Option")
    encrypt_combo.bind("<<ComboboxSelected>>", update_key_fields)
    encrypt_combo.place(x=10, y=310, width=355)

    decrypt_combo = ttk.Combobox(Screen, values=["Affine Decrypt", "Caesar Decrypt", "DES Decrypt","AES Decrypt"], state="readonly")
    decrypt_combo.set("Select Decrypt Option")
    decrypt_combo.bind("<<ComboboxSelected>>", update_key_fields)
    decrypt_combo.place(x=10, y=345, width=355)

    hash_combo = ttk.Combobox(Screen, values=["MD5", "SHA1", "SHA256","SHA512"], state="readonly")
    hash_combo.set("Select Hashing Options")
    hash_combo.bind("<<ComboboxSelected>>", update_key_fields)
    hash_combo.place(x=10, y=380, width=355)

    Button(text="Process", bg="#34eb9e", command=process).place(x=10, y=420, width=355)
    Button(text="Reset", bg="#1089ff", command=reset).place(x=10, y=470, width=355)
    Button(text="Save Result", bg="#ffcc00", command=save_result).place(x=130, y=170, width=100)
    theme_button = Button(text="Dark Theme", bg="#1089ff", fg="white", command=toggle_theme)
    theme_button.place(x=10, y=170, width=100)
    Button(text="Upload File", bg="#ff5733", command=upload_file).place(x=250, y=170, width=100)

    result_label = Text(font=("calibri", 13), height=4, width=37, state=DISABLED, bd=3)
    result_label.place(x=10, y=530)

    def update_result(text, color):
        result_label.config(state=NORMAL)
        result_label.delete(1.0, END)
        result_label.insert(END, text)
        result_label.config(state=DISABLED)
        result_label.tag_configure("result", foreground=color)

    Screen.mainloop()

main_screen()
