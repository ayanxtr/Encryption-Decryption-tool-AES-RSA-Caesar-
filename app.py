import base64
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from tkinter.scrolledtext import ScrolledText
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import os

def caesar_encrypt(text, shift):
    out = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            out.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            out.append(ch)
    return ''.join(out)

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)


def aes_encrypt_text(plaintext, key_b64=None):
    """AES for TEXT: returns (b64(iv+ciphertext), b64(key))"""
    if key_b64:
        key = base64.b64decode(key_b64)
        if len(key) not in (16, 24, 32):
            raise ValueError('Invalid AES key length (must be 16/24/32 bytes in Base64 form)')
    else:
        key = get_random_bytes(16) 
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return base64.b64encode(iv + ct).decode('utf-8'), base64.b64encode(key).decode('utf-8')

def aes_decrypt_text(b64_ciphertext, key_b64):
    data = base64.b64decode(b64_ciphertext)
    key = base64.b64decode(key_b64)
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')


def generate_rsa_keys(bits=2048):
    key = RSA.generate(bits)
    priv = key.export_key()
    pub = key.publickey().export_key()
    return priv.decode('utf-8'), pub.decode('utf-8')

def rsa_encrypt_text(plaintext, public_pem):
    pub = RSA.import_key(public_pem)
    cipher = PKCS1_OAEP.new(pub)
    ct = cipher.encrypt(plaintext.encode('utf-8'))
    return base64.b64encode(ct).decode('utf-8')

def rsa_decrypt_text(b64_ciphertext, private_pem):
    priv = RSA.import_key(private_pem)
    cipher = PKCS1_OAEP.new(priv)
    data = base64.b64decode(b64_ciphertext)
    pt = cipher.decrypt(data)
    return pt.decode('utf-8')


def derive_key_from_password(password: str) -> bytes:
    """Derive a 32-byte AES-256 key from password using SHA-256."""
    h = SHA256.new(password.encode('utf-8'))
    return h.digest()

def encrypt_file_aes(path: str, password: str) -> str:
    """Encrypt any file with AES-CBC. Returns output path."""
    key = derive_key_from_password(password)
    with open(path, 'rb') as f:
        data = f.read()

    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(data, AES.block_size))

    out_path = path + '.enc'
    with open(out_path, 'wb') as f:
        f.write(iv + ct)

    return out_path

def decrypt_file_aes(path: str, password: str) -> str:
    """Decrypt AES-CBC file created by encrypt_file_aes. Returns output path."""
    key = derive_key_from_password(password)
    with open(path, 'rb') as f:
        data = f.read()

    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)


    if path.endswith('.enc'):
        out_path = path[:-4]
    else:
        out_path = path + '.dec'

    with open(out_path, 'wb') as f:
        f.write(pt)

    return out_path


class CryptoGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Encryption / Decryption Tool (Text + Files)')
        self.geometry('950x700')
        self.create_widgets()

    def create_widgets(self):
        top = tk.Frame(self)
        top.pack(fill='x', padx=8, pady=6)

        tk.Label(top, text='Text Method:').pack(side='left')
        self.method_var = tk.StringVar(value='Caesar')
        methods = ['Caesar', 'AES', 'RSA']
        tk.OptionMenu(top, self.method_var, *methods, command=self.on_method_change).pack(side='left')

        self.caesar_frame = tk.Frame(self)
        tk.Label(self.caesar_frame, text='Shift:').pack(side='left')
        self.shift_var = tk.IntVar(value=3)
        tk.Spinbox(self.caesar_frame, from_=-25, to=25, textvariable=self.shift_var, width=6).pack(side='left')

        self.aes_frame = tk.Frame(self)
        tk.Label(self.aes_frame, text='AES Key (Base64, optional for text):').pack(side='left')
        self.aes_key_entry = tk.Entry(self.aes_frame, width=44)
        self.aes_key_entry.pack(side='left', padx=6)
        tk.Button(self.aes_frame, text='Generate Key', command=self.generate_aes_key).pack(side='left')

        self.rsa_frame = tk.Frame(self)
        tk.Button(self.rsa_frame, text='Generate RSA Keypair', command=self.generate_rsa).pack(side='left')
        tk.Label(self.rsa_frame, text='(2048 bits)').pack(side='left', padx=6)

        pan = tk.PanedWindow(self, orient='horizontal')
        pan.pack(fill='both', expand=True, padx=8, pady=6)

        left = tk.Frame(pan)
        pan.add(left, stretch='always')
        right = tk.Frame(pan)
        pan.add(right, stretch='always')

        tk.Label(left, text='Input Text / Encrypted Text:').pack(anchor='w')
        self.input_text = ScrolledText(left, wrap='word', height=16)
        self.input_text.pack(fill='both', expand=True)

        inp_btns = tk.Frame(left)
        inp_btns.pack(fill='x', pady=4)
        tk.Button(inp_btns, text='Load Text File', command=self.load_file_to_input).pack(side='left')
        tk.Button(inp_btns, text='Clear', command=lambda: self.input_text.delete('1.0', 'end')).pack(side='left', padx=6)

        tk.Label(right, text='Output Text:').pack(anchor='w')
        self.output_text = ScrolledText(right, wrap='word', height=16)
        self.output_text.pack(fill='both', expand=True)

        out_btns = tk.Frame(right)
        out_btns.pack(fill='x', pady=4)
        tk.Button(out_btns, text='Save Output Text', command=self.save_output_text).pack(side='left')
        tk.Button(out_btns, text='Copy Output', command=self.copy_output).pack(side='left', padx=6)

        rsa_keys = tk.Frame(self)
        rsa_keys.pack(fill='x', padx=8, pady=4)
        tk.Label(rsa_keys, text='Public Key (PEM):').grid(row=0, column=0, sticky='w')
        tk.Label(rsa_keys, text='Private Key (PEM):').grid(row=0, column=1, sticky='w')
        self.pub_text = tk.Text(rsa_keys, height=6, width=50)
        self.pub_text.grid(row=1, column=0, padx=6)
        self.priv_text = tk.Text(rsa_keys, height=6, width=50)
        self.priv_text.grid(row=1, column=1, padx=6)

        act = tk.Frame(self)
        act.pack(fill='x', padx=8, pady=6)
        tk.Button(act, text='Encrypt Text', command=self.encrypt_text_action, width=14).pack(side='left')
        tk.Button(act, text='Decrypt Text', command=self.decrypt_text_action, width=14).pack(side='left', padx=6)
        tk.Button(act, text='Clear Output', command=lambda: self.output_text.delete('1.0', 'end')).pack(side='left', padx=6)

        file_frame = tk.LabelFrame(self, text='File Encryption (AES + Password)', padx=8, pady=8)
        file_frame.pack(fill='x', padx=8, pady=8)

        tk.Button(file_frame, text='Encrypt File (AES)', command=self.encrypt_file_action, width=18).pack(side='left')
        tk.Button(file_frame, text='Decrypt File (AES)', command=self.decrypt_file_action, width=18).pack(side='left', padx=8)
        tk.Label(file_frame, text='(Any file: PDF, image, video, docs, etc.)').pack(side='left')

        self.on_method_change('Caesar')

    def on_method_change(self, method):
        # hide all
        self.caesar_frame.pack_forget()
        self.aes_frame.pack_forget()
        self.rsa_frame.pack_forget()
        if method == 'Caesar':
            self.caesar_frame.pack(fill='x', padx=8)
        elif method == 'AES':
            self.aes_frame.pack(fill='x', padx=8)
        elif method == 'RSA':
            self.rsa_frame.pack(fill='x', padx=8)

    def load_file_to_input(self):
        path = filedialog.askopenfilename(filetypes=[('Text files','*.txt'),('All files','*.*')])
        if not path:
            return
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                data = f.read()
            self.input_text.delete('1.0', 'end')
            self.input_text.insert('1.0', data)
        except Exception as e:
            messagebox.showerror('Error', str(e))

    def save_output_text(self):
        path = filedialog.asksaveasfilename(defaultextension='.txt', filetypes=[('Text files','*.txt')])
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(self.output_text.get('1.0', 'end').rstrip('\n'))
            messagebox.showinfo('Saved', f'Saved to {path}')
        except Exception as e:
            messagebox.showerror('Error', str(e))

    def copy_output(self):
        out = self.output_text.get('1.0', 'end').rstrip('\n')
        self.clipboard_clear()
        self.clipboard_append(out)
        messagebox.showinfo('Copied', 'Output text copied to clipboard')

    def generate_aes_key(self):
        key = get_random_bytes(16)
        self.aes_key_entry.delete(0, 'end')
        self.aes_key_entry.insert(0, base64.b64encode(key).decode('utf-8'))
        messagebox.showinfo('AES Key', 'New AES key (Base64) generated for TEXT')

    def generate_rsa(self):
        priv, pub = generate_rsa_keys()
        self.priv_text.delete('1.0', 'end')
        self.pub_text.delete('1.0', 'end')
        self.pub_text.insert('1.0', pub)
        self.priv_text.insert('1.0', priv)
        messagebox.showinfo('RSA Keys', 'RSA keypair generated (PEM)')

    def encrypt_text_action(self):
        method = self.method_var.get()
        data = self.input_text.get('1.0', 'end').rstrip('\n')
        if not data:
            messagebox.showwarning('Input required', 'Please enter input text or load a text file')
            return
        try:
            if method == 'Caesar':
                shift = self.shift_var.get()
                out = caesar_encrypt(data, shift)
                self.output_text.delete('1.0', 'end')
                self.output_text.insert('1.0', out)

            elif method == 'AES':
                key_b64 = self.aes_key_entry.get().strip() or None
                cipher_b64, used_key = aes_encrypt_text(data, key_b64)
                self.output_text.delete('1.0', 'end')
                self.output_text.insert('1.0', f'Ciphertext (Base64):\n{cipher_b64}\n\nAES Key (Base64):\n{used_key}')

            elif method == 'RSA':
                pub = self.pub_text.get('1.0', 'end').strip()
                if not pub:
                    messagebox.showwarning('Public key', 'Please paste/generate a public key (PEM) in the Public Key box')
                    return
                ct = rsa_encrypt_text(data, pub)
                self.output_text.delete('1.0', 'end')
                self.output_text.insert('1.0', ct)

        except Exception as e:
            messagebox.showerror('Error', str(e))

    def decrypt_text_action(self):
        method = self.method_var.get()
        data = self.input_text.get('1.0', 'end').rstrip('\n')
        if not data:
            messagebox.showwarning('Input required', 'Please enter ciphertext or load a text file')
            return
        try:
            if method == 'Caesar':
                shift = self.shift_var.get()
                out = caesar_decrypt(data, shift)
                self.output_text.delete('1.0', 'end')
                self.output_text.insert('1.0', out)

            elif method == 'AES':
                key_b64 = self.aes_key_entry.get().strip()
                if not key_b64:
                    messagebox.showwarning('AES key', 'Please provide the AES key (Base64) used to encrypt the text')
                    return
                pt = aes_decrypt_text(data, key_b64)
                self.output_text.delete('1.0', 'end')
                self.output_text.insert('1.0', pt)

            elif method == 'RSA':
                priv = self.priv_text.get('1.0', 'end').strip()
                if not priv:
                    messagebox.showwarning('Private key', 'Please paste/generate the private key (PEM) in the Private Key box')
                    return
                pt = rsa_decrypt_text(data, priv)
                self.output_text.delete('1.0', 'end')
                self.output_text.insert('1.0', pt)

        except Exception as e:
            messagebox.showerror('Error', str(e))
          
    def encrypt_file_action(self):
        path = filedialog.askopenfilename(title='Select file to encrypt')
        if not path:
            return
        password = simpledialog.askstring('Password', 'Enter password for file encryption:', show='*')
        if not password:
            messagebox.showwarning('Password required', 'File encryption cancelled (no password provided)')
            return
        try:
            out_path = encrypt_file_aes(path, password)
            messagebox.showinfo('File Encrypted', f'Encrypted file saved as:\n{out_path}')
        except Exception as e:
            messagebox.showerror('Error', str(e))

    def decrypt_file_action(self):
        path = filedialog.askopenfilename(title='Select file to decrypt', filetypes=[('Encrypted files','*.enc'), ('All files','*.*')])
        if not path:
            return
        password = simpledialog.askstring('Password', 'Enter password used for encryption:', show='*')
        if not password:
            messagebox.showwarning('Password required', 'File decryption cancelled (no password provided)')
            return
        try:
            out_path = decrypt_file_aes(path, password)
            messagebox.showinfo('File Decrypted', f'Decrypted file saved as:\n{out_path}')
        except ValueError:
            messagebox.showerror('Error', 'Wrong password or corrupted file (padding error)')
        except Exception as e:
            messagebox.showerror('Error', str(e))


if __name__ == '__main__':
    app = CryptoGUI()
    app.mainloop()
