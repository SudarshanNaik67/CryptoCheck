import os
import hashlib
import math
import string
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# =========================================================
# CryptoCheck
# Secure File Protection & Integrity Verification
# =========================================================

SALT_SIZE = 16
NONCE_SIZE = 12
HASH_SIZE = 32
KEY_SIZE = 32
ITERATIONS = 600000

selected_file = ""

# Activity history
activity_history = []


# ---------------- COLORS ----------------

BG = "#071426"
HEADER = "#081a31"
SIDEBAR = "#091a2f"
PANEL = "#0d1f38"
PANEL2 = "#102746"
BORDER = "#1d4770"

TEXT = "#eef6ff"
MUTED = "#91a9c4"

BLUE = "#1688ff"
GREEN = "#18c996"
PURPLE = "#7c4dff"
ORANGE = "#f4a62a"
RED = "#ef5350"


# =========================================================
# CRYPTOGRAPHIC FUNCTIONS
# =========================================================

def derive_key(password, salt):
    """
    Generate a 256-bit encryption key from the password.
    """

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS
    )

    return kdf.derive(password.encode("utf-8"))


def sha256_file(file_path):
    """
    Calculate SHA-256 hash of a file.
    """

    sha = hashlib.sha256()

    with open(file_path, "rb") as file:

        while True:

            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            sha.update(chunk)

    return sha.hexdigest()


# =========================================================
# ACTIVITY LOG
# =========================================================

def log_activity(message):

    timestamp = datetime.now().strftime("%H:%M:%S")

    full_message = f"[{timestamp}]  {message}"

    # Store complete history
    activity_history.insert(0, full_message)

    # Display only recent 8 activities on dashboard
    activity_list.delete(0, tk.END)

    for item in activity_history[:8]:
        activity_list.insert(tk.END, item)

    status_var.set("● System Ready")


def show_activity_logs():

    log_window = tk.Toplevel(root)

    log_window.title("CryptoCheck - Activity Logs")
    log_window.geometry("720x520")
    log_window.configure(bg=BG)

    log_window.transient(root)

    # ---------------- HEADER ----------------

    header_frame = tk.Frame(
        log_window,
        bg=HEADER,
        height=75
    )

    header_frame.pack(
        fill="x"
    )

    header_frame.pack_propagate(False)

    tk.Label(
        header_frame,
        text="☷  ACTIVITY LOGS",
        bg=HEADER,
        fg=TEXT,
        font=("Segoe UI", 20, "bold")
    ).pack(
        side="left",
        padx=25
    )

    # ---------------- DESCRIPTION ----------------

    tk.Label(
        log_window,
        text="Security operations performed during this session.",
        bg=BG,
        fg=MUTED,
        font=("Segoe UI", 10)
    ).pack(
        anchor="w",
        padx=25,
        pady=(20, 10)
    )

    # ---------------- LOG BOX ----------------

    log_frame = tk.Frame(
        log_window,
        bg=PANEL,
        highlightthickness=1,
        highlightbackground=BORDER
    )

    log_frame.pack(
        fill="both",
        expand=True,
        padx=25,
        pady=10
    )

    scrollbar = tk.Scrollbar(
        log_frame
    )

    scrollbar.pack(
        side="right",
        fill="y"
    )

    log_box = tk.Listbox(
        log_frame,
        bg=PANEL2,
        fg="#b8cce0",
        bd=0,
        highlightthickness=0,
        font=("Consolas", 10),
        yscrollcommand=scrollbar.set
    )

    log_box.pack(
        side="left",
        fill="both",
        expand=True,
        padx=10,
        pady=10
    )

    scrollbar.config(
        command=log_box.yview
    )

    if activity_history:

        for item in activity_history:
            log_box.insert(tk.END, item)

    else:

        log_box.insert(
            tk.END,
            "No activity recorded yet."
        )

    # ---------------- BUTTONS ----------------

    button_frame = tk.Frame(
        log_window,
        bg=BG
    )

    button_frame.pack(
        fill="x",
        padx=25,
        pady=15
    )

    def clear_logs():

        if not activity_history:
            return

        confirm = messagebox.askyesno(
            "Clear Activity Logs",
            "Are you sure you want to clear all activity logs?",
            parent=log_window
        )

        if confirm:

            activity_history.clear()

            activity_list.delete(
                0,
                tk.END
            )

            activity_list.insert(
                tk.END,
                "No activity recorded."
            )

            log_box.delete(
                0,
                tk.END
            )

            log_box.insert(
                tk.END,
                "No activity recorded yet."
            )

    tk.Button(
        button_frame,
        text="Clear Logs",
        command=clear_logs,
        bg=RED,
        fg="white",
        bd=0,
        padx=20,
        pady=9,
        font=("Segoe UI", 9, "bold")
    ).pack(
        side="left"
    )

    tk.Button(
        button_frame,
        text="Close",
        command=log_window.destroy,
        bg=BLUE,
        fg="white",
        bd=0,
        padx=25,
        pady=9,
        font=("Segoe UI", 9, "bold")
    ).pack(
        side="right"
    )


# =========================================================
# FILE SELECTION
# =========================================================

def select_file():

    global selected_file

    file_path = filedialog.askopenfilename(
        title="Select File"
    )

    if not file_path:
        return

    selected_file = file_path

    file_name_var.set(
        os.path.basename(file_path)
    )

    file_path_var.set(
        file_path
    )

    try:

        file_size = os.path.getsize(
            file_path
        )

        if file_size < 1024:

            size_text = f"{file_size} bytes"

        elif file_size < 1024 * 1024:

            size_text = f"{file_size / 1024:.2f} KB"

        else:

            size_text = (
                f"{file_size / (1024 * 1024):.2f} MB"
            )

        file_size_var.set(
            size_text
        )

    except OSError:

        file_size_var.set(
            "Unknown"
        )

    operation_var.set(
        "File selected"
    )

    log_activity(
        f"Selected: {os.path.basename(file_path)}"
    )


# =========================================================
# ENCRYPT FILE
# =========================================================

def encrypt_file():

    global selected_file

    if not selected_file:

        messagebox.showwarning(
            "No File Selected",
            "Please select a file first."
        )

        return

    password = simpledialog.askstring(
        "Encryption Password",
        "Enter password for encryption:",
        show="*"
    )

    if not password:
        return

    if len(password) < 8:

        messagebox.showwarning(
            "Weak Password",
            "For this application, use at least 8 characters."
        )

        return

    try:

        # Read original file
        with open(selected_file, "rb") as file:

            data = file.read()

        # Generate SHA-256 hash of original file
        original_hash = hashlib.sha256(
            data
        ).digest()

        # Generate random salt
        salt = os.urandom(
            SALT_SIZE
        )

        # Generate random nonce
        nonce = os.urandom(
            NONCE_SIZE
        )

        # Generate key from password
        key = derive_key(
            password,
            salt
        )

        # AES-GCM encryption
        aes = AESGCM(
            key
        )

        encrypted_data = aes.encrypt(
            nonce,
            data,
            None
        )

        # Output file
        output_file = selected_file + ".enc"

        # File structure:
        # SALT + NONCE + ORIGINAL HASH + ENCRYPTED DATA

        with open(output_file, "wb") as file:

            file.write(salt)
            file.write(nonce)
            file.write(original_hash)
            file.write(encrypted_data)

        operation_var.set(
            "Encryption completed"
        )

        integrity_var.set(
            "SHA-256 stored"
        )

        log_activity(
            f"Encrypted: {os.path.basename(selected_file)}"
        )

        messagebox.showinfo(
            "Encryption Successful",
            "File encrypted successfully!\n\n"
            f"Protected file:\n{output_file}\n\n"
            "Encryption: AES-GCM\n"
            "Key derivation: PBKDF2-SHA256\n"
            "Integrity record: SHA-256"
        )

    except Exception as error:

        messagebox.showerror(
            "Encryption Error",
            f"Encryption failed:\n\n{error}"
        )


# =========================================================
# DECRYPT FILE
# =========================================================

def decrypt_file():

    global selected_file

    if not selected_file:

        messagebox.showwarning(
            "No File Selected",
            "Please select an encrypted .enc file first."
        )

        return

    if not selected_file.lower().endswith(".enc"):

        messagebox.showwarning(
            "Invalid File",
            "Please select a CryptoCheck .enc encrypted file."
        )

        return

    password = simpledialog.askstring(
        "Decryption Password",
        "Enter password for decryption:",
        show="*"
    )

    if not password:
        return

    try:

        with open(selected_file, "rb") as file:

            salt = file.read(
                SALT_SIZE
            )

            nonce = file.read(
                NONCE_SIZE
            )

            stored_hash = file.read(
                HASH_SIZE
            )

            encrypted_data = file.read()

        # Basic format validation

        if (
            len(salt) != SALT_SIZE
            or len(nonce) != NONCE_SIZE
            or len(stored_hash) != HASH_SIZE
        ):

            raise ValueError(
                "Invalid or corrupted CryptoCheck file."
            )

        # Recreate key

        key = derive_key(
            password,
            salt
        )

        # AES-GCM decryption

        aes = AESGCM(
            key
        )

        decrypted_data = aes.decrypt(
            nonce,
            encrypted_data,
            None
        )

        # Integrity verification

        current_hash = hashlib.sha256(
            decrypted_data
        ).digest()

        if current_hash != stored_hash:

            raise ValueError(
                "Integrity verification failed."
            )

        # Remove .enc

        output_file = selected_file[:-4]

        with open(output_file, "wb") as file:

            file.write(
                decrypted_data
            )

        operation_var.set(
            "Decryption + integrity verified"
        )

        integrity_var.set(
            "Integrity verified ✓"
        )

        log_activity(
            f"Decrypted & verified: "
            f"{os.path.basename(output_file)}"
        )

        messagebox.showinfo(
            "Decryption Successful",
            "File decrypted successfully!\n\n"
            f"Recovered file:\n{output_file}\n\n"
            "Integrity: VERIFIED ✓"
        )

    except Exception:

        log_activity(
            f"Decryption failed: "
            f"{os.path.basename(selected_file)}"
        )

        messagebox.showerror(
            "Decryption Failed",
            "Incorrect password OR the encrypted file "
            "has been corrupted/modified."
        )


# =========================================================
# INTEGRITY VERIFICATION
# =========================================================

def verify_integrity():

    if not selected_file:

        messagebox.showwarning(
            "No File Selected",
            "Please select a file first."
        )

        return

    try:

        digest = sha256_file(
            selected_file
        )

        integrity_var.set(
            "SHA-256 calculated"
        )

        operation_var.set(
            "Integrity hash generated"
        )

        log_activity(
            f"SHA-256 calculated: "
            f"{os.path.basename(selected_file)}"
        )

        messagebox.showinfo(
            "SHA-256 Integrity Verification",
            f"File:\n{os.path.basename(selected_file)}\n\n"
            f"SHA-256:\n{digest}"
        )

    except Exception as error:

        messagebox.showerror(
            "Integrity Error",
            str(error)
        )


# =========================================================
# PASSWORD ANALYSIS
# =========================================================

def analyze_password():

    password = simpledialog.askstring(
        "Password Security Analysis",
        "Enter a password to analyze:",
        show="*"
    )

    if password is None:
        return

    if not password:

        messagebox.showwarning(
            "Password Analysis",
            "Please enter a password."
        )

        return

    pool_size = 0

    if any(
        c.islower()
        for c in password
    ):

        pool_size += 26

    if any(
        c.isupper()
        for c in password
    ):

        pool_size += 26

    if any(
        c.isdigit()
        for c in password
    ):

        pool_size += 10

    if any(
        c in string.punctuation
        for c in password
    ):

        pool_size += len(
            string.punctuation
        )

    if pool_size > 0:

        entropy = (
            len(password)
            * math.log2(pool_size)
        )

    else:

        entropy = 0

    if entropy < 28:

        strength = "Very Weak"

    elif entropy < 36:

        strength = "Weak"

    elif entropy < 60:

        strength = "Moderate"

    elif entropy < 80:

        strength = "Strong"

    else:

        strength = "Very Strong"

    log_activity(
        "Password security analyzed"
    )

    messagebox.showinfo(
        "Password Security Analysis",
        f"Password Length: {len(password)}\n\n"
        f"Estimated Entropy: {entropy:.1f} bits\n\n"
        f"Security Strength: {strength}"
    )


# =========================================================
# DIGITAL SIGNATURE
# =========================================================

def get_key_paths():

    project_folder = os.path.dirname(
        os.path.abspath(__file__)
    )

    private_key_path = os.path.join(
        project_folder,
        "cryptocheck_private_key.pem"
    )

    public_key_path = os.path.join(
        project_folder,
        "cryptocheck_public_key.pem"
    )

    return private_key_path, public_key_path


def create_signature_keys():

    private_key_path, public_key_path = get_key_paths()

    if os.path.exists(private_key_path) and os.path.exists(public_key_path):

        with open(
            private_key_path,
            "rb"
        ) as file:

            private_key = serialization.load_pem_private_key(
                file.read(),
                password=None
            )

        return private_key

    # Generate new Ed25519 key pair

    private_key = Ed25519PrivateKey.generate()

    public_key = private_key.public_key()

    # Save private key

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open(
        private_key_path,
        "wb"
    ) as file:

        file.write(
            private_bytes
        )

    # Save public key

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(
        public_key_path,
        "wb"
    ) as file:

        file.write(
            public_bytes
        )

    return private_key


def sign_file():

    global selected_file

    if not selected_file:

        messagebox.showwarning(
            "No File Selected",
            "Please select a file first."
        )

        return

    try:

        private_key = create_signature_keys()

        with open(
            selected_file,
            "rb"
        ) as file:

            data = file.read()

        signature = private_key.sign(
            data
        )

        signature_file = selected_file + ".sig"

        with open(
            signature_file,
            "wb"
        ) as file:

            file.write(
                signature
            )

        operation_var.set(
            "Digital signature generated"
        )

        log_activity(
            f"Digital signature generated: "
            f"{os.path.basename(selected_file)}"
        )

        messagebox.showinfo(
            "Signature Generated",
            "Digital signature generated successfully!\n\n"
            f"File:\n{os.path.basename(selected_file)}\n\n"
            f"Signature:\n{signature_file}\n\n"
            "Algorithm: Ed25519"
        )

    except Exception as error:

        messagebox.showerror(
            "Signature Error",
            f"Unable to generate signature:\n\n{error}"
        )


def verify_signature():

    global selected_file

    if not selected_file:

        messagebox.showwarning(
            "No File Selected",
            "Please select the signed file first."
        )

        return

    private_key_path, public_key_path = get_key_paths()

    signature_file = selected_file + ".sig"

    if not os.path.exists(signature_file):

        messagebox.showwarning(
            "Signature Not Found",
            "No .sig signature file was found for the selected file.\n\n"
            "Generate a signature first."
        )

        return

    if not os.path.exists(public_key_path):

        messagebox.showerror(
            "Public Key Missing",
            "CryptoCheck public key was not found."
        )

        return

    try:

        # Load public key

        with open(
            public_key_path,
            "rb"
        ) as file:

            public_key = serialization.load_pem_public_key(
                file.read()
            )

        # Read original file

        with open(
            selected_file,
            "rb"
        ) as file:

            data = file.read()

        # Read signature

        with open(
            signature_file,
            "rb"
        ) as file:

            signature = file.read()

        # Verify

        public_key.verify(
            signature,
            data
        )

        operation_var.set(
            "Digital signature VALID"
        )

        log_activity(
            f"Signature verified: "
            f"{os.path.basename(selected_file)}"
        )

        messagebox.showinfo(
            "Signature Verification",
            "✓ DIGITAL SIGNATURE VALID\n\n"
            f"File:\n{os.path.basename(selected_file)}\n\n"
            "The file matches the generated signature.\n\n"
            "Algorithm: Ed25519"
        )

    except Exception:

        operation_var.set(
            "Digital signature INVALID"
        )

        log_activity(
            f"Signature verification FAILED: "
            f"{os.path.basename(selected_file)}"
        )

        messagebox.showerror(
            "Signature Verification",
            "✗ DIGITAL SIGNATURE INVALID\n\n"
            "The file may have been modified or "
            "the signature does not match."
        )


def show_digital_signature():

    signature_window = tk.Toplevel(root)

    signature_window.title(
        "CryptoCheck - Digital Signature"
    )

    signature_window.geometry(
        "760x560"
    )

    signature_window.configure(
        bg=BG
    )

    signature_window.transient(
        root
    )

    # ---------------- HEADER ----------------

    top = tk.Frame(
        signature_window,
        bg=HEADER,
        height=80
    )

    top.pack(
        fill="x"
    )

    top.pack_propagate(
        False
    )

    tk.Label(
        top,
        text="✎  DIGITAL SIGNATURE",
        bg=HEADER,
        fg=TEXT,
        font=("Segoe UI", 21, "bold")
    ).pack(
        side="left",
        padx=25
    )

    # ---------------- DESCRIPTION ----------------

    tk.Label(
        signature_window,
        text="Create and verify a cryptographic signature for a file.",
        bg=BG,
        fg=MUTED,
        font=("Segoe UI", 10)
    ).pack(
        anchor="w",
        padx=25,
        pady=(22, 12)
    )

    # ---------------- FILE INFORMATION ----------------

    file_panel = tk.Frame(
        signature_window,
        bg=PANEL,
        highlightthickness=1,
        highlightbackground=BORDER
    )

    file_panel.pack(
        fill="x",
        padx=25,
        pady=8
    )

    tk.Label(
        file_panel,
        text="SELECTED FILE",
        bg=PANEL,
        fg=MUTED,
        font=("Segoe UI", 9, "bold")
    ).pack(
        anchor="w",
        padx=18,
        pady=(15, 5)
    )

    signature_file_var = tk.StringVar(
        value=(
            os.path.basename(selected_file)
            if selected_file
            else "No file selected"
        )
    )

    tk.Label(
        file_panel,
        textvariable=signature_file_var,
        bg=PANEL2,
        fg=TEXT,
        font=("Segoe UI", 10, "bold"),
        anchor="w"
    ).pack(
        fill="x",
        padx=18,
        pady=(0, 15),
        ipady=10
    )

    # ---------------- EXPLANATION ----------------

    info = tk.Frame(
        signature_window,
        bg=PANEL2,
        highlightthickness=1,
        highlightbackground=BORDER
    )

    info.pack(
        fill="x",
        padx=25,
        pady=18
    )

    tk.Label(
        info,
        text="HOW IT WORKS",
        bg=PANEL2,
        fg=TEXT,
        font=("Segoe UI", 11, "bold")
    ).pack(
        anchor="w",
        padx=18,
        pady=(15, 6)
    )

    tk.Label(
        info,
        text=(
            "1. Select a file from the main dashboard.\n"
            "2. Generate a digital signature using Ed25519.\n"
            "3. CryptoCheck creates a .sig signature file.\n"
            "4. Verify the signature to detect file changes."
        ),
        bg=PANEL2,
        fg=MUTED,
        font=("Segoe UI", 9),
        justify="left"
    ).pack(
        anchor="w",
        padx=18,
        pady=(0, 15)
    )

    # ---------------- BUTTONS ----------------

    buttons = tk.Frame(
        signature_window,
        bg=BG
    )

    buttons.pack(
        fill="x",
        padx=25,
        pady=8
    )

    tk.Button(
        buttons,
        text="✎  Generate Signature",
        command=sign_file,
        bg=PURPLE,
        fg="white",
        bd=0,
        padx=22,
        pady=11,
        font=("Segoe UI", 10, "bold")
    ).pack(
        side="left",
        padx=(0, 10)
    )

    tk.Button(
        buttons,
        text="✓  Verify Signature",
        command=verify_signature,
        bg=GREEN,
        fg="white",
        bd=0,
        padx=22,
        pady=11,
        font=("Segoe UI", 10, "bold")
    ).pack(
        side="left"
    )

    tk.Button(
        buttons,
        text="Close",
        command=signature_window.destroy,
        bg=BLUE,
        fg="white",
        bd=0,
        padx=25,
        pady=11,
        font=("Segoe UI", 10, "bold")
    ).pack(
        side="right"
    )


# =========================================================
# ABOUT
# =========================================================

def show_about():

    messagebox.showinfo(
        "About CryptoCheck",
        "CryptoCheck v1.0\n\n"
        "A Cryptographic Security System for Secure "
        "File Protection, Integrity Verification and "
        "Password Security Analysis.\n\n"
        "MDM Minor CyberSecurity Project"
    )


# =========================================================
# MAIN WINDOW
# =========================================================

root = tk.Tk()

root.title(
    "CryptoCheck"
)

root.geometry(
    "1180x720"
)

root.minsize(
    1000,
    650
)

root.configure(
    bg=BG
)


# =========================================================
# VARIABLES
# =========================================================

file_name_var = tk.StringVar(
    value="No file selected"
)

file_path_var = tk.StringVar(
    value="Select a file to begin"
)

file_size_var = tk.StringVar(
    value="-"
)

operation_var = tk.StringVar(
    value="Ready"
)

integrity_var = tk.StringVar(
    value="Ready"
)

status_var = tk.StringVar(
    value="● System Ready"
)


# =========================================================
# HEADER
# =========================================================

header = tk.Frame(
    root,
    bg=HEADER,
    height=75
)

header.pack(
    fill="x"
)

header.pack_propagate(
    False
)


brand = tk.Label(
    header,
    text="🛡  CryptoCheck",
    bg=HEADER,
    fg=TEXT,
    font=("Segoe UI", 24, "bold")
)

brand.pack(
    side="left",
    padx=28
)


subtitle = tk.Label(
    header,
    text="SECURE  •  VERIFY  •  PROTECT",
    bg=HEADER,
    fg="#62b6ff",
    font=("Segoe UI", 10, "bold")
)

subtitle.pack(
    side="left",
    padx=10
)


about_button = tk.Button(
    header,
    text="ⓘ",
    command=show_about,
    bg=HEADER,
    fg=TEXT,
    bd=0,
    font=("Segoe UI", 18),
    activebackground=HEADER,
    activeforeground=TEXT
)

about_button.pack(
    side="right",
    padx=25
)


# =========================================================
# BODY
# =========================================================

body = tk.Frame(
    root,
    bg=BG
)

body.pack(
    fill="both",
    expand=True
)


# =========================================================
# SIDEBAR
# =========================================================

sidebar = tk.Frame(
    body,
    bg=SIDEBAR,
    width=205
)

sidebar.pack(
    side="left",
    fill="y"
)

sidebar.pack_propagate(
    False
)


tk.Label(
    sidebar,
    text="WORKSPACE",
    bg=SIDEBAR,
    fg=MUTED,
    font=("Segoe UI", 9, "bold")
).pack(
    anchor="w",
    padx=24,
    pady=(30, 12)
)


def navigation_button(
    text,
    command=None
):

    button = tk.Button(
        sidebar,
        text=text,
        command=command,
        anchor="w",
        bg=SIDEBAR,
        fg=TEXT,
        bd=0,
        padx=24,
        pady=13,
        font=("Segoe UI", 10, "bold"),
        activebackground="#12345a",
        activeforeground=TEXT
    )

    button.pack(
        fill="x",
        padx=8,
        pady=2
    )

    return button


navigation_button(
    "⌂   Home"
)

navigation_button(
    "🔒  File Encryption",
    select_file
)

navigation_button(
    "🔓  File Decryption",
    select_file
)

navigation_button(
    "✓   Integrity Verification",
    verify_integrity
)

navigation_button(
    "🔑  Password Analysis",
    analyze_password
)

# NOW WORKING
navigation_button(
    "✎   Digital Signature",
    show_digital_signature
)

# NOW WORKING
navigation_button(
    "☷   Activity Logs",
    show_activity_logs
)


tk.Label(
    sidebar,
    text="CRYPTOCHECK v1.0",
    bg=SIDEBAR,
    fg="#4d6a87",
    font=("Segoe UI", 8, "bold")
).pack(
    side="bottom",
    pady=20
)


# =========================================================
# MAIN CONTENT
# =========================================================

content = tk.Frame(
    body,
    bg=BG
)

content.pack(
    side="left",
    fill="both",
    expand=True,
    padx=24,
    pady=22
)


# =========================================================
# HERO PANEL
# =========================================================

hero = tk.Frame(
    content,
    bg="#102b55",
    height=125,
    highlightthickness=1,
    highlightbackground="#1a5ea8"
)

hero.pack(
    fill="x"
)

hero.pack_propagate(
    False
)


tk.Label(
    hero,
    text="CRYPTOCHECK",
    bg="#102b55",
    fg=TEXT,
    font=("Segoe UI", 28, "bold")
).pack(
    anchor="w",
    padx=25,
    pady=(20, 2)
)


tk.Label(
    hero,
    text="A cryptographic security system for secure file "
         "protection, integrity verification and password "
         "security analysis.",
    bg="#102b55",
    fg="#b6d1ed",
    font=("Segoe UI", 10),
    wraplength=700,
    justify="left"
).pack(
    anchor="w",
    padx=26
)


# =========================================================
# FILE OPERATIONS PANEL
# =========================================================

file_card = tk.Frame(
    content,
    bg=PANEL,
    highlightthickness=1,
    highlightbackground=BORDER
)

file_card.pack(
    fill="x",
    pady=18
)


tk.Label(
    file_card,
    text="FILE OPERATIONS",
    bg=PANEL,
    fg=TEXT,
    font=("Segoe UI", 14, "bold")
).pack(
    anchor="w",
    padx=20,
    pady=(16, 2)
)


tk.Label(
    file_card,
    text="Select a file to encrypt, decrypt or verify its integrity.",
    bg=PANEL,
    fg=MUTED,
    font=("Segoe UI", 9)
).pack(
    anchor="w",
    padx=20,
    pady=(0, 12)
)


# File selector

file_row = tk.Frame(
    file_card,
    bg=PANEL2,
    highlightthickness=1,
    highlightbackground=BORDER
)

file_row.pack(
    fill="x",
    padx=20,
    pady=(0, 16)
)


tk.Label(
    file_row,
    text="📄",
    bg=PANEL2,
    fg=TEXT,
    font=("Segoe UI", 16)
).pack(
    side="left",
    padx=14
)


tk.Label(
    file_row,
    textvariable=file_name_var,
    bg=PANEL2,
    fg=TEXT,
    font=("Segoe UI", 10, "bold"),
    anchor="w"
).pack(
    side="left",
    fill="x",
    expand=True
)


tk.Button(
    file_row,
    text="Browse",
    command=select_file,
    bg=BLUE,
    fg="white",
    bd=0,
    padx=22,
    pady=9,
    font=("Segoe UI", 10, "bold"),
    activebackground="#0b6fd4"
).pack(
    side="right",
    padx=8,
    pady=8
)


# =========================================================
# ACTION CARDS
# =========================================================

cards = tk.Frame(
    file_card,
    bg=PANEL
)

cards.pack(
    fill="x",
    padx=20,
    pady=(0, 18)
)


def action_card(
    parent,
    title,
    description,
    command,
    accent
):

    frame = tk.Frame(
        parent,
        bg=PANEL2,
        highlightthickness=1,
        highlightbackground=accent
    )

    frame.pack(
        side="left",
        fill="both",
        expand=True,
        padx=4
    )

    tk.Label(
        frame,
        text=title,
        bg=PANEL2,
        fg=TEXT,
        font=("Segoe UI", 12, "bold")
    ).pack(
        anchor="w",
        padx=14,
        pady=(14, 4)
    )

    tk.Label(
        frame,
        text=description,
        bg=PANEL2,
        fg=MUTED,
        font=("Segoe UI", 8),
        wraplength=190,
        justify="left"
    ).pack(
        anchor="w",
        padx=14
    )

    tk.Button(
        frame,
        text="Open",
        command=command,
        bg=accent,
        fg="white",
        bd=0,
        padx=18,
        pady=7,
        font=("Segoe UI", 9, "bold")
    ).pack(
        anchor="w",
        padx=14,
        pady=14
    )


action_card(
    cards,
    "🔒  Encrypt File",
    "Protect a file using password-based AES-GCM encryption.",
    encrypt_file,
    GREEN
)


action_card(
    cards,
    "🔓  Decrypt File",
    "Recover the original file and verify its integrity.",
    decrypt_file,
    BLUE
)


action_card(
    cards,
    "🛡  Verify Integrity",
    "Calculate the SHA-256 hash of the selected file.",
    verify_integrity,
    PURPLE
)


# =========================================================
# LOWER INFORMATION PANELS
# =========================================================

bottom = tk.Frame(
    content,
    bg=BG
)

bottom.pack(
    fill="both",
    expand=True
)


# Security status

security_panel = tk.Frame(
    bottom,
    bg=PANEL,
    highlightthickness=1,
    highlightbackground=BORDER
)

security_panel.pack(
    side="left",
    fill="both",
    expand=True,
    padx=(0, 9)
)


tk.Label(
    security_panel,
    text="SECURITY STATUS",
    bg=PANEL,
    fg=TEXT,
    font=("Segoe UI", 13, "bold")
).pack(
    anchor="w",
    padx=18,
    pady=(15, 8)
)


security_items = [
    ("Encryption", "AES-GCM"),
    ("Integrity", "SHA-256"),
    ("Password Analysis", "Entropy based"),
    ("Digital Signature", "Ed25519")
]


for name, value in security_items:

    row = tk.Frame(
        security_panel,
        bg=PANEL
    )

    row.pack(
        fill="x",
        padx=18,
        pady=5
    )

    tk.Label(
        row,
        text="●  " + name,
        bg=PANEL,
        fg="#a9c5df",
        font=("Segoe UI", 9, "bold")
    ).pack(
        side="left"
    )

    tk.Label(
        row,
        text=value,
        bg=PANEL,
        fg=GREEN,
        font=("Segoe UI", 9, "bold")
    ).pack(
        side="right"
    )


# Recent activity

activity_panel = tk.Frame(
    bottom,
    bg=PANEL,
    highlightthickness=1,
    highlightbackground=BORDER
)

activity_panel.pack(
    side="left",
    fill="both",
    expand=True,
    padx=(9, 0)
)


tk.Label(
    activity_panel,
    text="RECENT ACTIVITY",
    bg=PANEL,
    fg=TEXT,
    font=("Segoe UI", 13, "bold")
).pack(
    anchor="w",
    padx=18,
    pady=(15, 8)
)


activity_list = tk.Listbox(
    activity_panel,
    bg=PANEL2,
    fg="#b8cce0",
    bd=0,
    highlightthickness=0,
    font=("Consolas", 9),
    height=5
)

activity_list.pack(
    fill="both",
    expand=True,
    padx=14,
    pady=(0, 14)
)


activity_list.insert(
    0,
    "System initialized"
)

activity_list.insert(
    1,
    "Waiting for file..."
)


# =========================================================
# FOOTER
# =========================================================

footer = tk.Frame(
    root,
    bg=HEADER,
    height=34
)

footer.pack(
    fill="x",
    side="bottom"
)

footer.pack_propagate(
    False
)


tk.Label(
    footer,
    text="CryptoCheck v1.0  |  MDM Minor CyberSecurity Project",
    bg=HEADER,
    fg=MUTED,
    font=("Segoe UI", 8)
).pack(
    side="left",
    padx=20
)


tk.Label(
    footer,
    textvariable=status_var,
    bg=HEADER,
    fg=GREEN,
    font=("Segoe UI", 8, "bold")
).pack(
    side="right",
    padx=20
)


# =========================================================
# START APPLICATION
# =========================================================

root.mainloop()