from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import tkinter as tk
import sqlite3
from tkinter import messagebox
from tkinter import ttk
import os
import random
import string
import math
import base64
from faker import Faker



############################################################
#encryption and decryption 
############################################################
TEST_MASTER_KEY = b'super_secure_master_key'  # store this better or generate randomly and store

# Derive AES key using PBKDF2
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

# AES Encryption
def encrypt_data(data, key):
    iv = os.urandom(16)  # Random IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

# AES Decryption
def decrypt_data(encrypted_data, key):
    encrypted_data = base64.b64decode(encrypted_data)
    iv, ciphertext = encrypted_data[:16], encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(ciphertext) + decryptor.finalize()).decode()

# Securely generate salt
def generate_salt():
    return os.urandom(16)




##################################################################
# Database creation if not made and fill
##################################################################
DATABASE_NAME = 'tellmeee.db'

# Initialize Faker instance
fake = Faker()

# Connect to SQLite database (or create if it doesn't exist)
conn = sqlite3.connect(DATABASE_NAME)
cursor = conn.cursor()
# Connect to SQLite database (or create if it doesn't exist)
conn = sqlite3.connect(DATABASE_NAME)
cursor = conn.cursor()

# Create tables with salt in patients table
cursor.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    salt TEXT NOT NULL,
    user_type TEXT NOT NULL
)''')

cursor.execute('''CREATE TABLE IF NOT EXISTS patients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    gender BOOLEAN NOT NULL,
    age INTEGER NOT NULL,
    weight REAL NOT NULL,
    height REAL NOT NULL,
    health_history TEXT,
    salt TEXT NOT NULL,  -- Added salt field for each patient
    FOREIGN KEY (user_id) REFERENCES users(id)
)''')

conn.commit()

# Check if the "test" user exists, if not add it
cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'test'")
if cursor.fetchone()[0] == 0:
    salt = generate_salt()
    key = derive_key(TEST_MASTER_KEY, salt)
    encrypted_password = encrypt_data('pass', key)
    cursor.execute("INSERT INTO users (username, password, salt, user_type) VALUES (?, ?, ?, ?)",
                   ('test', encrypted_password, base64.b64encode(salt).decode(), 'admin'))

# Generate and encrypt fake patient data
cursor.execute("SELECT COUNT(*) FROM patients")
patient_count = cursor.fetchone()[0]

if patient_count < 100:
    for _ in range(100 - patient_count):
        username = fake.user_name()
        password = fake.password()
        user_salt = generate_salt()
        user_key = derive_key(TEST_MASTER_KEY, user_salt)
        encrypted_password = encrypt_data(password, user_key)

        cursor.execute("INSERT INTO users (username, password, salt, user_type) VALUES (?, ?, ?, ?)",
                       (username, encrypted_password, base64.b64encode(user_salt).decode(), random.choice(['regular', 'admin'])))
        user_id = cursor.lastrowid

        # Generate and encrypt patient data
        patient_salt = generate_salt()
        patient_key = derive_key(TEST_MASTER_KEY, patient_salt)

        first_name = fake.first_name()
        last_name = fake.last_name()
        gender = random.choice([True, False])
        age = random.randint(18, 80)
        weight = round(random.uniform(110, 220), 2)
        height = round(random.uniform(4.5, 6.5), 2)
        health_history = fake.text(max_nb_chars=200)

        encrypted_first_name = encrypt_data(first_name, patient_key)
        encrypted_last_name = encrypt_data(last_name, patient_key)
        encrypted_health_history = encrypt_data(health_history, patient_key)

        cursor.execute('''INSERT INTO patients (user_id, first_name, last_name, gender, age, weight, height, health_history, salt)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                       (user_id, encrypted_first_name, encrypted_last_name, gender, age, weight, height, encrypted_health_history,
                        base64.b64encode(patient_salt).decode()))

conn.commit()
conn.close()




#############################################################################
#get data from patients database and view in window
############################################################################
def fetch_patients():
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT first_name, last_name, gender, age, weight, height, health_history, salt FROM patients")
    rows = cursor.fetchall()
    conn.close()

    decrypted_rows = []
    for row in rows:
        encrypted_first_name, encrypted_last_name, gender, age, weight, height, encrypted_health_history, stored_salt = row
        stored_salt = base64.b64decode(stored_salt)
        key = derive_key(TEST_MASTER_KEY, stored_salt)  # Derive the key
        
        decrypted_rows.append((
            decrypt_data(encrypted_first_name, key),
            decrypt_data(encrypted_last_name, key),
            'Male' if gender else 'Female',
            age,
            weight,
            height,
            decrypt_data(encrypted_health_history, key),
        ))

    return decrypted_rows

def display_patients():
    patients = fetch_patients()  # Fetch and decrypt patient data

    # Clear existing data
    for row in tree.get_children():
        tree.delete(row)

    # Insert decrypted data into the Treeview
    for patient in patients:
        tree.insert("", "end", values=patient)


# Function to show the patient list window
def show_patient_list():
    global tree

    # Create a new window for patient list
    patient_window = tk.Tk()
    patient_window.title("Patients Database Viewer")

    # Create a Treeview widget to display the patient data
    tree = ttk.Treeview(patient_window, columns=("First Name", "Last Name", "Gender", "Age", "Weight", "Height", "Health History"), show="headings")

    # Define headings for the columns
    tree.heading("First Name", text="First Name")
    tree.heading("Last Name", text="Last Name")
    tree.heading("Gender", text="Gender")
    tree.heading("Age", text="Age")
    tree.heading("Weight", text="Weight (lbs)")
    tree.heading("Height", text="Height (ft)")
    tree.heading("Health History", text="Health History")

    # Set column widths
    tree.column("First Name", width=100)
    tree.column("Last Name", width=100)
    tree.column("Gender", width=70)
    tree.column("Age", width=50)
    tree.column("Weight", width=70)
    tree.column("Height", width=70)
    tree.column("Health History", width=200)

    # Add a scrollbar to the Treeview
    scrollbar = tk.Scrollbar(patient_window, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side="right", fill="y")

    # Pack the Treeview widget
    tree.pack(padx=10, pady=10)

    # Add a button to fetch and display patient data
    button = tk.Button(patient_window, text="Load Patients", command=display_patients)
    button.pack(pady=10)

    # Run the Tkinter main loop for the patient list window
    patient_window.mainloop()



###################################################
#login window and functionality
######################################################

def login():
    username = username_entry.get()
    password = password_entry.get()

    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    
    # Fetch user info for the entered username
    cursor.execute("SELECT password, salt FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if user:
        encrypted_password, stored_salt = user
        stored_salt = base64.b64decode(stored_salt)
        key = derive_key(TEST_MASTER_KEY, stored_salt)  # Derive the key
        decrypted_password = decrypt_data(encrypted_password, key)
        
        if password == decrypted_password:  # Compare the decrypted password
            login_window.destroy()  # Close login window
            show_patient_list()  # Show the patient list
            conn.close()
            return
    
    conn.close()
    messagebox.showerror("Login Failed", "Invalid username or password. Please try again.")

# Function to create the login window
def create_login_window():
    global login_window, username_entry, password_entry
    
    login_window = tk.Tk()
    login_window.title("Login")

    # Username label and entry
    username_label = tk.Label(login_window, text="Username")
    username_label.pack(pady=5)
    username_entry = tk.Entry(login_window)
    username_entry.pack(pady=5)

    # Password label and entry
    password_label = tk.Label(login_window, text="Password")
    password_label.pack(pady=5)
    password_entry = tk.Entry(login_window, show="*")
    password_entry.pack(pady=5)

    # Login button
    login_button = tk.Button(login_window, text="Login", command=login)
    login_button.pack(pady=10)

    # Run the login window
    login_window.mainloop()

# Start the program by creating the login window
create_login_window()
