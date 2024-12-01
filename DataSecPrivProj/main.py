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
import hashlib

# MASTER_KEY = b'super_secure_master_key'
MASTER_KEY = os.getenv("MASTER_KEY")

if not MASTER_KEY:
    raise ValueError("Error: MASTER_KEY environment variable is not set!")

# Convert to bytes
if isinstance(MASTER_KEY, str):
    MASTER_KEY = MASTER_KEY.encode()  # Convert the string to bytes

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

# Hashing the data (using SHA-256)
def hash_data(data):
    hash_object = hashlib.sha256(data.encode())
    return hash_object.hexdigest()

# Verifying hash after decryption
def verify_data_integrity(encrypted_data, key, stored_hash):
    decrypted_data = decrypt_data(encrypted_data, key)
    # Compute the hash of the decrypted data
    computed_hash = hash_data(decrypted_data)
    # Compare the computed hash with the stored hash
    return computed_hash == stored_hash

###########################################################
# Database creation if not made and filling with users
###########################################################
HOSPITAL_DB = 'Hospital.db'

# Initialize Faker instance
fake = Faker()

# Connect to SQLite database (or create if it doesn't exist)
conn = sqlite3.connect(HOSPITAL_DB)
cursor = conn.cursor()

# Create tables with salt in patients table (updated to not store the plain password)
cursor.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    passwordhash TEXT NOT NULL,  -- Storing password hash only
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
    salt TEXT NOT NULL,
    patient_data_hash TEXT, -- not sure if we will use just in case
    FOREIGN KEY (user_id) REFERENCES users(id)
)''')

conn.commit()

# Check if the "test" user exists, if not add it
cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'test'")
if cursor.fetchone()[0] == 0:
    salt = generate_salt()  # Generate salt for the user
    key = derive_key(MASTER_KEY, salt)  # Derive the key
    encrypted_password = encrypt_data('pass', key)  # Encrypt password using the derived key

    password_hash = hash_data('pass')  # Hash the password for storage

    # Insert the user (username, encrypted password, password hash, salt, user type)
    cursor.execute("INSERT INTO users (username, passwordhash, salt, user_type) VALUES (?, ?, ?, ?)",
                   ('test', password_hash, base64.b64encode(salt).decode(), 'h'))

# Check if the "test2" user exists, if not add it
cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'test2'")
if cursor.fetchone()[0] == 0:
    salt = generate_salt()  # Generate salt for the user
    key = derive_key(MASTER_KEY, salt)  # Derive the key
    encrypted_password = encrypt_data('pass', key)  # Encrypt password using the derived key

    password_hash = hash_data('pass')  # Hash the password for storage

    # Insert the user (username, encrypted password, password hash, salt, user type)
    cursor.execute("INSERT INTO users (username, passwordhash, salt, user_type) VALUES (?, ?, ?, ?)",
                   ('test2', password_hash, base64.b64encode(salt).decode(), 'r'))

# Generate and encrypt fake patient data
cursor.execute("SELECT COUNT(*) FROM patients")
patient_count = cursor.fetchone()[0]

if patient_count < 100:
    for _ in range(100 - patient_count):
        username = fake.user_name()
        password = fake.password()
        user_salt = generate_salt()
        user_key = derive_key(MASTER_KEY, user_salt)
        encrypted_password = encrypt_data(password, user_key)
        user_type = random.choice(['h', 'r'])  # 'h' for no first last name, 'r' for all

        # Hash the password for storage
        user_password_hash = hash_data(password)

        cursor.execute("INSERT INTO users (username, salt, user_type, passwordhash) VALUES (?, ?, ?, ?)",
                       (username, base64.b64encode(user_salt).decode(), user_type, user_password_hash))
        user_id = cursor.lastrowid  # Get the last inserted user ID

        # Generate and encrypt patient data
        patient_salt = generate_salt()
        patient_key = derive_key(MASTER_KEY, patient_salt)

        first_name = fake.first_name()
        last_name = fake.last_name()
        gender = random.choice([True, False])
        age = random.randint(18, 80)
        weight = round(random.uniform(110, 220), 2)
        height = round(random.uniform(4.5, 6.5), 2)
        health_history = fake.text(max_nb_chars=200)

        # Hash patient data before encryption (for integrity check)
        patient_data_string = f"{first_name}{last_name}{gender}{age}{weight}{height}{health_history}"
        patient_data_hash = hash_data(patient_data_string)

        encrypted_first_name = encrypt_data(first_name, patient_key)
        encrypted_last_name = encrypt_data(last_name, patient_key)
        encrypted_gender = encrypt_data(str(gender), patient_key)
        encrypted_age = encrypt_data(str(age), patient_key)
        encrypted_weight = encrypt_data(str(weight), patient_key)
        encrypted_height = encrypt_data(str(height), patient_key)
        encrypted_health_history = encrypt_data(health_history, patient_key)

        cursor.execute('''INSERT INTO patients (user_id, first_name, last_name, gender, age, weight, height, health_history, salt, patient_data_hash)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                       (user_id, encrypted_first_name, encrypted_last_name, encrypted_gender, encrypted_age, encrypted_weight, encrypted_height, encrypted_health_history,
                        base64.b64encode(patient_salt).decode(), patient_data_hash))

# Commit the changes and close the connection
conn.commit()
conn.close()

#############################################################################
#get data from patients database and view in window
############################################################################
def fetch_patients(is_admin, search_criteria=None):
    conn = sqlite3.connect(HOSPITAL_DB)
    cursor = conn.cursor()

    # Base query for fetching data
    query = "SELECT first_name, last_name, gender, age, weight, height, health_history, salt FROM patients"

    # Add filter conditions based on the search criteria provided
    conditions = []
    params = []

    if search_criteria:
        if 'first_name' in search_criteria and search_criteria['first_name']:
            conditions.append("first_name IS NOT NULL")  # Placeholder to fetch all records, as search happens in Python
        if 'last_name' in search_criteria and search_criteria['last_name']:
            conditions.append("last_name IS NOT NULL")  # Same here for last name
        if 'weight' in search_criteria and search_criteria['weight']:
            # Added a tolerance since some of the Faker numbers are strange
            tolerance = 5
            conditions.append("(weight BETWEEN ? AND ?)")
            params.append(float(search_criteria['weight']) - tolerance)  # Convert weight to float
            params.append(float(search_criteria['weight']) + tolerance)  # Convert weight to float
        if 'gender' in search_criteria and search_criteria['gender']:
            conditions.append("gender = ?")
            params.append(search_criteria['gender'])
        if 'height' in search_criteria and search_criteria['height']:
            # Added tolerance since some of the Faker numbers are strange
            tolerance = 0.05
            conditions.append("(height BETWEEN ? AND ?)")
            params.append(float(search_criteria['height']) - tolerance)  # Convert height to float
            params.append(float(search_criteria['height']) + tolerance)  # Convert height to float
        if 'age' in search_criteria and search_criteria['age']:
            conditions.append("age = ?")
            params.append(int(search_criteria['age']))  # Convert age to integer

    # Append conditions to the base query if any
    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    conn.close()

    decrypted_rows = []
    for row in rows:
        encrypted_first_name, encrypted_last_name, encrypted_gender, encrypted_age, encrypted_weight, encrypted_height, encrypted_health_history, stored_salt = row
        stored_salt = base64.b64decode(stored_salt)
        key = derive_key(MASTER_KEY, stored_salt)  # Derive the key

        # Decrypt values
        decrypted_first_name = decrypt_data(encrypted_first_name, key)
        decrypted_last_name = decrypt_data(encrypted_last_name, key)
        decrypted_health_history = decrypt_data(encrypted_health_history, key)
        decrypted_gender = decrypt_data(encrypted_gender, key)
        decrypted_age = decrypt_data(encrypted_age, key)
        decrypted_weight = decrypt_data(encrypted_weight, key)
        decrypted_height = decrypt_data(encrypted_height, key)

        # Convert decrypted values back to their correct types
        decrypted_gender = decrypted_gender == "True"  # Convert back to boolean
        decrypted_age = int(decrypted_age)  # Convert back to integer
        decrypted_weight = float(decrypted_weight)  # Convert back to float
        decrypted_height = float(decrypted_height)  # Convert back to float

        # Filter based on search criteria in Python
        if search_criteria:
            if 'first_name' in search_criteria and search_criteria[
                'first_name'].lower() not in decrypted_first_name.lower():
                continue
            if 'last_name' in search_criteria and search_criteria[
                'last_name'].lower() not in decrypted_last_name.lower():
                continue

        # Append decrypted data to the list
        if is_admin:
            decrypted_rows.append((  # Admin can see all details
                decrypted_first_name,
                decrypted_last_name,
                'Male' if decrypted_gender else 'Female',
                decrypted_age,
                decrypted_weight,
                decrypted_height,
                decrypted_health_history,
            ))
        else:
            decrypted_rows.append((  # Non-admin sees limited info
                "Anonymous",
                "Anonymous",
                'Male' if decrypted_gender else 'Female',
                decrypted_age,
                decrypted_weight,
                decrypted_height,
                decrypted_health_history,
            ))

    return decrypted_rows


# Function to create a search window
def search_patients(is_admin):
    def perform_search():
        filters = {
            'first_name': first_name_entry.get() if first_name_entry.get() else None,
            'last_name': last_name_entry.get() if last_name_entry.get() else None,
            'gender': gender_entry.get().strip().lower() if gender_entry.get() else None,
            'age': age_entry.get() if age_entry.get() else None,
            'weight': weight_entry.get() if weight_entry.get() else None,
            'height': height_entry.get() if height_entry.get() else None,
        }

        # Handle gender as 'male' and 'female' or None
        if filters['gender'] == '1':
            filters['gender'] = 'male'
        elif filters['gender'] == '0':
            filters['gender'] = 'female'

        # Convert age, weight, and height to integers/floats if provided
        if filters['age']:
            filters['age'] = str(int(filters['age']))  # Convert to string representation
        if filters['weight']:
            filters['weight'] = str(float(filters['weight']))  # Convert to string representation
        if filters['height']:
            filters['height'] = str(float(filters['height']))  # Convert to string representation

        # Remove filters that are still None or empty (this avoids unnecessary database search criteria)
        filters = {key: value for key, value in filters.items() if value is not None}

        # Fetch patients with the filters
        patients = fetch_patients(is_admin, filters)

        # Clear existing data in the Treeview
        for row in tree.get_children():
            tree.delete(row)

        # Insert search results into the Treeview
        for patient in patients:
            tree.insert("", "end", values=patient)

    # Create a new window for search functionality
    search_window = tk.Toplevel()
    search_window.title("Search Patients")

    if is_admin:
        tk.Label(search_window, text="First Name").grid(row=0, column=0, padx=5, pady=5)
        first_name_entry = tk.Entry(search_window)
        first_name_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(search_window, text="Last Name").grid(row=1, column=0, padx=5, pady=5)
        last_name_entry = tk.Entry(search_window)
        last_name_entry.grid(row=1, column=1, padx=5, pady=5)

    tk.Label(search_window, text="Gender (1 for Male, 0 for Female)").grid(row=2, column=0, padx=5, pady=5)
    gender_entry = tk.Entry(search_window)
    gender_entry.grid(row=2, column=1, padx=5, pady=5)

    tk.Label(search_window, text="Age").grid(row=3, column=0, padx=5, pady=5)
    age_entry = tk.Entry(search_window)
    age_entry.grid(row=3, column=1, padx=5, pady=5)

    tk.Label(search_window, text="Weight").grid(row=4, column=0, padx=5, pady=5)
    weight_entry = tk.Entry(search_window)
    weight_entry.grid(row=4, column=1, padx=5, pady=5)

    tk.Label(search_window, text="Height").grid(row=5, column=0, padx=5, pady=5)
    height_entry = tk.Entry(search_window)
    height_entry.grid(row=5, column=1, padx=5, pady=5)

    search_button = tk.Button(search_window, text="Search", command=perform_search)
    search_button.grid(row=6, column=0, columnspan=2, pady=10)


def display_patients(is_admin):
    patients = fetch_patients(is_admin)  # Fetch and decrypt patient data

    # Clear existing data
    for row in tree.get_children():
        tree.delete(row)

    # Insert decrypted data into the Treeview
    for patient in patients:
        tree.insert("", "end", values=patient)

# Function to show the patient list window
def show_patient_list(is_admin):
    global tree
    # Create a new window for patient list
    patient_window = tk.Tk()
    patient_window.title("Patients Database Viewer")

    # Create a Treeview widget to display the patient data
    tree = ttk.Treeview(patient_window, columns=("First Name", "Last Name", "Gender", "Age", "Weight", "Height", "Health History"), show="headings", height=5)

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
    tree.pack(padx=10, pady=10, expand=True, fill="both")

    #Added a label for the health history
    health_history_label = tk.Label(patient_window, text="Health History Summary")
    health_history_label.pack(padx=10, pady=(10, 5))

    # Add a Text widget to display the "Health History" stuff
    health_history_text = tk.Text(patient_window, height=5, wrap=tk.WORD)
    health_history_text.pack(padx=10, pady=10, fill="x")

    # Function to update the Text widget with Health History content
    def show_health_history(event):
        selected_item = tree.selection()
        if selected_item:
            item = tree.item(selected_item)
            health_history_text.delete("1.0", tk.END)
            health_history_text.insert(tk.END, item["values"][-1])  # Last column is Health History

    # Bind the Treeview selection to update the Text widget
    tree.bind("<<TreeviewSelect>>", show_health_history)

    # Create a frame to hold the buttons in a row
    button_frame = tk.Frame(patient_window)
    button_frame.pack(pady=10)  # Add vertical padding for spacing

    # Add buttons to the frame
    load_button = tk.Button(button_frame, text="Load Patients", command=lambda: display_patients(is_admin))
    load_button.pack(side=tk.LEFT, padx=5)  # Add horizontal padding for spacing

    search_button = tk.Button(button_frame, text="Search Patients", command=lambda: search_patients(is_admin))
    search_button.pack(side=tk.LEFT, padx=5)

    if is_admin:
        add_patient_button = tk.Button(button_frame, text="Add Patient", command=lambda: manage_patient(is_admin))
        add_patient_button.pack(side=tk.LEFT, padx=5)

    # Run the Tkinter main loop for the patient list window
    patient_window.mainloop()

def manage_patient(is_admin):
    if not is_admin:
        messagebox.showerror("Permission Denied", "You do not have the necessary privileges.")
        return

    # Create a new window to manage patient data
    manage_patient_window = tk.Toplevel()
    manage_patient_window.title("Manage Patient")

    # Create common input fields for both actions
    tk.Label(manage_patient_window, text="First Name").grid(row=0, column=0, padx=5, pady=5)
    first_name_entry = tk.Entry(manage_patient_window)
    first_name_entry.grid(row=0, column=1, padx=5, pady=5)

    tk.Label(manage_patient_window, text="Last Name").grid(row=1, column=0, padx=5, pady=5)
    last_name_entry = tk.Entry(manage_patient_window)
    last_name_entry.grid(row=1, column=1, padx=5, pady=5)

    # Additional fields for adding a patient
    tk.Label(manage_patient_window, text="Gender (M/F)").grid(row=2, column=0, padx=5, pady=5)
    gender_entry = tk.Entry(manage_patient_window)
    gender_entry.grid(row=2, column=1, padx=5, pady=5)

    tk.Label(manage_patient_window, text="Age").grid(row=3, column=0, padx=5, pady=5)
    age_entry = tk.Entry(manage_patient_window)
    age_entry.grid(row=3, column=1, padx=5, pady=5)

    tk.Label(manage_patient_window, text="Weight").grid(row=4, column=0, padx=5, pady=5)
    weight_entry = tk.Entry(manage_patient_window)
    weight_entry.grid(row=4, column=1, padx=5, pady=5)

    tk.Label(manage_patient_window, text="Height").grid(row=5, column=0, padx=5, pady=5)
    height_entry = tk.Entry(manage_patient_window)
    height_entry.grid(row=5, column=1, padx=5, pady=5)

    tk.Label(manage_patient_window, text="Health History").grid(row=6, column=0, padx=5, pady=5)
    health_history_entry = tk.Entry(manage_patient_window)
    health_history_entry.grid(row=6, column=1, padx=5, pady=5)

    # Function to add a new patient
    def save_patient():
        first_name = first_name_entry.get()
        last_name = last_name_entry.get()

        if not first_name or not last_name:
            messagebox.showerror("Input Error", "Please provide both First Name and Last Name.")
            return

        gender = gender_entry.get().upper() == 'M'  # Convert to boolean (True for Male, False for Female)
        age = int(age_entry.get())
        weight = float(weight_entry.get())
        height = float(height_entry.get())
        health_history = health_history_entry.get()

        # Generate salt and derive key for encryption
        patient_salt = generate_salt()
        patient_key = derive_key(MASTER_KEY, patient_salt)

        # Hash the patient data for integrity check (before encryption)
        patient_data_string = f"{first_name}{last_name}{gender}{age}{weight}{height}{health_history}"
        patient_data_hash = hash_data(patient_data_string)

        # Encrypt sensitive patient data
        encrypted_first_name = encrypt_data(first_name, patient_key)
        encrypted_last_name = encrypt_data(last_name, patient_key)
        encrypted_gender = encrypt_data(str(gender), patient_key)
        encrypted_age = encrypt_data(str(age), patient_key)
        encrypted_weight = encrypt_data(str(weight), patient_key)
        encrypted_height = encrypt_data(str(height), patient_key)
        encrypted_health_history = encrypt_data(health_history, patient_key)

        # Insert encrypted patient data into the database
        conn = sqlite3.connect(HOSPITAL_DB)
        cursor = conn.cursor()

        user_id = cursor.lastrowid

        cursor.execute(""" 
            INSERT INTO patients (user_id, first_name, last_name, gender, age, weight, height, health_history, salt, patient_data_hash) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) 
        """, (user_id, encrypted_first_name, encrypted_last_name, encrypted_gender, encrypted_age, encrypted_weight,
              encrypted_height, encrypted_health_history, base64.b64encode(patient_salt).decode(), patient_data_hash))
        conn.commit()
        conn.close()

        messagebox.showinfo("Success", "Patient added successfully.")
        manage_patient_window.destroy()

    # Add Button (calls save_patient to add a new patient)
    add_button = tk.Button(manage_patient_window, text="Add Patient", command=save_patient)
    add_button.grid(row=8, column=0, columnspan=2, pady=10)

###################################################
#login window
###################################################
def login():
    username = username_entry.get()
    password = password_entry.get()

    conn = sqlite3.connect(HOSPITAL_DB)
    cursor = conn.cursor()

    # Fetch user info for the entered username, including passwordhash, salt, and user_type
    cursor.execute("SELECT passwordhash, salt, user_type FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if user:
        stored_password_hash, stored_salt, user_type = user  # Retrieve password hash and user type
        stored_salt = base64.b64decode(stored_salt)  # Decode the salt from base64
        key = derive_key(MASTER_KEY, stored_salt)  # Derive the key using the salt

        # Hash the entered password
        entered_password_hash = hash_data(password)  # Hash the entered password

        if entered_password_hash == stored_password_hash:  # Compare the password hashes
            login_window.destroy()  # Close login window

            # Determine if the user is an admin (user_type is 'h') or regular (user_type is 'r')
            is_admin = (user_type == 'h')
            show_patient_list(is_admin)  # Show the patient list determined by is_admin status
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
    username_label.pack(pady=5, padx=55)
    username_entry = tk.Entry(login_window)
    username_entry.pack(pady=5, padx=55)

    # Password label and entry
    password_label = tk.Label(login_window, text="Password")
    password_label.pack(pady=5, padx=55)
    password_entry = tk.Entry(login_window, show="*")
    password_entry.pack(pady=5, padx=55)

    # Login button
    login_button = tk.Button(login_window, text="Login", command=login)
    login_button.pack(pady=10)

    # Run the login window
    login_window.mainloop()

# Start the program by creating the login window
create_login_window()