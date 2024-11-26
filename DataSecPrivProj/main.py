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

DATABASE_NAME = 'tellme.db'

##################################################################
# Database creation if not made and fill
##################################################################
# Initialize Faker instance
fake = Faker()

# Connect to SQLite database (or create if it doesn't exist)
conn = sqlite3.connect(DATABASE_NAME)
cursor = conn.cursor()

# Create the 'users' table if it doesn't exist
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,  -- Primary key
        username TEXT NOT NULL UNIQUE,         -- Username (unique)
        password TEXT NOT NULL,                -- Password (hashed)
        salt TEXT NOT NULL,                    -- Salt for password hashing
        user_type TEXT NOT NULL                -- User type (e.g., 'admin', 'regular')
    )
''')

# Create the 'patients' table if it doesn't exist
cursor.execute('''
    CREATE TABLE IF NOT EXISTS patients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,  -- Primary key
        user_id INTEGER,                       -- Foreign key to link to the 'users' table
        first_name TEXT NOT NULL,              -- Patient's first name
        last_name TEXT NOT NULL,               -- Patient's last name
        gender BOOLEAN NOT NULL,               -- Gender (True = male, False = female)
        age INTEGER NOT NULL,                  -- Age
        weight REAL NOT NULL,                  -- Weight (float, lbs)
        height REAL NOT NULL,                  -- Height (float, feet)
        health_history TEXT,                   -- Health history (text)
        FOREIGN KEY (user_id) REFERENCES users(id)  -- Foreign key constraint
    )
''')

# Commit changes to create tables
conn.commit()

# Check how many records exist in the 'patients' table
cursor.execute("SELECT COUNT(*) FROM patients")
patient_count = cursor.fetchone()[0]

if patient_count < 100:
    # Calculate how many more records need to be generated
    records_to_generate = 100 - patient_count
    
    # Check if the "test" user exists, if not add it
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'test'")
    test_user_exists = cursor.fetchone()[0] > 0
    
    if not test_user_exists:
        # Insert a user with username "test" and password "pass"
        cursor.execute('''
            INSERT INTO users (username, password, salt, user_type)
            VALUES (?, ?, ?, ?)
        ''', ('test', 'pass', fake.uuid4(), 'admin'))  # "test" user with password "pass"
        conn.commit()  # Commit after inserting the test user
    else:
        print("Test user already exists in the database.")
    
    # Now generate the remaining records (other users and patients)
    for _ in range(records_to_generate):
        # Generate fake user data
        username = fake.user_name()
        password = fake.password()  # In a real case, you'd hash this
        salt = fake.uuid4()  # Using a UUID as a salt
        user_type = random.choice(['regular', 'admin'])  # Random user type
        
        # Insert user into the 'users' table
        cursor.execute(''' 
            INSERT INTO users (username, password, salt, user_type)
            VALUES (?, ?, ?, ?)
        ''', (username, password, salt, user_type))
        
        # Fetch the user_id of the last inserted user
        user_id = cursor.lastrowid
        
        # Generate fake patient data
        first_name = fake.first_name()
        last_name = fake.last_name()
        gender = random.choice([True, False])  # True for male, False for female
        age = random.randint(18, 80)  # Random age between 18 and 80
        
        # Weight: Random weight between 110 lbs and 220 lbs (floating-point)
        weight = round(random.uniform(110, 220), 2)  # Weight in lbs
        
        # Height: Random height between 4'6" and 6'5" (in feet and inches)
        feet = random.randint(4, 6)  # Height in feet (4 to 6 feet)
        inches = random.randint(0, 11)  # Height in inches (0 to 11 inches)
        # Convert feet and inches to a floating-point value (feet + inches/12)
        height = round(feet + inches / 12, 2)  # Height in feet as a float
        
        # Health history: Generate some random health history text
        health_history = fake.text(max_nb_chars=200)
        
        # Insert patient data into the 'patients' table
        cursor.execute('''
            INSERT INTO patients (user_id, first_name, last_name, gender, age, weight, height, health_history)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, first_name, last_name, gender, age, weight, height, health_history))

    # Commit the changes to the database
    conn.commit()

    print(f"{records_to_generate} new patients added to the database.")

else:
    print("There are already 100 or more patients in the database.")

# Close the connection
conn.close()

#############################################################################
#quick test view to see all patients and data
############################################################################
# Function to fetch patients data from the database
def fetch_patients():
    conn = sqlite3.connect(DATABASE_NAME)  # Connect to the SQLite database
    cursor = conn.cursor()
    
    # Fetch data from the 'patients' table
    cursor.execute("SELECT first_name, last_name, gender, age, weight, height, health_history FROM patients")
    rows = cursor.fetchall()  # Get all rows of the table
    
    conn.close()
    return rows

# Function to display the data in the Treeview widget
def display_patients():
    # Fetch the patient data
    patients = fetch_patients()

    # Clear the previous data in the Treeview
    for row in tree.get_children():
        tree.delete(row)
    
    # Insert new data into the Treeview
    for patient in patients:
        first_name, last_name, gender, age, weight, height, health_history = patient
        gender_str = 'Male' if gender else 'Female'  # Convert gender to a string
        tree.insert("", "end", values=(first_name, last_name, gender_str, age, weight, height, health_history))

# Function to handle login verification
def login():
    username = username_entry.get()
    password = password_entry.get()

    # Connect to the database and check the username and password
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = cursor.fetchone()
    
    conn.close()

    # If a user is found, show the patient list
    if user:
        login_window.destroy()  # Close the login window
        show_patient_list()  # Show the patient list
    else:
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

# Start the program by creating the login window
create_login_window()
