import streamlit as st
import sqlite3
from dotenv import load_dotenv
import os
import openai
import bcrypt

# --- Load API key ---
load_dotenv()
LLAMA_API_KEY = os.getenv("LLAMA_API_KEY")
openai.api_key = LLAMA_API_KEY

# --- Database ---
conn = sqlite3.connect("users.db", check_same_thread=False)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE,
                password TEXT,
                avatar TEXT DEFAULT '👤'
            )''')
c.execute('''CREATE TABLE IF NOT EXISTS chat_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                message TEXT,
                role TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
conn.commit()

# --- Functions ---
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

def register_user(email, password):
    try:
        hashed_pw = hash_password(password)
        c.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed_pw))
        conn.commit()
        return True
    except:
        return False

def login_user(email, password):
    c.execute("SELECT id, password FROM users WHERE email=?", (email,))
    user = c.fetchone()
    if user and verify_password(password, user[1]):
        return user[0]
    return None

def save_message(user_id, message, role):
    c.execute("SELECT * FROM chat_history WHERE user_id=? AND message=?", (user_id, message))
    if c.fetchone():
        return False
    c.execute("INSERT INTO chat_history (user_id, message, role) VALUES (?, ?, ?)", (user_id, message, role))
    conn.commit()
    return True

def get_chat_history(user_id):
    c.
