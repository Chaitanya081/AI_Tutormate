import streamlit as st
import sqlite3
from dotenv import load_dotenv
import os
import openai
import bcrypt

# Load API key from .env
load_dotenv()
LLAMA_API_KEY = os.getenv("LLAMA_API_KEY")
openai.api_key = LLAMA_API_KEY

# --- DATABASE SETUP ---
conn = sqlite3.connect("users.db", check_same_thread=False)
c = conn.cursor()

# Users table
c.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE,
                password TEXT,
                avatar TEXT DEFAULT '👤'
            )''')

# Chat history table
c.execute('''CREATE TABLE IF NOT EXISTS chat_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                message TEXT,
                role TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
conn.commit()

# --- FUNCTIONS ---
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
    # Prevent duplicates in chat
    c.execute("SELECT * FROM chat_history WHERE user_id=? AND message=?", (user_id, message))
    if c.fetchone():
        return False
    c.execute("INSERT INTO chat_history (user_id, message, role) VALUES (?, ?, ?)", (user_id, message, role))
    conn.commit()
    return True

def get_chat_history(user_id):
    c.execute("SELECT message, role, created_at FROM chat_history WHERE user_id=? ORDER BY created_at ASC", (user_id,))
    return c.fetchall()

def ask_ai(message):
    # Call LLaMA API
    response = openai.ChatCompletion.create(
        model="llama-3.1-8b-instant",
        messages=[
            {"role": "system", "content": "You are a helpful AI tutor. Only answer academic questions."},
            {"role": "user", "content": message}
        ],
        temperature=0.7,
        max_tokens=500
    )
    return response.choices[0].message.content

# --- STREAMLIT UI ---
st.set_page_config(page_title="AI-Tutormate", layout="wide")
st.title("🤖 AI-Tutormate")

# --- THEME SWITCHER ---
theme = st.sidebar.selectbox("Theme", ["Light", "Dark"])
if theme == "Dark":
    st.markdown(
        """<style>
        body {background-color: #1e1e1e; color: white;}
        </style>""", unsafe_allow_html=True
    )

# --- AUTHENTICATION ---
auth_option = st.sidebar.selectbox("Login / Register", ["Login", "Register"])
email = st.sidebar.text_input("Email")
password = st.sidebar.text_input("Password", type="password")
if st.sidebar.button(auth_option):
    if auth_option == "Register":
        if register_user(email, password):
            st.sidebar.success("Registered successfully! Please login.")
        else:
            st.sidebar.error("Email already exists.")
    else:
        user_id = login_user(email, password)
        if user_id:
            st.session_state['user_id'] = user_id
            st.session_state['email'] = email
            st.success(f"Logged in as {email}")
        else:
            st.sidebar.error("Invalid credentials.")

if 'user_id' in st.session_state:
    user_id = st.session_state['user_id']
    
    # --- Display chat history ---
    st.subheader("Chat History")
    chat_history = get_chat_history(user_id)
    for msg, role, ts in chat_history:
        if role=="user":
            st.markdown(f"**You:** {msg}")
        else:
            st.markdown(f"**AI-Tutormate:** {msg}")
    
    # --- User input ---
    user_message = st.text_input("Ask a study-related question:")
    if st.button("Send"):
        if user_message.strip():
            # Prevent duplicates
            if save_message(user_id, user_message, "user"):
                ai_response = ask_ai(user_message)
                save_message(user_id, ai_response, "AI")
                st.experimental_rerun()
            else:
                st.warning("This question was already asked.")
