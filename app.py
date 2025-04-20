import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate encryption key
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory storage
stored_data = {}
failed_attempts = 0

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)

    for key, value in stored_data.items():
        if key == encrypted_text and value["passkey"] == hashed_passkey:
            failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()

    failed_attempts += 1
    return None

# Streamlit UI setup
st.set_page_config(page_title="Secure Data System", page_icon="🔒")

st.title("🔒 Secure Data Encryption System")

# Sidebar menu
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome To My Data Encryption System!")
    st.write("Develop a Streamlit-based secure data storage & retrieval system where: User store data with a unique passkey.Users decrypt data by providing the correct passkey.Multiple failed attempts result in a forced reauthorization (login page). The system operates entirely in memory without external databases.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            stored_data[encrypted_text] = {"passkey": hashed_passkey}
            st.success("✅ Data encrypted and stored successfully!")
            st.write("🔐 **Encrypted Data:**")
            st.code(encrypted_text)
        else:
            st.error("⚠️ Please fill both fields!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)

            if decrypted_text:
                st.success("✅ Data Decrypted Successfully!")
                st.write(f"🔓 **Decrypted Data:** {decrypted_text}")
            else:
                st.error(f"❌ Incorrect passkey! Attempts left: {3 - failed_attempts}")

                if failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login...")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Please fill both fields!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            failed_attempts = 0
            st.success("✅ Reauthorized successfully! Go to Retrieve Data.")
        else:
            st.error("❌ Incorrect master password!")

