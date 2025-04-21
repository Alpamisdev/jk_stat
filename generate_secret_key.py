#!/usr/bin/env python3
import secrets
import os
from dotenv import load_dotenv, set_key

def generate_secret_key():
    """Generate a secure random secret key and save it to .env file"""
    # Load existing .env file if it exists
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    load_dotenv(env_path)
    
    # Check if SECRET_KEY already exists
    existing_key = os.getenv("SECRET_KEY")
    if existing_key:
        print(f"SECRET_KEY already exists in .env file.")
        replace = input("Do you want to replace it? (y/n): ").lower()
        if replace != 'y':
            print("Keeping existing SECRET_KEY.")
            return
    
    # Generate a secure random key (32 bytes = 256 bits)
    new_key = secrets.token_hex(32)
    
    # Update .env file
    if os.path.exists(env_path):
        # Update existing .env file
        set_key(env_path, "SECRET_KEY", new_key)
    else:
        # Create new .env file
        with open(env_path, 'w') as f:
            f.write(f"SECRET_KEY={new_key}\n")
    
    print(f"New SECRET_KEY generated and saved to .env file.")
    print(f"SECRET_KEY={new_key}")

if __name__ == "__main__":
    generate_secret_key()

