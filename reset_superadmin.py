"""
Script to reset the superadmin password
Run this script to reset the password for the superadmin user
"""
import os
import sys
from sqlalchemy import text
from dotenv import load_dotenv

# Add the parent directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import engine, SessionLocal
from models import User
from auth import get_password_hash

load_dotenv()

def reset_superadmin_password():
    # Create a database session
    db = SessionLocal()
    
    try:
        # Set a simple password without special characters
        new_password = "Admin1234"
        hashed_password = get_password_hash(new_password)
        
        # Update the superadmin user directly with SQL
        with engine.connect() as connection:
            result = connection.execute(
                text("UPDATE users SET password_hash = :hash, is_active = TRUE, deleted_at = NULL WHERE username = 'superadmin'"),
                {"hash": hashed_password}
            )
            connection.commit()
            
            if result.rowcount > 0:
                print(f"Superadmin password reset successfully to '{new_password}'")
            else:
                print("No superadmin user found. Creating one...")
                # Create a new superadmin user
                superadmin = User(
                    username="superadmin",
                    password_hash=hashed_password,
                    is_superadmin=True,
                    is_active=True,
                    deleted_at=None
                )
                db.add(superadmin)
                db.commit()
                print(f"Superadmin created with password '{new_password}'")
    
    except Exception as e:
        print(f"Error resetting superadmin password: {e}")
    
    finally:
        db.close()

if __name__ == "__main__":
    reset_superadmin_password()

