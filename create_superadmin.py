"""
Script to create the initial superadmin user
Run this script after setting up the database to create the first superadmin
"""
import os
import sys
from dotenv import load_dotenv
from sqlalchemy.orm import Session
from sqlalchemy import inspect

# Add the parent directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import SessionLocal, engine
from models import Base, User, Region
from auth import get_password_hash

load_dotenv()

# Update the create_superadmin function to assign all regions
def create_superadmin(username, password):
    # Create tables if they don't exist
    Base.metadata.create_all(bind=engine)
    
    # Create a database session
    db = SessionLocal()
    
    try:
        # Check if the superadmin already exists
        existing_user = db.query(User).filter(User.username == username).first()
        if existing_user:
            print(f"User with username '{username}' already exists.")
            # Update the password for the existing user
            existing_user.password_hash = get_password_hash(password)
            existing_user.is_active = True
            existing_user.deleted_at = None
            
            # Assign all regions to the superadmin
            all_regions = db.query(Region).filter(Region.deleted_at == None).all()
            existing_user.regions = all_regions
            print(f"Assigned {len(all_regions)} regions to superadmin '{username}'")
            
            db.commit()
            print(f"Updated password for user '{username}'")
            return
        
        # Create the superadmin user
        hashed_password = get_password_hash(password)
        
        # Check if deleted_at column exists
        inspector = inspect(engine)
        columns = [column['name'] for column in inspector.get_columns('users')]
        
        if 'deleted_at' in columns:
            superadmin = User(
                username=username,
                password_hash=hashed_password,
                is_superadmin=True,
                is_active=True,
                deleted_at=None
            )
        else:
            # Create user without deleted_at if the column doesn't exist yet
            superadmin = User(
                username=username,
                password_hash=hashed_password,
                is_superadmin=True,
                is_active=True
            )
        
        db.add(superadmin)
        db.commit()
        
        # Assign all regions to the superadmin
        all_regions = db.query(Region).filter(Region.deleted_at == None).all()
        superadmin.regions = all_regions
        db.commit()
        
        print(f"Superadmin '{username}' created successfully!")
        print(f"Assigned {len(all_regions)} regions to superadmin '{username}'")
    
    except Exception as e:
        print(f"Error creating superadmin: {e}")
    
    finally:
        db.close()

if __name__ == "__main__":
    # Get superadmin credentials from environment variables or use defaults
    username = os.getenv("SUPERADMIN_USERNAME", "superadmin")
    password = os.getenv("SUPERADMIN_PASSWORD", "Admin1234")
    
    if not password:
        # If password is not provided in environment variables, prompt for it
        import getpass
        password = getpass.getpass("Enter superadmin password: ")
    
    create_superadmin(username, password)
