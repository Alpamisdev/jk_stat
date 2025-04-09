"""
Script to add both created_at and updated_at columns to the projects table if they don't exist
"""
import os
import sys
from sqlalchemy import text
from dotenv import load_dotenv
from datetime import datetime

# Add the parent directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import engine, SessionLocal

load_dotenv()

def add_timestamp_columns():
    """Add created_at and updated_at columns to projects table if they don't exist"""
    # Create a database session
    db = SessionLocal()
    
    try:
        # Check which columns exist by querying the table info
        with engine.connect() as connection:
            result = connection.execute(text("PRAGMA table_info(projects)")).fetchall()
            
            # Extract column names
            column_names = [col[1] for col in result]
            print(f"Existing columns: {column_names}")
            
            # Check if created_at exists
            created_at_exists = 'created_at' in column_names
            # Check if updated_at exists
            updated_at_exists = 'updated_at' in column_names
            
            # Current timestamp for default values
            current_time = datetime.utcnow().isoformat()
            
            # Add columns as needed
            if not created_at_exists:
                print("Adding created_at column...")
                connection.execute(
                    text(f"ALTER TABLE projects ADD COLUMN created_at TIMESTAMP DEFAULT '{current_time}'")
                )
                print("created_at column added successfully.")
            else:
                print("created_at column already exists.")
            
            if not updated_at_exists:
                print("Adding updated_at column...")
                connection.execute(
                    text(f"ALTER TABLE projects ADD COLUMN updated_at TIMESTAMP DEFAULT '{current_time}'")
                )
                print("updated_at column added successfully.")
            else:
                print("updated_at column already exists.")
            
            # If we added either column, commit the changes
            if not created_at_exists or not updated_at_exists:
                connection.commit()
                
                # Verify the columns were added
                result = connection.execute(text("PRAGMA table_info(projects)")).fetchall()
                print("Updated table structure:")
                for col in result:
                    print(f"  {col[1]}: {col[2]}")
    
    except Exception as e:
        print(f"Error adding timestamp columns: {e}")
    
    finally:
        db.close()

if __name__ == "__main__":
    add_timestamp_columns()

