"""
Script to add the updated_at column to the projects table if it doesn't exist
"""
import os
import sys
from sqlalchemy import text
from dotenv import load_dotenv

# Add the parent directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import engine, SessionLocal
from models import Project

load_dotenv()

def add_updated_at_column():
    """Add updated_at column to projects table if it doesn't exist"""
    # Create a database session
    db = SessionLocal()
    
    try:
        # Check if the column exists by trying to query it
        try:
            db.query(Project.updated_at).limit(1).all()
            print("The updated_at column already exists in the projects table.")
            return
        except Exception as e:
            if "no such column" in str(e).lower():
                print("The updated_at column does not exist in the projects table. Adding it now...")
            else:
                # If it's some other error, re-raise it
                raise e
        
        # Add the updated_at column with a default value of the created_at timestamp
        with engine.connect() as connection:
            # First add the column
            connection.execute(
                text("ALTER TABLE projects ADD COLUMN updated_at TIMESTAMP")
            )
            
            # Then set the default value to created_at for existing records
            connection.execute(
                text("UPDATE projects SET updated_at = created_at WHERE updated_at IS NULL")
            )
            
            # Make sure the column is not nullable for future records
            # Note: SQLite doesn't support ALTER COLUMN, so we can't make it NOT NULL directly
            
            connection.commit()
            
            print("Successfully added updated_at column to projects table.")
            
            # Verify the column was added
            result = connection.execute(text("PRAGMA table_info(projects)")).fetchall()
            for col in result:
                if col[1] == 'updated_at':
                    print(f"Column details: {col}")
                    break
    
    except Exception as e:
        print(f"Error adding updated_at column: {e}")
    
    finally:
        db.close()

if __name__ == "__main__":
    add_updated_at_column()

