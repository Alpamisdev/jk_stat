"""
Script to fix the database schema by adding missing columns
"""
import os
import sys
from sqlalchemy import text, inspect
from dotenv import load_dotenv

# Add the parent directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import engine, SessionLocal, Base
from models import Project

load_dotenv()

def fix_database_schema():
    """
    Check for missing columns in the database schema and add them if needed.
    This ensures the database structure matches the SQLAlchemy models.
    """
    print("Checking database schema...")
    
    # Create a database session
    db = SessionLocal()
    
    try:
        # Get the inspector to check table structure
        inspector = inspect(engine)
        
        # Check if the projects table exists
        if 'projects' not in inspector.get_table_names():
            print("Projects table doesn't exist. Creating all tables...")
            Base.metadata.create_all(bind=engine)
            print("Tables created successfully.")
            return
        
        # Get existing columns in the projects table
        columns = {column['name'] for column in inspector.get_columns('projects')}
        print(f"Existing columns in projects table: {columns}")
        
        # Check for missing columns
        missing_columns = []
        
        if 'created_at' not in columns:
            missing_columns.append(('created_at', 'TIMESTAMP'))
        
        if 'updated_at' not in columns:
            missing_columns.append(('updated_at', 'TIMESTAMP'))
        
        # Add missing columns if any
        if missing_columns:
            print(f"Found {len(missing_columns)} missing columns: {[col[0] for col in missing_columns]}")
            
            with engine.connect() as connection:
                for column_name, column_type in missing_columns:
                    print(f"Adding column {column_name} ({column_type}) to projects table...")
                    connection.execute(
                        text(f"ALTER TABLE projects ADD COLUMN {column_name} {column_type}")
                    )
                
                # Set default values for new columns
                if 'created_at' in [col[0] for col in missing_columns]:
                    print("Setting default value for created_at column...")
                    connection.execute(
                        text("UPDATE projects SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")
                    )
                
                if 'updated_at' in [col[0] for col in missing_columns]:
                    print("Setting default value for updated_at column...")
                    connection.execute(
                        text("UPDATE projects SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL")
                    )
                
                connection.commit()
                print("Schema update completed successfully.")
        else:
            print("Database schema is up to date. No changes needed.")
        
        # Verify the schema after updates
        columns_after = {column['name'] for column in inspector.get_columns('projects')}
        print(f"Current columns in projects table: {columns_after}")
    
    except Exception as e:
        print(f"Error fixing database schema: {e}")
    
    finally:
        db.close()

if __name__ == "__main__":
    fix_database_schema()
