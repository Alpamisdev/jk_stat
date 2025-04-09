"""
Script to update existing projects to set updated_at = created_at if it's NULL
This ensures all existing projects have a valid updated_at timestamp
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

def update_project_timestamps():
    """Update any NULL updated_at values to match created_at"""
    # Create a database session
    db = SessionLocal()
    
    try:
        # First check if we have any projects with NULL updated_at
        null_updated_count = db.query(Project).filter(
            Project.updated_at == None
        ).count()
        
        if null_updated_count > 0:
            print(f"Found {null_updated_count} projects with NULL updated_at timestamps")
            
            # Update directly with SQL for efficiency
            with engine.connect() as connection:
                result = connection.execute(
                    text("UPDATE projects SET updated_at = created_at WHERE updated_at IS NULL")
                )
                connection.commit()
                
                print(f"Updated {result.rowcount} projects to set updated_at = created_at")
        else:
            print("No projects found with NULL updated_at timestamps")
            
        # Verify all projects now have updated_at values
        remaining_null = db.query(Project).filter(
            Project.updated_at == None
        ).count()
        
        if remaining_null > 0:
            print(f"WARNING: {remaining_null} projects still have NULL updated_at timestamps")
        else:
            print("All projects now have valid updated_at timestamps")
    
    except Exception as e:
        print(f"Error updating project timestamps: {e}")
    
    finally:
        db.close()

if __name__ == "__main__":
    update_project_timestamps()

