"""
Script to modify the Project model to ensure compatibility with existing database
"""
import os
import sys
from sqlalchemy import text
from dotenv import load_dotenv

# Add the parent directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import engine, SessionLocal, Base
from models import Project

load_dotenv()

def fix_project_model():
    """
    This function provides a workaround for the timestamp columns issue.
    It modifies the main.py file to handle missing columns gracefully.
    """
    try:
        # Path to main.py
        main_py_path = os.path.join(os.path.dirname(__file__), 'main.py')
        
        # Read the current content
        with open(main_py_path, 'r') as file:
            content = file.read()
        
        # Check if we need to modify the get_last_project_updates function
        if 'def get_last_project_updates(' in content:
            print("Modifying get_last_project_updates function to handle missing columns...")
            
            # Find the function and modify it to handle missing columns
            start_idx = content.find('def get_last_project_updates(')
            if start_idx != -1:
                # Find the end of the function definition line
                end_line_idx = content.find('\n', start_idx)
                
                # Find the start of the function body (after the docstring if present)
                body_start_idx = content.find('"""', end_line_idx)
                if body_start_idx != -1:
                    body_start_idx = content.find('"""', body_start_idx + 3)
                    if body_start_idx != -1:
                        body_start_idx = content.find('\n', body_start_idx) + 1
                    else:
                        body_start_idx = end_line_idx + 1
                else:
                    body_start_idx = end_line_idx + 1
                
                # Find the query part
                query_start_idx = content.find('query = db.query(', body_start_idx)
                if query_start_idx != -1:
                    # Find the end of the query block
                    query_end_idx = content.find(')', content.find(')', query_start_idx) + 1) + 1
                    
                    # Extract the original query
                    original_query = content[query_start_idx:query_end_idx]
                    
                    # Create a modified query that handles missing columns
                    modified_query = """
    # Check if updated_at column exists
    try:
        # Base query for non-deleted projects
        query = db.query(
            models.Project.id.label("project_id"),
            models.Project.name.label("project_name"),
            models.Region.name.label("region_name"),
            models.Project.updated_at
        ).join(
            models.Region, models.Project.region_id == models.Region.id
        ).filter(
            models.Project.deleted_at == None,
            models.Region.deleted_at == None
        )
    except Exception as e:
        # If updated_at doesn't exist, use a simpler query
        if "no such column" in str(e):
            print("Warning: updated_at column not found, using id as fallback")
            query = db.query(
                models.Project.id.label("project_id"),
                models.Project.name.label("project_name"),
                models.Region.name.label("region_name"),
                models.Project.id.label("updated_at")  # Use id as a fallback
            ).join(
                models.Region, models.Project.region_id == models.Region.id
            ).filter(
                models.Project.deleted_at == None,
                models.Region.deleted_at == None
            )
        else:
            raise e"""
                    
                    # Replace the original query with the modified one
                    new_content = content[:query_start_idx] + modified_query + content[query_end_idx:]
                    
                    # Write the modified content back to the file
                    with open(main_py_path, 'w') as file:
                        file.write(new_content)
                    
                    print("Successfully modified get_last_project_updates function.")
                else:
                    print("Could not find query part in get_last_project_updates function.")
            else:
                print("Could not find get_last_project_updates function.")
        
        # Check if we need to modify the get_last_update_timestamp function
        if 'def get_last_update_timestamp(' in content:
            print("Modifying get_last_update_timestamp function to handle missing columns...")
            
            # Find the function and modify it
            start_idx = content.find('def get_last_update_timestamp(')
            if start_idx != -1:
                # Find the end of the function definition line
                end_line_idx = content.find('\n', start_idx)
                
                # Find the start of the function body (after the docstring if present)
                body_start_idx = content.find('"""', end_line_idx)
                if body_start_idx != -1:
                    body_start_idx = content.find('"""', body_start_idx + 3)
                    if body_start_idx != -1:
                        body_start_idx = content.find('\n', body_start_idx) + 1
                    else:
                        body_start_idx = end_line_idx + 1
                else:
                    body_start_idx = end_line_idx + 1
                
                # Find the query part
                query_start_idx = content.find('query = db.query(', body_start_idx)
                if query_start_idx != -1:
                    # Find the end of the query block
                    query_end_idx = content.find(')', content.find(')', query_start_idx) + 1) + 1
                    
                    # Extract the original query
                    original_query = content[query_start_idx:query_end_idx]
                    
                    # Create a modified query that handles missing columns
                    modified_query = """
    # Check if updated_at column exists
    try:
        # Base query for non-deleted projects
        query = db.query(func.max(models.Project.updated_at)).filter(
            models.Project.deleted_at == None
        )
    except Exception as e:
        # If updated_at doesn't exist, use a simpler query
        if "no such column" in str(e):
            print("Warning: updated_at column not found, using current timestamp as fallback")
            from datetime import datetime
            # Return current timestamp as fallback
            return {
                "last_update": datetime.utcnow().isoformat()
            }
        else:
            raise e"""
                    
                    # Replace the original query with the modified one
                    new_content = content[:query_start_idx] + modified_query + content[query_end_idx:]
                    
                    # Write the modified content back to the file
                    with open(main_py_path, 'w') as file:
                        file.write(new_content)
                    
                    print("Successfully modified get_last_update_timestamp function.")
                else:
                    print("Could not find query part in get_last_update_timestamp function.")
            else:
                print("Could not find get_last_update_timestamp function.")
        
        print("Finished modifying main.py to handle missing columns.")
    
    except Exception as e:
        print(f"Error modifying main.py: {e}")

if __name__ == "__main__":
    fix_project_model()

