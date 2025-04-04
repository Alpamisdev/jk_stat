import json
import os
from sqlalchemy.orm import Session
from models import Region, Authority, Status, Project
from datetime import datetime, date

def initialize_database(db: Session):
    """
    Initialize the database with data from the provided JSON file.
    
    Args:
        db: SQLAlchemy database session
        
    Returns:
        dict: Summary of imported data
    """
    # Path to the JSON file
    json_file_path = os.path.join(os.path.dirname(__file__), 'data', 'initial_data.json')
    
    # Check if the file exists
    if not os.path.exists(json_file_path):
        # Create the data directory if it doesn't exist
        os.makedirs(os.path.dirname(json_file_path), exist_ok=True)
        
        # Create a sample JSON file with minimal data
        sample_data = {
            "Regions": [],
            "Authorities": [],
            "Statuses": [],
            "Projects": []
        }
        
        with open(json_file_path, 'w', encoding='utf-8') as f:
            json.dump(sample_data, f, ensure_ascii=False, indent=2)
    
    # Load data from JSON file
    with open(json_file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Initialize counters
    counters = {
        "regions": {"added": 0, "updated": 0},
        "authorities": {"added": 0, "updated": 0},
        "statuses": {"added": 0, "updated": 0},
        "projects": {"added": 0, "updated": 0}
    }
    
    # Import regions
    for region_data in data.get("Regions", []):
        # Check if region already exists
        region = db.query(Region).filter(Region.id == region_data["id"]).first()
        
        if region:
            # Update existing region
            region.name = region_data["name"]
            region.stat_code = region_data.get("stat_code", 0)
            region.deleted_at = None
            counters["regions"]["updated"] += 1
        else:
            # Create new region
            region = Region(
                id=region_data["id"],
                name=region_data["name"],
                stat_code=region_data.get("stat_code", 0)
            )
            db.add(region)
            counters["regions"]["added"] += 1
    
    # Import authorities
    for authority_data in data.get("Authorities", []):
        # Check if authority already exists
        authority = db.query(Authority).filter(Authority.id == authority_data["id"]).first()
        
        if authority:
            # Update existing authority
            authority.name = authority_data["name"]
            authority.deleted_at = None
            counters["authorities"]["updated"] += 1
        else:
            # Create new authority
            authority = Authority(
                id=authority_data["id"],
                name=authority_data["name"]
            )
            db.add(authority)
            counters["authorities"]["added"] += 1
    
    # Import statuses
    for status_data in data.get("Statuses", []):
        # Check if status already exists
        status = db.query(Status).filter(Status.id == status_data["id"]).first()
        
        if status:
            # Update existing status
            status.name = status_data["name"]
            status.deleted_at = None
            counters["statuses"]["updated"] += 1
        else:
            # Create new status
            status = Status(
                id=status_data["id"],
                name=status_data["name"]
            )
            db.add(status)
            counters["statuses"]["added"] += 1
    
    # Commit changes to ensure regions, authorities, and statuses are available for projects
    db.commit()
    
    # Import projects
    for project_data in data.get("Projects", []):
        # Check if project already exists
        project = db.query(Project).filter(Project.id == project_data["id"]).first()
        
        # Parse completion date
        completion_date = None
        if "completion_date" in project_data and project_data["completion_date"]:
            try:
                completion_date = datetime.strptime(project_data["completion_date"], "%Y-%m-%d").date()
            except ValueError:
                # Try alternative format
                try:
                    completion_date = datetime.strptime(project_data["completion_date"], "%d.%m.%Y").date()
                except ValueError:
                    # Default to current date if parsing fails
                    completion_date = date.today()
        
        if project:
            # Update existing project
            project.region_id = project_data["region_id"]
            project.initiator = project_data["initiator"]
            project.name = project_data["name"]
            project.budget_million = project_data["budget_million"]
            project.jobs_created = project_data["jobs_created"]
            project.completion_date = completion_date
            project.authority_id = project_data["authority_id"]
            project.status_id = project_data["status_id"]
            project.general_status = project_data.get("general_status")
            project.deleted_at = None
            counters["projects"]["updated"] += 1
        else:
            # Create new project
            project = Project(
                id=project_data["id"],
                region_id=project_data["region_id"],
                initiator=project_data["initiator"],
                name=project_data["name"],
                budget_million=project_data["budget_million"],
                jobs_created=project_data["jobs_created"],
                completion_date=completion_date,
                authority_id=project_data["authority_id"],
                status_id=project_data["status_id"],
                general_status=project_data.get("general_status")
            )
            db.add(project)
            counters["projects"]["added"] += 1
    
    # Commit all changes
    db.commit()
    
    return counters

