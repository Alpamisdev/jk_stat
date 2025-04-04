from fastapi import FastAPI, Depends, HTTPException, status, Query, Response, Request
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_
from typing import List, Optional, Dict, Any
from datetime import timedelta
import io
import openpyxl
from openpyxl.styles import Font, Alignment, PatternFill
from openpyxl.utils import get_column_letter
from fastapi.openapi.utils import get_openapi
from fastapi.routing import APIRouter
from fastapi.staticfiles import StaticFiles
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
import logging

import models
import schemas
import auth
from database import engine, get_db, filter_deleted
from auth import (
    get_current_active_user, 
    get_current_superadmin, 
    authenticate_user, 
    create_access_token,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    get_password_hash,
    check_region_access,
    conditional_auth
)
from data_initializer import initialize_database

# Configure logging to reduce noise from invalid HTTP requests
logging.getLogger("uvicorn.error").setLevel(logging.ERROR)
logging.getLogger("uvicorn.access").setLevel(logging.INFO)

# Create database tables
models.Base.metadata.create_all(bind=engine)

# Create FastAPI app with docs disabled (we'll create custom routes)
app = FastAPI(
    title="Project Management API",
    description="API for managing regional projects with user authentication",
    version="1.0.0",
    docs_url=None,  # Disable default docs
    redoc_url=None  # Disable default redoc
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create routers for different categories
auth_router = APIRouter(tags=["Authentication"])
users_router = APIRouter(tags=["User Management"])
regions_router = APIRouter(tags=["Region Management"])
projects_router = APIRouter(tags=["Project Management"])
authorities_router = APIRouter(tags=["Authority Management"])
statuses_router = APIRouter(tags=["Status Management"])

# Health check endpoint for load balancers and monitoring
@app.get("/health", include_in_schema=False)
async def health_check():
    return {"status": "healthy"}

# Handle OPTIONS requests explicitly to prevent invalid HTTP request warnings
@app.options("/{path:path}")
async def options_handler(request: Request, path: str):
    return Response(status_code=200)

# Custom documentation routes that don't rely on CORS
@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title=app.title + " - Swagger UI",
        swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js",
        swagger_css_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css",
    )

@app.get("/redoc", include_in_schema=False)
async def redoc_html():
    return get_redoc_html(
        openapi_url="/openapi.json",
        title=app.title + " - ReDoc",
        redoc_js_url="https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.js",
    )

# Authentication endpoints
@auth_router.post("/token", response_model=schemas.Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# User management endpoints (superadmin only)
@users_router.post("/users/", response_model=schemas.User)
async def create_user(
    user: schemas.UserCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_superadmin)
):
    # Check if username already exists (including soft-deleted users)
    db_user = db.query(models.User).filter(
        models.User.username == user.username
    ).first()
    
    # Validate region assignment for non-superadmins
    if not user.is_superadmin and (not user.region_ids or len(user.region_ids) == 0):
        raise HTTPException(
            status_code=400, 
            detail="Regular admins must be assigned to at least one region"
        )
    
    if db_user and db_user.deleted_at is None:
        raise HTTPException(status_code=400, detail="Username already registered")
    elif db_user:
        # If user was soft-deleted, restore it with new data
        db_user.password_hash = get_password_hash(user.password)
        db_user.is_superadmin = user.is_superadmin
        db_user.is_active = user.is_active
        db_user.deleted_at = None
    else:
        # Create new user
        hashed_password = get_password_hash(user.password)
        db_user = models.User(
            username=user.username,
            password_hash=hashed_password,
            is_superadmin=user.is_superadmin,
            is_active=user.is_active
        )
        db.add(db_user)
        db.commit()  # Commit to get the user ID
    
    # Assign regions for non-superadmin users
    if not user.is_superadmin and user.region_ids:
        # Verify all region IDs exist and are not deleted
        regions = []
        for region_id in user.region_ids:
            region = db.query(models.Region).filter(
                models.Region.id == region_id,
                models.Region.deleted_at == None
            ).first()
            if region is None:
                raise HTTPException(status_code=404, detail=f"Region with ID {region_id} not found")
            regions.append(region)
        
        # Update user's regions
        db_user.regions = regions
    
    db.commit()
    db.refresh(db_user)
    return db_user

@users_router.get("/users/", response_model=List[schemas.UserWithRegions])
async def read_users(
    include_deleted: bool = False,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    # This endpoint requires authentication since it's user-related
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required for user data"
        )
    
    # Only superadmins can see all users
    if not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    
    query = db.query(models.User)
    if not include_deleted:
        query = filter_deleted(query, models.User)
    users = query.all()
    return users

@users_router.get("/users/{user_id}", response_model=schemas.UserWithRegions)
async def read_user(
    user_id: int,
    include_deleted: bool = False,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    # This endpoint requires authentication since it's user-related
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required for user data"
        )
    
    # Only superadmins can see other users
    if not current_user.is_superadmin and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    
    query = db.query(models.User).filter(models.User.id == user_id)
    if not include_deleted:
        query = filter_deleted(query, models.User)
    db_user = query.first()
    
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user

@users_router.put("/users/{user_id}", response_model=schemas.User)
async def update_user(
    user_id: int,
    user_update: schemas.UserUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_superadmin)
):
    db_user = db.query(models.User).filter(
        models.User.id == user_id,
        models.User.deleted_at == None
    ).first()
    
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Update user fields if provided
    if user_update.username is not None:
        # Check if username already exists
        existing_user = db.query(models.User).filter(
            models.User.username == user_update.username,
            models.User.id != user_id,
            models.User.deleted_at == None
        ).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already taken")
        db_user.username = user_update.username
    
    if user_update.password is not None:
        db_user.password_hash = get_password_hash(user_update.password)
    
    if user_update.is_active is not None:
        db_user.is_active = user_update.is_active
    
    db.commit()
    db.refresh(db_user)
    return db_user

@users_router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_superadmin)
):
    db_user = db.query(models.User).filter(
        models.User.id == user_id,
        models.User.deleted_at == None
    ).first()
    
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Prevent deleting yourself
    if db_user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    
    # Soft delete
    db_user.soft_delete(db)
    return None

# Add endpoint to restore a deleted user
@users_router.post("/users/{user_id}/restore", response_model=schemas.User)
async def restore_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_superadmin)
):
    db_user = db.query(models.User).filter(
        models.User.id == user_id,
        models.User.deleted_at != None
    ).first()
    
    if db_user is None:
        raise HTTPException(status_code=404, detail="Deleted user not found")
    
    # Restore user
    db_user.restore(db)
    return db_user

# User-Region management (superadmin only)
@users_router.put("/users/{user_id}/regions", response_model=schemas.UserWithRegions)
async def update_user_regions(
    user_id: int,
    region_update: schemas.UserRegionUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_superadmin)
):
    db_user = db.query(models.User).filter(
        models.User.id == user_id,
        models.User.deleted_at == None
    ).first()
    
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Verify all region IDs exist and are not deleted
    for region_id in region_update.region_ids:
        region = db.query(models.Region).filter(
            models.Region.id == region_id,
            models.Region.deleted_at == None
        ).first()
        if region is None:
            raise HTTPException(status_code=404, detail=f"Region with ID {region_id} not found")
    
    # Get all regions by IDs
    regions = db.query(models.Region).filter(
        models.Region.id.in_(region_update.region_ids),
        models.Region.deleted_at == None
    ).all()
    
    # Update user's regions
    db_user.regions = regions
    
    db.commit()
    db.refresh(db_user)
    return db_user

# User profile endpoint
@users_router.get("/users/me/", response_model=schemas.UserWithRegions)
async def read_users_me(current_user: models.User = Depends(get_current_active_user)):
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required for user data"
        )
    return current_user

@users_router.get("/users/me/regions/", response_model=List[schemas.Region])
async def read_users_regions(current_user: models.User = Depends(get_current_active_user)):
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required for user data"
        )
    # Filter out deleted regions
    return [region for region in current_user.regions if region.deleted_at is None]

# Region endpoints
@regions_router.post("/regions/", response_model=schemas.Region)
async def create_region(
    region: schemas.RegionCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_superadmin)
):
    # Check if a soft-deleted region with the same name exists
    db_region = db.query(models.Region).filter(
        models.Region.name == region.name
    ).first()
    
    if db_region and db_region.deleted_at is None:
        raise HTTPException(status_code=400, detail="Region with this name already exists")
    elif db_region:
        # If region was soft-deleted, restore it with new data
        db_region.stat_code = region.stat_code
        db_region.deleted_at = None
    else:
        # Create new region
        db_region = models.Region(**region.dict())
        db.add(db_region)
    
    db.commit()
    db.refresh(db_region)
    return db_region

@regions_router.get("/regions/", response_model=List[schemas.Region])
async def read_regions(
    include_deleted: bool = False,
    db: Session = Depends(get_db),
    current_user: Optional[models.User] = Depends(conditional_auth)
):
    # This GET endpoint doesn't require authentication
    query = db.query(models.Region)
    if not include_deleted:
        query = filter_deleted(query, models.Region)
    regions = query.all()
    return regions

@regions_router.get("/regions/{region_id}", response_model=schemas.Region)
async def read_region(
    region_id: int,
    include_deleted: bool = False,
    db: Session = Depends(get_db),
    current_user: Optional[models.User] = Depends(conditional_auth)
):
    # This GET endpoint doesn't require authentication
    query = db.query(models.Region).filter(models.Region.id == region_id)
    if not include_deleted:
        query = filter_deleted(query, models.Region)
    db_region = query.first()
    
    if db_region is None:
        raise HTTPException(status_code=404, detail="Region not found")
    return db_region

@regions_router.put("/regions/{region_id}", response_model=schemas.Region)
async def update_region(
    region_id: int,
    region_update: schemas.RegionUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    # PUT requests always require authentication
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    
    # Check if user has access to this region
    if not check_region_access(current_user, region_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this region"
        )
    
    db_region = db.query(models.Region).filter(
        models.Region.id == region_id,
        models.Region.deleted_at == None
    ).first()
    
    if db_region is None:
        raise HTTPException(status_code=404, detail="Region not found")
    
    # Update region fields if provided
    if region_update.name is not None:
        # Check if name already exists
        existing_region = db.query(models.Region).filter(
            models.Region.name == region_update.name,
            models.Region.id != region_id,
            models.Region.deleted_at == None
        ).first()
        if existing_region:
            raise HTTPException(status_code=400, detail="Region name already exists")
        db_region.name = region_update.name
    
    if region_update.stat_code is not None:
        db_region.stat_code = region_update.stat_code
    
    db.commit()
    db.refresh(db_region)
    return db_region

@regions_router.delete("/regions/{region_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_region(
    region_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_superadmin)
):
    db_region = db.query(models.Region).filter(
        models.Region.id == region_id,
        models.Region.deleted_at == None
    ).first()
    
    if db_region is None:
        raise HTTPException(status_code=404, detail="Region not found")
    
    # Check if region has associated projects
    projects = db.query(models.Project).filter(
        models.Project.region_id == region_id,
        models.Project.deleted_at == None
    ).count()
    
    if projects > 0:
        raise HTTPException(
            status_code=400, 
            detail=f"Cannot delete region with {projects} active projects"
        )
    
    # Soft delete
    db_region.soft_delete(db)
    return None

# Add endpoint to restore a deleted region
@regions_router.post("/regions/{region_id}/restore", response_model=schemas.Region)
async def restore_region(
    region_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_superadmin)
):
    db_region = db.query(models.Region).filter(
        models.Region.id == region_id,
        models.Region.deleted_at != None
    ).first()
    
    if db_region is None:
        raise HTTPException(status_code=404, detail="Deleted region not found")
    
    # Restore region
    db_region.restore(db)
    return db_region

# Project management endpoints
@projects_router.post("/projects/", response_model=schemas.Project)
async def create_project(
    project: schemas.ProjectCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    # Check if user has access to the region
    if not check_region_access(current_user, project.region_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create projects in this region"
        )
    
    # Check if region exists
    region = db.query(models.Region).filter(
        models.Region.id == project.region_id,
        models.Region.deleted_at == None
    ).first()
    if not region:
        raise HTTPException(status_code=404, detail="Region not found")
    
    # Check if authority exists
    authority = db.query(models.Authority).filter(
        models.Authority.id == project.authority_id,
        models.Authority.deleted_at == None
    ).first()
    if not authority:
        raise HTTPException(status_code=404, detail="Authority not found")
    
    # Check if status exists
    status = db.query(models.Status).filter(
        models.Status.id == project.status_id,
        models.Status.deleted_at == None
    ).first()
    if not status:
        raise HTTPException(status_code=404, detail="Status not found")
    
    # Create project
    db_project = models.Project(**project.dict())
    db.add(db_project)
    db.commit()
    db.refresh(db_project)
    return db_project

@projects_router.get("/projects/", response_model=List[schemas.Project])
async def read_projects(
    region_id: Optional[int] = None,
    include_deleted: bool = False,
    db: Session = Depends(get_db),
    current_user: Optional[models.User] = Depends(conditional_auth)
):
    # This GET endpoint doesn't require authentication
    query = db.query(models.Project)
    
    # Filter by region if specified
    if region_id is not None:
        # For authenticated users, check region access
        if current_user is not None and not check_region_access(current_user, region_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to view projects in this region"
            )
        query = query.filter(models.Project.region_id == region_id)
    else:
        # If no region specified and user is authenticated, only show projects from regions they have access to
        if current_user is not None and not current_user.is_superadmin:
            accessible_region_ids = [region.id for region in current_user.regions if region.deleted_at is None]
            if not accessible_region_ids:
                return []  # Return empty list if user has no accessible regions
            query = query.filter(models.Project.region_id.in_(accessible_region_ids))
    
    # Filter out deleted projects unless include_deleted is True
    if not include_deleted:
        query = filter_deleted(query, models.Project)
    
    projects = query.all()
    return projects

# New endpoint for filtering projects
@projects_router.get("/projects/filter", response_model=schemas.ProjectFilterResponse)
async def filter_projects(
    region_id: Optional[int] = None,
    budget_min: Optional[float] = None,
    budget_max: Optional[float] = None,
    status_id: Optional[int] = None,
    initiator: Optional[str] = None,
    name: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: Optional[models.User] = Depends(conditional_auth)
):
    # This GET endpoint doesn't require authentication
    # Start with base query
    query = db.query(models.Project).filter(models.Project.deleted_at == None)
    
    # Apply region filter and check access for authenticated users
    if region_id is not None:
        if current_user is not None and not check_region_access(current_user, region_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to view projects in this region"
            )
        query = query.filter(models.Project.region_id == region_id)
    else:
        # If no region specified and user is authenticated, only show projects from regions they have access to
        if current_user is not None and not current_user.is_superadmin:
            accessible_region_ids = [region.id for region in current_user.regions if region.deleted_at is None]
            if not accessible_region_ids:
                return {"total": 0, "items": []}  # Return empty result if user has no accessible regions
            query = query.filter(models.Project.region_id.in_(accessible_region_ids))
    
    # Apply budget filters
    if budget_min is not None:
        query = query.filter(models.Project.budget_million >= budget_min)
    if budget_max is not None:
        query = query.filter(models.Project.budget_million <= budget_max)
    
    # Apply status filter
    if status_id is not None:
        query = query.filter(models.Project.status_id == status_id)
    
    # Apply initiator (responsible person) filter
    if initiator is not None:
        query = query.filter(models.Project.initiator.ilike(f"%{initiator}%"))
    
    # Apply name filter
    if name is not None:
        query = query.filter(models.Project.name.ilike(f"%{name}%"))
    
    # Get total count
    total = query.count()
    
    # Get all projects
    projects = query.all()
    
    # Load related data
    result_items = []
    for project in projects:
        project_dict = {
            "id": project.id,
            "region_id": project.region_id,
            "initiator": project.initiator,
            "name": project.name,
            "budget_million": project.budget_million,
            "jobs_created": project.jobs_created,
            "completion_date": project.completion_date,
            "authority_id": project.authority_id,
            "status_id": project.status_id,
            "general_status": project.general_status,
            "deleted_at": project.deleted_at,
            "region": {
                "id": project.region.id,
                "name": project.region.name,
                "stat_code": project.region.stat_code,
                "deleted_at": project.region.deleted_at
            },
            "authority": {
                "id": project.authority.id,
                "name": project.authority.name,
                "deleted_at": project.authority.deleted_at
            },
            "status": {
                "id": project.status.id,
                "name": project.status.name,
                "deleted_at": project.status.deleted_at
            }
        }
        result_items.append(project_dict)
    
    return {"total": total, "items": result_items}

# New endpoint for exporting projects to Excel
@projects_router.get("/projects/export")
async def export_projects_to_excel(
    region_id: Optional[int] = None,
    budget_min: Optional[float] = None,
    budget_max: Optional[float] = None,
    status_id: Optional[int] = None,
    initiator: Optional[str] = None,
    name: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: Optional[models.User] = Depends(conditional_auth)
):
    # This GET endpoint doesn't require authentication
    # Start with base query
    query = db.query(models.Project).filter(models.Project.deleted_at == None)
    
    # Apply region filter and check access for authenticated users
    if region_id is not None:
        if current_user is not None and not check_region_access(current_user, region_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to export projects in this region"
            )
        query = query.filter(models.Project.region_id == region_id)
    else:
        # If no region specified and user is authenticated, only show projects from regions they have access to
        if current_user is not None and not current_user.is_superadmin:
            accessible_region_ids = [region.id for region in current_user.regions if region.deleted_at is None]
            if not accessible_region_ids:
                # Create empty Excel file
                wb = openpyxl.Workbook()
                ws = wb.active
                ws.title = "Projects"
                
                output = io.BytesIO()
                wb.save(output)
                output.seek(0)
                
                headers = {
                    'Content-Disposition': 'attachment; filename="projects.xlsx"',
                    'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                }
                return Response(content=output.getvalue(), headers=headers)
            
            query = query.filter(models.Project.region_id.in_(accessible_region_ids))
    
    # Apply budget filters
    if budget_min is not None:
        query = query.filter(models.Project.budget_million >= budget_min)
    if budget_max is not None:
        query = query.filter(models.Project.budget_million <= budget_max)
    
    # Apply status filter
    if status_id is not None:
        query = query.filter(models.Project.status_id == status_id)
    
    # Apply initiator (responsible person) filter
    if initiator is not None:
        query = query.filter(models.Project.initiator.ilike(f"%{initiator}%"))
    
    # Apply name filter
    if name is not None:
        query = query.filter(models.Project.name.ilike(f"%{name}%"))
    
    # Get all projects with their related data
    projects = query.all()
    
    # Create Excel workbook
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Projects"
    
    # Define headers
    headers = [
        "ID", "Region", "Initiator", "Name", "Budget (Million)", 
        "Jobs Created", "Completion Date", "Authority", "Status", "General Status"
    ]
    
    # Add headers with styling
    header_fill = PatternFill(start_color="DDEBF7", end_color="DDEBF7", fill_type="solid")
    header_font = Font(bold=True)
    
    for col_num, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col_num, value=header)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal='center')
    
    # Add data
    for row_num, project in enumerate(projects, 2):
        ws.cell(row=row_num, column=1, value=project.id)
        ws.cell(row=row_num, column=2, value=project.region.name)
        ws.cell(row=row_num, column=3, value=project.initiator)
        ws.cell(row=row_num, column=4, value=project.name)
        ws.cell(row=row_num, column=5, value=project.budget_million)
        ws.cell(row=row_num, column=6, value=project.jobs_created)
        ws.cell(row=row_num, column=7, value=project.completion_date.isoformat() if project.completion_date else None)
        ws.cell(row=row_num, column=8, value=project.authority.name)
        ws.cell(row=row_num, column=9, value=project.status.name)
        ws.cell(row=row_num, column=10, value=project.general_status)
    
    # Auto-adjust column widths
    for col_num, _ in enumerate(headers, 1):
        column_letter = get_column_letter(col_num)
        # Set a minimum width
        ws.column_dimensions[column_letter].width = 15
    
    # Save to BytesIO
    output = io.BytesIO()
    wb.save(output)
    output.seek(0)
    
    # Return Excel file
    headers = {
        'Content-Disposition': 'attachment; filename="projects.xlsx"',
        'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    }
    return Response(content=output.getvalue(), headers=headers)

@projects_router.get("/projects/{project_id}", response_model=schemas.ProjectDetail)
async def read_project(
    project_id: int,
    include_deleted: bool = False,
    db: Session = Depends(get_db),
    current_user: Optional[models.User] = Depends(conditional_auth)
):
    # This GET endpoint doesn't require authentication
    query = db.query(models.Project).filter(models.Project.id == project_id)
    
    if not include_deleted:
        query = filter_deleted(query, models.Project)
    
    project = query.first()
    
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Check if authenticated user has access to the project's region
    if current_user is not None and not check_region_access(current_user, project.region_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this project"
        )
    
    return project

@projects_router.put("/projects/{project_id}", response_model=schemas.Project)
async def update_project(
    project_id: int,
    project_update: schemas.ProjectUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    # Get the project
    project = db.query(models.Project).filter(
        models.Project.id == project_id,
        models.Project.deleted_at == None
    ).first()
    
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Check if user has access to the project's region
    if not check_region_access(current_user, project.region_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this project"
        )
    
    # If updating region_id, check if user has access to the new region
    if project_update.region_id is not None and project_update.region_id != project.region_id:
        if not check_region_access(current_user, project_update.region_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to move project to this region"
            )
        
        # Check if new region exists
        new_region = db.query(models.Region).filter(
            models.Region.id == project_update.region_id,
            models.Region.deleted_at == None
        ).first()
        if not new_region:
            raise HTTPException(status_code=404, detail="New region not found")
        
        project.region_id = project_update.region_id
    
    # Update other fields if provided
    if project_update.initiator is not None:
        project.initiator = project_update.initiator
    
    if project_update.name is not None:
        project.name = project_update.name
    
    if project_update.budget_million is not None:
        project.budget_million = project_update.budget_million
    
    if project_update.jobs_created is not None:
        project.jobs_created = project_update.jobs_created
    
    if project_update.completion_date is not None:
        project.completion_date = project_update.completion_date
    
    if project_update.authority_id is not None:
        # Check if authority exists
        authority = db.query(models.Authority).filter(
            models.Authority.id == project_update.authority_id,
            models.Authority.deleted_at == None
        ).first()
        if not authority:
            raise HTTPException(status_code=404, detail="Authority not found")
        
        project.authority_id = project_update.authority_id
    
    if project_update.status_id is not None:
        # Check if status exists
        status = db.query(models.Status).filter(
            models.Status.id == project_update.status_id,
            models.Status.deleted_at == None
        ).first()
        if not status:
            raise HTTPException(status_code=404, detail="Status not found")
        
        project.status_id = project_update.status_id
    
    if project_update.general_status is not None:
        project.general_status = project_update.general_status
    
    db.commit()
    db.refresh(project)
    return project

@projects_router.delete("/projects/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    project = db.query(models.Project).filter(
        models.Project.id == project_id,
        models.Project.deleted_at == None
    ).first()
    
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Check if user has access to the project's region
    if not check_region_access(current_user, project.region_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this project"
        )
    
    # Soft delete
    project.soft_delete(db)
    return None

@projects_router.post("/projects/{project_id}/restore", response_model=schemas.Project)
async def restore_project(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    project = db.query(models.Project).filter(
        models.Project.id == project_id,
        models.Project.deleted_at != None
    ).first()
    
    if project is None:
        raise HTTPException(status_code=404, detail="Deleted project not found")
    
    # Check if user has access to the project's region
    if not check_region_access(current_user, project.region_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to restore this project"
        )
    
    # Restore project
    project.restore(db)
    return project

# Authority endpoints - Restored
@authorities_router.post("/authorities/", response_model=schemas.Authority)
async def create_authority(
    authority: schemas.AuthorityCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_superadmin)
):
    # Check if authority with the same name exists
    db_authority = db.query(models.Authority).filter(
        models.Authority.name == authority.name
    ).first()
    
    if db_authority and db_authority.deleted_at is None:
        raise HTTPException(status_code=400, detail="Authority with this name already exists")
    elif db_authority:
        # If authority was soft-deleted, restore it
        db_authority.deleted_at = None
    else:
        # Create new authority
        db_authority = models.Authority(**authority.dict())
        db.add(db_authority)
    
    db.commit()
    db.refresh(db_authority)
    return db_authority

@authorities_router.get("/authorities/", response_model=List[schemas.Authority])
async def read_authorities(
    include_deleted: bool = False,
    db: Session = Depends(get_db),
    current_user: Optional[models.User] = Depends(conditional_auth)
):
    # This GET endpoint doesn't require authentication
    query = db.query(models.Authority)
    if not include_deleted:
        query = filter_deleted(query, models.Authority)
    authorities = query.all()
    return authorities

@authorities_router.get("/authorities/{authority_id}", response_model=schemas.Authority)
async def read_authority(
    authority_id: int,
    include_deleted: bool = False,
    db: Session = Depends(get_db),
    current_user: Optional[models.User] = Depends(conditional_auth)
):
    # This GET endpoint doesn't require authentication
    query = db.query(models.Authority).filter(models.Authority.id == authority_id)
    if not include_deleted:
        query = filter_deleted(query, models.Authority)
    db_authority = query.first()
    
    if db_authority is None:
        raise HTTPException(status_code=404, detail="Authority not found")
    return db_authority

@authorities_router.put("/authorities/{authority_id}", response_model=schemas.Authority)
async def update_authority(
    authority_id: int,
    authority_update: schemas.AuthorityCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_superadmin)
):
    db_authority = db.query(models.Authority).filter(
        models.Authority.id == authority_id,
        models.Authority.deleted_at == None
    ).first()
    
    if db_authority is None:
        raise HTTPException(status_code=404, detail="Authority not found")
    
    # Check if name already exists
    existing_authority = db.query(models.Authority).filter(
        models.Authority.name == authority_update.name,
        models.Authority.id != authority_id,
        models.Authority.deleted_at == None
    ).first()
    if existing_authority:
        raise HTTPException(status_code=400, detail="Authority name already exists")
    
    db_authority.name = authority_update.name
    
    db.commit()
    db.refresh(db_authority)
    return db_authority

@authorities_router.delete("/authorities/{authority_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_authority(
    authority_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_superadmin)
):
    db_authority = db.query(models.Authority).filter(
        models.Authority.id == authority_id,
        models.Authority.deleted_at == None
    ).first()
    
    if db_authority is None:
        raise HTTPException(status_code=404, detail="Authority not found")
    
    # Check if authority has associated projects
    projects = db.query(models.Project).filter(
        models.Project.authority_id == authority_id,
        models.Project.deleted_at == None
    ).count()
    
    if projects > 0:
        raise HTTPException(
            status_code=400, 
            detail=f"Cannot delete authority with {projects} active projects"
        )
    
    # Soft delete
    db_authority.soft_delete(db)
    return None

@authorities_router.post("/authorities/{authority_id}/restore", response_model=schemas.Authority)
async def restore_authority(
    authority_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_superadmin)
):
    db_authority = db.query(models.Authority).filter(
        models.Authority.id == authority_id,
        models.Authority.deleted_at != None
    ).first()
    
    if db_authority is None:
        raise HTTPException(status_code=404, detail="Deleted authority not found")
    
    # Restore authority
    db_authority.restore(db)
    return db_authority

# Status endpoints - Restored
@statuses_router.post("/statuses/", response_model=schemas.Status)
async def create_status(
    status: schemas.StatusCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_superadmin)
):
    # Check if status with the same name exists
    db_status = db.query(models.Status).filter(
        models.Status.name == status.name
    ).first()
    
    if db_status and db_status.deleted_at is None:
        raise HTTPException(status_code=400, detail="Status with this name already exists")
    elif db_status:
        # If status was soft-deleted, restore it
        db_status.deleted_at = None
    else:
        # Create new status
        db_status = models.Status(**status.dict())
        db.add(db_status)
    
    db.commit()
    db.refresh(db_status)
    return db_status

@statuses_router.get("/statuses/", response_model=List[schemas.Status])
async def read_statuses(
    include_deleted: bool = False,
    db: Session = Depends(get_db),
    current_user: Optional[models.User] = Depends(conditional_auth)
):
    # This GET endpoint doesn't require authentication
    query = db.query(models.Status)
    if not include_deleted:
        query = filter_deleted(query, models.Status)
    statuses = query.all()
    return statuses

@statuses_router.get("/statuses/{status_id}", response_model=schemas.Status)
async def read_status(
    status_id: int,
    include_deleted: bool = False,
    db: Session = Depends(get_db),
    current_user: Optional[models.User] = Depends(conditional_auth)
):
    # This GET endpoint doesn't require authentication
    query = db.query(models.Status).filter(models.Status.id == status_id)
    if not include_deleted:
        query = filter_deleted(query, models.Status)
    db_status = query.first()
    
    if db_status is None:
        raise HTTPException(status_code=404, detail="Status not found")
    return db_status

@statuses_router.put("/statuses/{status_id}", response_model=schemas.Status)
async def update_status(
    status_id: int,
    status_update: schemas.StatusCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_superadmin)
):
    db_status = db.query(models.Status).filter(
        models.Status.id == status_id,
        models.Status.deleted_at == None
    ).first()
    
    if db_status is None:
        raise HTTPException(status_code=404, detail="Status not found")
    
    # Check if name already exists
    existing_status = db.query(models.Status).filter(
        models.Status.name == status_update.name,
        models.Status.id != status_id,
        models.Status.deleted_at == None
    ).first()
    if existing_status:
        raise HTTPException(status_code=400, detail="Status name already exists")
    
    db_status.name = status_update.name
    
    db.commit()
    db.refresh(db_status)
    return db_status

@statuses_router.delete("/statuses/{status_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_status(
    status_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_superadmin)
):
    db_status = db.query(models.Status).filter(
        models.Status.id == status_id,
        models.Status.deleted_at == None
    ).first()
    
    if db_status is None:
        raise HTTPException(status_code=404, detail="Status not found")
    
    # Check if status has associated projects
    projects = db.query(models.Project).filter(
        models.Project.status_id == status_id,
        models.Project.deleted_at == None
    ).count()
    
    if projects > 0:
        raise HTTPException(
            status_code=400, 
            detail=f"Cannot delete status with {projects} active projects"
        )
    
    # Soft delete
    db_status.soft_delete(db)
    return None

@statuses_router.post("/statuses/{status_id}/restore", response_model=schemas.Status)
async def restore_status(
    status_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_superadmin)
):
    db_status = db.query(models.Status).filter(
        models.Status.id == status_id,
        models.Status.deleted_at != None
    ).first()
    
    if db_status is None:
        raise HTTPException(status_code=404, detail="Deleted status not found")
    
    # Restore status
    db_status.restore(db)
    return db_status

# Root endpoint
@app.get("/", tags=["Root"])
async def root():
    return {"message": "Welcome to the Project Management API"}

# Initialize database endpoint
@app.post("/initialize-database", tags=["Administration"])
async def init_database(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_superadmin)
):
    """Initialize the database with data from the provided JSON file."""
    result = initialize_database(db)
    return {"message": "Database initialized successfully", "details": result}

# Include all routers
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(regions_router)
app.include_router(projects_router)
app.include_router(authorities_router)
app.include_router(statuses_router)

# Customize OpenAPI schema to organize endpoints by tags
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    
    # Customize the schema here if needed
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# Run the application
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

