from pydantic import BaseModel, EmailStr, ConfigDict
from typing import List, Optional, Dict, Any
from datetime import date, datetime

# User schemas
class UserBase(BaseModel):
    username: str
    is_active: bool = True

class UserCreate(UserBase):
    password: str
    is_superadmin: bool = False
    region_ids: Optional[List[int]] = None

class UserUpdate(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    is_active: Optional[bool] = None

class UserRegionUpdate(BaseModel):
    region_ids: List[int]

class User(UserBase):
    id: int
    is_superadmin: bool
    created_at: datetime
    deleted_at: Optional[datetime] = None
    
    model_config = ConfigDict(from_attributes=True)

class UserWithRegions(User):
    regions: List["Region"]
    
    model_config = ConfigDict(from_attributes=True)

# Region schemas
class RegionBase(BaseModel):
    name: str
    stat_code: int

class RegionCreate(RegionBase):
    pass

class RegionUpdate(BaseModel):
    name: Optional[str] = None
    stat_code: Optional[int] = None

class Region(RegionBase):
    id: int
    deleted_at: Optional[datetime] = None
    
    model_config = ConfigDict(from_attributes=True)

# Authority schemas
class AuthorityBase(BaseModel):
    name: str

class AuthorityCreate(AuthorityBase):
    pass

class Authority(AuthorityBase):
    id: int
    deleted_at: Optional[datetime] = None
    
    model_config = ConfigDict(from_attributes=True)

# Status schemas
class StatusBase(BaseModel):
    name: str

class StatusCreate(StatusBase):
    pass

class Status(StatusBase):
    id: int
    deleted_at: Optional[datetime] = None
    
    model_config = ConfigDict(from_attributes=True)

# Project schemas
class ProjectBase(BaseModel):
    region_id: int
    initiator: str
    name: str
    budget_million: float
    jobs_created: int
    completion_date: date
    authority_id: int
    status_id: int
    general_status: Optional[str] = None

class ProjectCreate(ProjectBase):
    pass

class ProjectUpdate(BaseModel):
    region_id: Optional[int] = None
    initiator: Optional[str] = None
    name: Optional[str] = None
    budget_million: Optional[float] = None
    jobs_created: Optional[int] = None
    completion_date: Optional[date] = None
    authority_id: Optional[int] = None
    status_id: Optional[int] = None
    general_status: Optional[str] = None

class Project(ProjectBase):
    id: int
    deleted_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    model_config = ConfigDict(from_attributes=True)

class ProjectDetail(Project):
    region: Region
    authority: Authority
    status: Status
    
    model_config = ConfigDict(from_attributes=True)

# New schema for last update information
class ProjectLastUpdate(BaseModel):
    project_id: int
    project_name: str
    region_name: str
    updated_at: datetime
  
    model_config = ConfigDict(from_attributes=True)

# New schema for project filtering response with updated_at
class ProjectFilterResponse(BaseModel):
    total: int
    items: List[Dict[str, Any]]

# Token schemas
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

# Update UserWithRegions to reference Region
UserWithRegions.update_forward_refs()

