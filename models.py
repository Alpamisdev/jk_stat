from sqlalchemy import Boolean, Column, Integer, String, Float, Date, Text, ForeignKey, Table, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, Query
from sqlalchemy.sql import func
from typing import Optional

Base = declarative_base()

# Custom query class that filters out soft-deleted records by default
class SoftDeleteQuery(Query):
    def __new__(cls, *args, **kwargs):
        obj = super(SoftDeleteQuery, cls).__new__(cls)
        with_deleted = kwargs.pop('_with_deleted', False)
        if len(args) > 0:
            super(SoftDeleteQuery, obj).__init__(*args, **kwargs)
            return obj.filter_by(deleted_at=None) if not with_deleted else obj
        return obj

    def __init__(self, *args, **kwargs):
        _with_deleted = kwargs.pop('_with_deleted', False)
        super(SoftDeleteQuery, self).__init__(*args, **kwargs)

    def with_deleted(self):
        return self.__class__(self._only_full_mapper_zero('get'),
                              session=self.session,
                              _with_deleted=True)

# Mixin for soft delete functionality
class SoftDeleteMixin:
    deleted_at = Column(DateTime(timezone=True), nullable=True)
    
    def soft_delete(self, session):
        self.deleted_at = func.now()
        session.add(self)
        session.commit()
    
    def restore(self, session):
        self.deleted_at = None
        session.add(self)
        session.commit()

# Junction table for User-Region many-to-many relationship
user_regions = Table(
    "user_regions",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id"), primary_key=True),
    Column("region_id", Integer, ForeignKey("regions.id"), primary_key=True)
)

class User(Base, SoftDeleteMixin):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    is_superadmin = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationship with regions (many-to-many)
    regions = relationship("Region", secondary=user_regions, back_populates="users")

class Region(Base, SoftDeleteMixin):
    __tablename__ = "regions"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    stat_code = Column(Integer)
    
    # Relationships
    projects = relationship("Project", back_populates="region")
    users = relationship("User", secondary=user_regions, back_populates="regions")

class Authority(Base, SoftDeleteMixin):
    __tablename__ = "authorities"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    
    # Relationships
    projects = relationship("Project", back_populates="authority")

class Status(Base, SoftDeleteMixin):
    __tablename__ = "statuses"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    
    # Relationships
    projects = relationship("Project", back_populates="status")

class Project(Base, SoftDeleteMixin):
    __tablename__ = "projects"
    
    id = Column(Integer, primary_key=True, index=True)
    region_id = Column(Integer, ForeignKey("regions.id"))
    initiator = Column(String)
    name = Column(String, index=True)
    budget_million = Column(Float)
    jobs_created = Column(Integer)
    completion_date = Column(Date)
    authority_id = Column(Integer, ForeignKey("authorities.id"))
    status_id = Column(Integer, ForeignKey("statuses.id"))
    general_status = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    region = relationship("Region", back_populates="projects")
    authority = relationship("Authority", back_populates="projects")
    status = relationship("Status", back_populates="projects")

