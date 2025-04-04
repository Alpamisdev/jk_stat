# Project Management API

A FastAPI backend for managing regional projects with user authentication and authorization.

## Features

- User management with superadmin and regular admin roles
- Region-based access control for admins
- CRUD operations for regions and projects
- JWT authentication
- SQLAlchemy ORM for database operations

## Database Schema

The application uses the following database schema:

- **Users**: Store admin credentials and permissions
- **Regions**: Geographic regions for projects
- **UserRegions**: Junction table linking users to regions they can manage
- **Authorities**: Project approval authorities
- **Statuses**: Project status categories
- **Projects**: Main project data

## Setup

1. Create a virtual environment:

