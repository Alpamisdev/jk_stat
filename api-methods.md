# API Methods Documentation

## HTTP Methods Support

The API supports the following HTTP methods for each resource:

### Users
- `GET /users` - List all users (requires authentication)
- `GET /users/{user_id}` - Get a specific user (requires authentication)
- `POST /users` - Create a new user (requires superadmin)
- `PUT /users/{user_id}` - Update a user (requires superadmin)
- `PATCH /users/{user_id}` - Partially update a user (requires superadmin)
- `DELETE /users/{user_id}` - Delete a user (requires superadmin)

### Regions
- `GET /regions` - List all regions (public)
- `GET /regions/{region_id}` - Get a specific region (public)
- `POST /regions` - Create a new region (requires superadmin)
- `PUT /regions/{region_id}` - Update a region (requires authentication and access)
- `PATCH /regions/{region_id}` - Partially update a region (requires authentication and access)
- `DELETE /regions/{region_id}` - Delete a region (requires superadmin)

### Projects
- `GET /projects` - List all projects (public)
- `GET /projects/{project_id}` - Get a specific project (public)
- `GET /projects/last-updates` - Get most recently updated projects (public)
- `GET /projects/last_update` - Get the latest update timestamp across all projects (public)
- `GET /projects/filter` - Filter projects with various criteria (public)
- `GET /projects/export` - Export projects to Excel file (public)
- `POST /projects` - Create a new project (requires authentication and region access)
- `PUT /projects/{project_id}` - Update a project (requires authentication and region access)
- `PATCH /projects/{project_id}` - Partially update a project (requires authentication and region access)
- `DELETE /projects/{project_id}` - Delete a project (requires authentication and region access)

### Authorities
- `GET /authorities` - List all authorities (public)
- `GET /authorities/{authority_id}` - Get a specific authority (public)
- `POST /authorities` - Create a new authority (requires superadmin)
- `PUT /authorities/{authority_id}` - Update an authority (requires superadmin)
- `PATCH /authorities/{authority_id}` - Partially update an authority (requires superadmin)
- `DELETE /authorities/{authority_id}` - Delete an authority (requires superadmin)

### Statuses
- `GET /statuses` - List all statuses (public)
- `GET /statuses/{status_id}` - Get a specific status (public)
- `POST /statuses` - Create a new status (requires superadmin)
- `PUT /statuses/{status_id}` - Update a status (requires superadmin)
- `PATCH /statuses/{status_id}` - Partially update a status (requires superadmin)
- `DELETE /statuses/{status_id}` - Delete a status (requires superadmin)

## URL Format

All endpoints support both formats:
- With trailing slash (e.g., `/users/`)
- Without trailing slash (e.g., `/users`)

Both formats are functionally identical and will work for all HTTP methods.

## PATCH vs PUT

- `PUT` - Used for complete resource updates (all fields must be provided)
- `PATCH` - Used for partial resource updates (only changed fields need to be provided)

Both methods are supported for all resources that can be updated.

## Error Handling

The API returns appropriate HTTP status codes:

- `200 OK` - Request succeeded
- `201 Created` - Resource created successfully
- `204 No Content` - Resource deleted successfully
- `400 Bad Request` - Invalid request parameters
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `405 Method Not Allowed` - HTTP method not supported for this endpoint
- `422 Unprocessable Entity` - Request validation failed

## Content Types

- Request bodies should use `application/json`
- Responses are returned as `application/json`
- The `/projects/export` endpoint returns `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`

## Project Update Tracking

All projects now include:
- `created_at` - When the project was created
- `updated_at` - When the project was last updated

The API provides two endpoints for tracking updates:
1. `/projects/last-updates` - Returns a list of recently updated projects with details
2. `/projects/last_update` - Returns just the latest update timestamp across all projects

These endpoints allow you to efficiently track changes and determine when the most recent update occurred.

