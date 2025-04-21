"""
Enhanced CORS middleware configuration for handling file downloads
"""
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI

def setup_cors(app: FastAPI):
    """
    Configure CORS middleware with settings optimized for file downloads
    """
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "https://alpamis.space", "https://www.alpamis.space"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["Content-Disposition", "Content-Type", "Content-Length"],
        max_age=600,  # Cache preflight requests for 10 minutes
    )
    
    return app
