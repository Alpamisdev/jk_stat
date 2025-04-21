"""
Script to generate a secure password reset token for a user
This is a safer alternative to exposing password hashes
"""
import os
import sys
import secrets
import datetime
from sqlalchemy import text
from dotenv import load_dotenv

# Add the parent directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import engine, SessionLocal
from models import User
from auth import get_password_hash

load_dotenv()

def generate_reset_token(username):
    """Generate a secure reset token for a user"""
    # Create a database session
    db = SessionLocal()
    
    try:
        # Find the user
        user = db.query(User).filter(
            User.username == username,
            User.deleted_at == None,
            User.is_active == True
        ).first()
        
        if not user:
            print(f"User '{username}' not found or is inactive")
            return None
        
        # Generate a secure token
        token = secrets.token_urlsafe(32)
        
        # Calculate expiration (24 hours from now)
        expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        expiration_str = expiration.isoformat()
        
        # Store the token in the database
        # Note: In a production system, you would have a dedicated table for reset tokens
        # This is a simplified example
        with engine.connect() as connection:
            # Check if the reset_tokens table exists, create it if not
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS reset_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    token TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    used BOOLEAN DEFAULT FALSE,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """))
            
            # Insert the new token
            connection.execute(
                text("INSERT INTO reset_tokens (user_id, token, expires_at) VALUES (:user_id, :token, :expires_at)"),
                {"user_id": user.id, "token": token, "expires_at": expiration_str}
            )
            connection.commit()
        
        # Return the token and expiration
        print(f"Reset token generated for user '{username}'")
        print(f"Token: {token}")
        print(f"Expires: {expiration_str}")
        
        # In a real system, you would send this token to the user via email
        # For this example, we just print it
        
        return {
            "username": username,
            "token": token,
            "expires_at": expiration_str
        }
    
    except Exception as e:
        print(f"Error generating reset token: {e}")
        return None
    
    finally:
        db.close()

def reset_password_with_token(token, new_password):
    """Reset a user's password using a valid token"""
    # Create a database session
    db = SessionLocal()
    
    try:
        # Find the token in the database
        with engine.connect() as connection:
            result = connection.execute(
                text("""
                    SELECT rt.id, rt.user_id, rt.expires_at, rt.used, u.username 
                    FROM reset_tokens rt
                    JOIN users u ON rt.user_id = u.id
                    WHERE rt.token = :token AND rt.used = FALSE
                """),
                {"token": token}
            ).fetchone()
            
            if not result:
                print("Invalid or already used token")
                return False
            
            token_id, user_id, expires_at, used, username = result
            
            # Check if token is expired
            expiration = datetime.datetime.fromisoformat(expires_at)
            if datetime.datetime.utcnow() > expiration:
                print("Token has expired")
                return False
            
            # Hash the new password
            hashed_password = get_password_hash(new_password)
            
            # Update the user's password
            connection.execute(
                text("UPDATE users SET password_hash = :hash WHERE id = :user_id"),
                {"hash": hashed_password, "user_id": user_id}
            )
            
            # Mark the token as used
            connection.execute(
                text("UPDATE reset_tokens SET used = TRUE WHERE id = :token_id"),
                {"token_id": token_id}
            )
            
            connection.commit()
            
            print(f"Password reset successfully for user '{username}'")
            return True
    
    except Exception as e:
        print(f"Error resetting password: {e}")
        return False
    
    finally:
        db.close()

if __name__ == "__main__":
    # Example usage
    import argparse
    
    parser = argparse.ArgumentParser(description="Password reset utility")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Generate token command
    generate_parser = subparsers.add_parser("generate", help="Generate a reset token")
    generate_parser.add_argument("username", help="Username to generate token for")
    
    # Reset password command
    reset_parser = subparsers.add_parser("reset", help="Reset password with token")
    reset_parser.add_argument("token", help="Reset token")
    reset_parser.add_argument("password", help="New password")
    
    args = parser.parse_args()
    
    if args.command == "generate":
        generate_reset_token(args.username)
    elif args.command == "reset":
        reset_password_with_token(args.token, args.password)
    else:
        parser.print_help()
