import os
import shutil
from app import app, db, User, UserSettings

def reset_application():
    print("Starting application reset...")
    
    # Get the database file path
    db_path = 'instance/passwords.db'
    uploads_path = 'temp_uploads'
    
    with app.app_context():
        # Drop all tables
        print("Dropping all database tables...")
        db.drop_all()
        
        # Recreate all tables
        print("Recreating database tables...")
        db.create_all()
        
        # Create default admin user
        print("Creating default admin user...")
        admin_settings = UserSettings(username='admin')
        db.session.add(admin_settings)
        
        admin_user = User(username='admin')
        admin_user.set_password('admin')
        db.session.add(admin_user)
        
        # Commit changes
        db.session.commit()
    
    # Clear uploaded files
    if os.path.exists(uploads_path):
        print(f"Clearing uploaded files from {uploads_path}...")
        for filename in os.listdir(uploads_path):
            file_path = os.path.join(uploads_path, filename)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                print(f"Error deleting {file_path}: {e}")
    
    print("Application reset complete!")
    print("Default login: username='admin', password='admin'")

if __name__ == "__main__":
    reset_application()