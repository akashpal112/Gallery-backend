# app.py - Full Updated Code for Multi-User System

from flask import Flask, request, jsonify, session, send_from_directory
from flask_bcrypt import Bcrypt
from flask_session import Session
from datetime import datetime
import os
from dotenv import load_dotenv

# Database and Cloudinary Imports
from pymongo import MongoClient, errors
from bson.objectid import ObjectId
import cloudinary
import cloudinary.uploader
from cloudinary.utils import cloudinary_url

# Load environment variables from .env file
load_dotenv()

# --- 1. CONFIGURATION ---
app = Flask(__name__, static_folder='.') # static_folder='.' means it serves files from the current directory

# Load configuration variables from .env
MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME")
SECRET_KEY = os.getenv("SECRET_KEY") # This is the critical key for session security

CLOUDINARY_CLOUD_NAME = os.getenv("CLOUDINARY_CLOUD_NAME")
CLOUDINARY_API_KEY = os.getenv("CLOUDINARY_API_KEY")
CLOUDINARY_API_SECRET = os.getenv("CLOUDINARY_API_SECRET")

# Check for critical configuration
if not all([MONGO_URI, DB_NAME, SECRET_KEY, CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET]):
    print("\n❌ ERROR: .env file is missing or values are empty.")
    print("Make sure .env exists and has MONGO_URI, DB_NAME, SECRET_KEY, and CLOUDINARY details.\n")
    # For security, raise an error if critical keys are missing
    raise EnvironmentError("Critical environment variables missing.")

# Flask and Session Config
app.config["SECRET_KEY"] = SECRET_KEY
app.config["SESSION_TYPE"] = "filesystem" # Stores sessions on the server's filesystem
app.config["SESSION_PERMANENT"] = False # Session cookies expire when browser is closed
app.config["SESSION_USE_SIGNER"] = True # Session cookie is cryptographically signed
Session(app)
bcrypt = Bcrypt(app) # For hashing passwords securely

# Cloudinary Configuration
cloudinary.config( 
    cloud_name = CLOUDINARY_CLOUD_NAME, 
    api_key = CLOUDINARY_API_KEY, 
    api_secret = CLOUDINARY_API_SECRET,
    secure = True # Ensures URLs are HTTPS
)

# --- MONGODB CONNECTION & TEST ---
client = None
db = None
users_collection = None
photos_collection = None

try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000) # 5 second timeout for connection
    client.server_info() # Trigger a connection command to ensure it works
    db = client[DB_NAME]
    users_collection = db["users"]
    photos_collection = db["photos"]
    print(f"\n✅ MongoDB Connected Successfully to: {DB_NAME}")
except errors.ServerSelectionTimeoutError as err:
    print(f"\n❌ MongoDB Connection Failed. Check your Internet or MONGO_URI: {err}")
    db = None # Set db to None to handle connection errors gracefully and prevent crashes
except Exception as e:
    print(f"\n❌ An unexpected error occurred during MongoDB connection: {e}")
    db = None

# --- HELPER: Require Login Decorator ---
# This decorator ensures a user is logged in before accessing certain routes
def login_required(f):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            # If not logged in, return a 401 Unauthorized response
            return jsonify({"success": False, "message": "Unauthorized. Please log in."}), 401
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__ # Important for Flask routes to maintain their original name
    return wrapper

# --- 2. AUTHENTICATION ROUTES ---

@app.route('/api/register', methods=['POST'])
def register():
    if db is None:
        return jsonify({"success": False, "message": "Database Error"}), 500

    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password are required."}), 400
    
    # Check if user already exists
    if users_collection.find_one({"username": username}):
        return jsonify({"success": False, "message": "Username already exists."}), 409

    # Hash password and insert new user
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    users_collection.insert_one({"username": username, "password": hashed_password})

    return jsonify({"success": True, "message": "Registration successful! Login now."})

@app.route('/api/login', methods=['POST'])
def login():
    if db is None:
        return jsonify({"success": False, "message": "Database Error"}), 500

    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = users_collection.find_one({"username": username})

    if user and bcrypt.check_password_hash(user['password'], password):
        # Successful login: Set session variables
        session['user_id'] = str(user['_id']) # Store user's MongoDB ID as string
        session['username'] = user['username'] # Store username
        print(f"User {user['username']} logged in. Session ID: {session['user_id']}") # Debugging
        return jsonify({"success": True, "message": "Login successful.", "username": user['username']})
    else:
        return jsonify({"success": False, "message": "Invalid username or password."}), 401

@app.route('/api/logout', methods=['POST'])
@login_required # Only a logged-in user can logout
def logout():
    session.pop('user_id', None) # Remove user_id from session
    session.pop('username', None) # Remove username from session
    print("User logged out.") # Debugging
    return jsonify({"success": True, "message": "Logout successful."})

@app.route('/api/status', methods=['GET'])
def get_status():
    """Returns the current login status and username."""
    if 'user_id' in session:
        return jsonify({"isLoggedIn": True, "username": session['username']})
    else:
        return jsonify({"isLoggedIn": False})

# --- 3. PHOTO MANAGEMENT ROUTES ---

@app.route('/api/photos', methods=['POST'])
@login_required
def upload_photo():
    """Handles photo upload to Cloudinary and saves data to MongoDB."""
    if db is None:
        return jsonify({"success": False, "message": "Database Error"}), 500

    if 'photo' not in request.files:
        return jsonify({"success": False, "message": "No photo file provided."}), 400

    photo_file = request.files['photo']
    user_id = session['user_id'] # Get user ID from session
    
    if photo_file.filename == '':
        return jsonify({"success": False, "message": "No selected file."}), 400
    
    # 1. Upload to Cloudinary
    try:
        # Create a unique folder for each user's photos in Cloudinary
        folder_name = f"cloudgallery_user_{user_id}" 
        print(f"Uploading to Cloudinary folder: {folder_name} for user: {session['username']}...")
        
        # Cloudinary will auto-generate a public_id if not provided
        upload_result = cloudinary.uploader.upload(photo_file, folder=folder_name)
        secure_url = upload_result['secure_url']
        public_id = upload_result['public_id'] # Store for future deletion
        filename = photo_file.filename # Original filename
        print("Cloudinary upload successful.")
        
    except Exception as e:
        print(f"❌ Cloudinary Upload Error for user {session['username']}: {e}")
        return jsonify({"success": False, "message": f"Cloud Upload Failed: {str(e)}"}), 500

    # 2. Save photo metadata to MongoDB, linked to the user_id
    new_photo = {
        "user_id": ObjectId(user_id), # Store as ObjectId to ensure proper database linking
        "src": secure_url,
        "public_id": public_id, 
        "title": filename, # Using original filename as title
        "date": datetime.now().strftime("%Y-%m-%d"), # Current date
        "uploaded_at": datetime.utcnow() # For sorting, stored as UTC for consistency
    }
    
    inserted_photo = photos_collection.insert_one(new_photo)
    new_photo['_id'] = str(inserted_photo.inserted_id) # Convert ObjectId to string for JSON response

    # Clean up the object before sending back to frontend (remove internal fields)
    new_photo.pop('uploaded_at', None)
    new_photo.pop('user_id', None) 
    new_photo.pop('public_id', None) # No need to send public_id to frontend

    return jsonify({"success": True, "message": "Photo uploaded successfully.", "photo": new_photo})

@app.route('/api/photos', methods=['GET'])
@login_required
def get_photos():
    """Fetches photos ONLY for the currently logged-in user."""
    if db is None:
        return jsonify({"success": False, "message": "Database Error"}), 500

    user_id = session['user_id']
    print(f"Fetching photos for user ID: {user_id}") # Debugging
    
    # Find all photos where user_id matches the current session user_id
    # We use ObjectId(user_id) to match the type stored in MongoDB
    # Sort by 'uploaded_at' in descending order (newest first)
    photos_cursor = photos_collection.find({"user_id": ObjectId(user_id)}).sort("uploaded_at", -1)
    
    photos_list = []
    for photo in photos_cursor:
        photo['_id'] = str(photo['_id']) # Convert ObjectId to string for JSON
        photo.pop('user_id', None) # Remove user_id before sending to frontend for security
        photo.pop('uploaded_at', None) # Remove internal timestamp
        photo.pop('public_id', None) # No need to send public_id to frontend
        photos_list.append(photo)
    
    print(f"Found {len(photos_list)} photos for user: {session['username']}") # Debugging
    return jsonify({"success": True, "photos": photos_list})

@app.route('/api/photos/<photo_id>', methods=['DELETE'])
@login_required
def delete_photo(photo_id):
    """Deletes a photo from Cloudinary and MongoDB."""
    if db is None:
        return jsonify({"success": False, "message": "Database Error"}), 500

    user_id = session['user_id']

    try:
        # 1. Find the photo in MongoDB and ensure it belongs to the current user
        photo_obj = photos_collection.find_one({
            "_id": ObjectId(photo_id),
            "user_id": ObjectId(user_id)
        })

        if not photo_obj:
            return jsonify({"success": False, "message": "Photo not found or unauthorized to delete."}), 404

        public_id = photo_obj['public_id'] # Get Cloudinary public ID for deletion

        # 2. Delete from Cloudinary
        print(f"Deleting Cloudinary asset: {public_id} for user {session['username']}...")
        cloudinary.uploader.destroy(public_id)
        print("Cloudinary deletion successful.")

        # 3. Delete from MongoDB
        photos_collection.delete_one({"_id": ObjectId(photo_id)})
        print(f"MongoDB photo ID {photo_id} deleted.")

        return jsonify({"success": True, "message": "Photo deleted successfully."})

    except Exception as e:
        print(f"❌ Delete Error for photo {photo_id} by user {session['username']}: {e}")
        return jsonify({"success": False, "message": f"Deletion failed: {str(e)}"}), 500


# --- 4. STATIC FILE ROUTES ---

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    """Serves all static files (HTML, CSS, JS, etc.) from the current directory."""
    return send_from_directory(app.static_folder, filename)

if __name__ == '__main__':
    # Use 0.0.0.0 for external access in deployment (e.g., if hosted on a server)
    # debug=True allows automatic reloading on code changes and provides a debugger
    app.run(debug=True, host='0.0.0.0', port=5000)