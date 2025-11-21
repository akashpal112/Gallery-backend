/* ---------------------------------
   SERVER API & CONFIGURATION
-----------------------------------*/
const SERVER_URL = ''; // Empty means same domain (e.g., http://127.0.0.1:5000)
const LOGIN_TOKEN = 'isLoggedIn'; 
let galleryItems = []; // To hold the photo data for the current user
let currentIndex = 0; // For lightbox navigation

// --- 1. AUTHENTICATION HANDLERS ---

// 1. REGISTER
async function handleRegister(event) {
    event.preventDefault();
    const username = document.getElementById('registerUsername').value;
    const password = document.getElementById('registerPassword').value;
    const messageElement = document.getElementById('registerMessage');
    
    messageElement.textContent = "Registering...";
    messageElement.style.color = 'yellow'; // Indicate processing

    try {
        const response = await fetch(`${SERVER_URL}/api/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await response.json();
        messageElement.style.color = data.success ? '#6bff6b' : '#ff6b6b';
        messageElement.textContent = data.message;
        if (data.success) {
            // Optional: Auto-redirect to login after a short delay
            setTimeout(() => { window.location.href = 'login.html'; }, 2000);
        }
    } catch (error) {
        console.error("Register Error:", error);
        messageElement.textContent = 'Server Error. Please try again later.';
        messageElement.style.color = '#ff6b6b';
    }
}

// 2. LOGIN
async function handleLogin(event) {
    event.preventDefault();
    const username = document.getElementById('loginUsername').value; 
    const password = document.getElementById('loginPassword').value;
    const messageElement = document.getElementById('loginMessage');
    
    messageElement.textContent = "Logging in...";
    messageElement.style.color = 'yellow'; // Indicate processing

    try {
        const response = await fetch(`${SERVER_URL}/api/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await response.json();
        
        if (data.success) {
            localStorage.setItem(LOGIN_TOKEN, 'true'); 
            localStorage.setItem('username', data.username); // Store username for display
            window.location.href = 'gallery.html'; // Redirect to gallery
        } else {
            messageElement.style.color = '#ff6b6b';
            messageElement.textContent = data.message;
        }
    } catch (error) {
        console.error("Login Error:", error);
        messageElement.textContent = 'Server Error. Please try again later.';
        messageElement.style.color = '#ff6b6b';
    }
}

// 3. LOGOUT
async function logout() {
    try {
        const response = await fetch(`${SERVER_URL}/api/logout`, { method: 'POST' });
        const data = await response.json();
        if (!data.success) {
            console.warn("Logout API reported an issue, but proceeding with client logout:", data.message);
        }
    } catch (error) {
        console.error("Logout API failed, but continuing client logout.", error);
    } finally {
        // Always clear client-side data and redirect, regardless of API response
        localStorage.removeItem(LOGIN_TOKEN);
        localStorage.removeItem('username');
        window.location.href = 'index.html'; 
    }
}

// --- 2. GALLERY MANAGEMENT ---

// Function to fetch the current user's photos
async function fetchGalleryImages() {
    const galleryDiv = document.getElementById('gallery');
    const imageCountSpan = document.getElementById('imageCount');
    const gallerySection = document.getElementById('gallerySection');
    
    // Show spinner while loading
    if (gallerySection) { // Ensure gallerySection exists
        gallerySection.innerHTML = `
            <h1 class="text-center mb-4"><i class="fas fa-images me-2"></i>My Private Collection</h1>
            <div class="upload-area mb-5 text-center">
                <label for="uploadInput" class="btn btn-info btn-lg">
                    <i class="fas fa-cloud-upload-alt me-2"></i> Upload New Photo
                </label>
                <input type="file" id="uploadInput" style="display: none;" accept="image/*">
                <p id="uploadMessage" class="mt-3 font-weight-bold text-white"></p>
                <p class="mt-2 text-secondary">Photos are saved securely in your private cloud.</p>
            </div>
            <div class="gallery-grid" id="gallery">
                <div class="col-12 text-center text-white-50"><i class="fas fa-spinner fa-spin fa-2x"></i> Loading Photos...</div>
            </div>
            <div class="text-center mt-5">
                <p class="text-white-50">Total Images: <span id="imageCount">0</span></p>
            </div>
        `;
        // Re-attach upload listener as innerHTML overwrites it
        const uploadInput = document.getElementById('uploadInput');
        if (uploadInput) uploadInput.addEventListener('change', uploadPhoto);
    }

    try {
        const response = await fetch(`${SERVER_URL}/api/photos`);
        const data = await response.json();

        if (response.status === 401) {
            // Session expired or unauthorized, force logout
            localStorage.removeItem(LOGIN_TOKEN);
            localStorage.removeItem('username');
            window.location.href = 'login.html'; // Redirect to login
            return;
        }

        if (data.success) {
            galleryItems = data.photos; // Update global array
            renderGallery(); // Render the photos
        } else {
            // Display error if API call was successful but returned success: false
            if (galleryDiv) galleryDiv.innerHTML = `<div class="col-12 text-center text-danger">Error loading photos: ${data.message}</div>`;
            if (imageCountSpan) imageCountSpan.textContent = '0';
        }

    } catch (error) {
        console.error("Fetch Gallery Images Error:", error);
        if (galleryDiv) galleryDiv.innerHTML = '<div class="col-12 text-center text-danger">Could not connect to the server or fetch photos.</div>';
        if (imageCountSpan) imageCountSpan.textContent = '0';
    }
}

// Function to render the fetched photos
function renderGallery() {
    const galleryDiv = document.getElementById('gallery');
    const imageCountSpan = document.getElementById('imageCount');

    if (!galleryDiv) {
        console.error("Gallery div not found.");
        return;
    }
    galleryDiv.innerHTML = ''; // Clear previous content

    if (galleryItems.length === 0) {
        galleryDiv.innerHTML = '<div class="col-12 text-center text-white-50"><h3>No photos yet. Upload one!</h3></div>';
        if (imageCountSpan) imageCountSpan.textContent = '0';
        return;
    }

    galleryItems.forEach((item, index) => {
        const itemHtml = `
            <div class="gallery-item" data-index="${index}" onclick="openLightbox(${index})">
                <img src="${item.src}" alt="${item.title}" class="img-fluid">
                <div class="gallery-overlay">
                    <div class="photo-info">
                        <i class="fas fa-camera"></i> ${item.title}
                        <div class="photo-date"><i class="fas fa-calendar-alt"></i> ${item.date}</div>
                    </div>
                    <div class="delete-btn" onclick="event.stopPropagation(); deletePhoto('${item._id}')"><i class="fas fa-trash"></i> Delete</div>
                </div>
            </div>
        `;
        galleryDiv.insertAdjacentHTML('beforeend', itemHtml);
    });

    if (imageCountSpan) imageCountSpan.textContent = galleryItems.length;
}

// Function to handle photo upload
async function uploadPhoto(event) {
    const file = event.target.files[0];
    const uploadMessageElement = document.getElementById('uploadMessage');
    if (!file) return;

    const formData = new FormData();
    formData.append('photo', file);

    if (uploadMessageElement) {
        uploadMessageElement.style.color = 'yellow';
        uploadMessageElement.textContent = `Uploading ${file.name}...`;
    }

    try {
        const response = await fetch(`${SERVER_URL}/api/photos`, {
            method: 'POST',
            body: formData,
        });
        const data = await response.json();

        if (data.success) {
            if (uploadMessageElement) {
                uploadMessageElement.style.color = '#6bff6b';
                uploadMessageElement.textContent = `Upload successful: ${file.message}`; // Use data.message
            }
            fetchGalleryImages(); // Refresh gallery to show the new photo
        } else {
            if (uploadMessageElement) {
                uploadMessageElement.style.color = '#ff6b6b';
                uploadMessageElement.textContent = `Upload failed: ${data.message}`;
            }
        }

    } catch (error) {
        console.error("Upload Photo Error:", error);
        if (uploadMessageElement) {
            uploadMessageElement.style.color = '#ff6b6b';
            uploadMessageElement.textContent = 'Server Error during upload.';
        }
    } finally {
        event.target.value = null; // Clear the file input
        if (uploadMessageElement) {
            setTimeout(() => { uploadMessageElement.textContent = ''; }, 3000);
        }
    }
}

// Function to handle photo deletion
async function deletePhoto(photoId) {
    if (!confirm("Are you sure you want to delete this photo? This cannot be undone.")) {
        return;
    }

    try {
        const response = await fetch(`${SERVER_URL}/api/photos/${photoId}`, {
            method: 'DELETE'
        });
        const data = await response.json();

        if (data.success) {
            galleryItems = galleryItems.filter(item => item._id !== photoId);
            renderGallery();
            alert("Photo deleted successfully!");
        } else {
            alert(`Deletion failed: ${data.message}`);
        }
    } catch (error) {
        console.error("Delete Photo Error:", error);
        alert("Server Error during deletion.");
    }
}

// --- 3. LIGHTBOX FUNCTIONS ---

function openLightbox(index) {
    currentIndex = index;
    updateLightbox(); 
    document.getElementById('lightbox').classList.add('active');
}
function closeLightbox() {
    document.getElementById('lightbox').classList.remove('active');
}
function navigateLightbox(dir) {
    currentIndex += dir;
    if (currentIndex < 0) currentIndex = galleryItems.length - 1;
    if (currentIndex >= galleryItems.length) currentIndex = 0;
    updateLightbox();
}
function updateLightbox() {
    const item = galleryItems[currentIndex];
    const lightboxImg = document.getElementById('lightbox-img');
    if (lightboxImg && item) {
        lightboxImg.src = item.src;
        lightboxImg.alt = item.title;
    }
}

// --- 4. INITIALIZATION ---

document.addEventListener('DOMContentLoaded', async () => {
    // 1. Attach form handlers
    const loginForm = document.getElementById('loginForm');
    if (loginForm) loginForm.addEventListener('submit', handleLogin);
    
    const registerForm = document.getElementById('registerForm');
    if (registerForm) registerForm.addEventListener('submit', handleRegister);

    // 2. Gallery Page Logic
    if (document.body.classList.contains('gallery-page')) {
        // Fetch login status from server
        const statusResponse = await fetch(`${SERVER_URL}/api/status`);
        const statusData = await statusResponse.json();
        
        const loginPrompt = document.getElementById("loginPrompt");
        const gallerySection = document.getElementById("gallerySection");
        const usernameDisplay = document.getElementById("usernameDisplay");
        
        if (usernameDisplay) {
            usernameDisplay.textContent = statusData.isLoggedIn ? statusData.username : 'Guest';
        }

        if (statusData.isLoggedIn) {
            if (loginPrompt) loginPrompt.style.display = "none";
            if (gallerySection) gallerySection.style.display = "block";
            fetchGalleryImages(); // Load data from server
            
            // Attach Upload Listener (Ensure it's attached after gallerySection is visible)
            const uploadInput = document.getElementById('uploadInput');
            if(uploadInput) uploadInput.addEventListener('change', uploadPhoto);
        } else {
            // User is not logged in
            if (loginPrompt) loginPrompt.style.display = "block";
            if (gallerySection) gallerySection.style.display = "none";
            // Optionally, clear local storage items if status is not logged in
            localStorage.removeItem(LOGIN_TOKEN);
            localStorage.removeItem('username');
        }
    }
});