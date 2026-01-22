// Load environment variables from .env file
require('dotenv').config();

const express = require('express');
const ejs = require('ejs');
const { v4: uuidv4 } = require('uuid'); // For generating unique IDs for testimonial links
const jwt = require('jsonwebtoken'); // For admin authentication
const cookieParser = require('cookie-parser'); // To parse cookies for JWT
const multer = require('multer'); // For handling file uploads
const path = require('path'); // NEW: Import the 'path' module

// Firebase Admin SDK for server-side database operations (Firestore will still be used)
const admin = require('firebase-admin');

// --- IMPORTANT FOR DEPLOYMENT ---
// Instead of requiring a local file, we will parse the JSON content from an environment variable.
// This is the secure way to handle service account keys on platforms like Vercel.
// Ensure FIREBASE_ADMIN_SDK_CONFIG is set on Vercel with the full JSON content of your serviceAccountKey.json
const serviceAccount = JSON.parse(process.env.FIREBASE_ADMIN_SDK_CONFIG);

// Initialize Firebase App options defensively
const firebaseAppOptions = {
    credential: admin.credential.cert(serviceAccount),
};

// Conditionally add storageBucket if it's defined and not an empty string
// This prevents the "Bucket name not specified" error if STORAGE_BUCKET is truly not set or empty
if (process.env.STORAGE_BUCKET && process.env.STORAGE_BUCKET.trim() !== '') {
    firebaseAppOptions.storageBucket = process.env.STORAGE_BUCKET;
}

admin.initializeApp(firebaseAppOptions);

const db = admin.firestore(); // Firestore instance

// Conditionally initialize bucket if STORAGE_BUCKET is provided
// This also prevents errors if Storage is not intended for use
let bucket = null;
if (process.env.STORAGE_BUCKET && process.env.STORAGE_BUCKET.trim() !== '') {
    try {
        bucket = admin.storage().bucket(process.env.STORAGE_BUCKET);
    } catch (error) {
        console.warn('Firebase Storage bucket initialization warning: ', error.message);
        // If there's an issue initializing the bucket, 'bucket' will remain null.
        // This is okay if Cloudinary is the primary upload method.
    }
}

const app = express();
const PORT = process.env.PORT || 3000;

// --- CORS Configuration for Deployment ---
// For development, app.use(cors()); is fine (allows all origins).
// For production, it's highly recommended to restrict this to your frontend's deployed URL.
// After deploying your frontend, replace 'YOUR_DEPLOYED_FRONTEND_URL_HERE' with its actual URL.
const cors = require('cors'); // Ensure cors is imported if it wasn't already
app.use(cors({
   origin: [
        'https://hudeen.netlify.app',
        'http://Localhost://5173' // Add your additional URL here
    ],// e.g., 'https://your-frontend-app.vercel.app'
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true, // Needed if you're using cookies (like for admin auth)
    optionsSuccessStatus: 204
}));


// NEW: Configure Cloudinary
const cloudinary = require('cloudinary').v2; // Ensure cloudinary is imported if it wasn't already
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Configure multer for file uploads
const upload = multer({
    storage: multer.memoryStorage(), // Store file in memory
    limits: {
        fileSize: 20 * 1024 * 1024 // Limit file size to 20MB
    },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'), false);
        }
    }
});

// Middleware
app.set('view engine', 'ejs'); // Set EJS as the template engine
// NEW: Explicitly set the views directory for EJS to ensure it's found on deployment
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public')); // Serve static files from the 'public' directory
app.use(express.json()); // Parse JSON request bodies (for non-file uploads)
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded request bodies
app.use(cookieParser()); // Parse cookies

const LINK_EXPIRY_HOURS = 24;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const JWT_SECRET = process.env.JWT_SECRET;

const authenticateAdmin = (req, res, next) => {
    const token = req.cookies.adminToken;
    if (!token) {
        return res.redirect('/admin/login');
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        console.error('Admin authentication error:', error);
        return res.redirect('/admin/login');
    }
};

// --- Routes ---

// 1. API for Approved Testimonials (for external landing pages)
app.get('/api/testimonials/approved', async (req, res) => {
    try {
        const testimonialsRef = db.collection('testimonials');
        const snapshot = await testimonialsRef.where('status', '==', 'approved').orderBy('submissionDate', 'desc').get();
        const testimonials = [];
        snapshot.forEach(doc => {
            const data = doc.data();
            testimonials.push({
                id: doc.id,
                ...data,
                submissionDate: data.submissionDate ? new Date(data.submissionDate._seconds * 1000).toISOString() : null
            });
        });
        res.status(200).json(testimonials);
    } catch (error) {
        console.error('Error fetching approved testimonials for API:', error);
        res.status(500).json({ error: 'Error fetching testimonials.' });
    }
});

// 2. Admin Login Page
app.get('/admin/login', (req, res) => {
    res.render('adminLogin', { message: null });
});

// 3. Handle Admin Login
app.post('/admin/login', (req, res) => {
    const { username, password } = req.body;
    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        const token = jwt.sign({ username: ADMIN_USERNAME, role: 'admin' }, JWT_SECRET, { expiresIn: '1h' });
        res.cookie('adminToken', token, { httpOnly: true, maxAge: 3600000 });
        return res.redirect('/admin/dashboard');
    } else {
        res.render('adminLogin', { message: 'Invalid credentials. Please try again.' });
    }
});

// 4. Admin Dashboard
app.get('/admin/dashboard', authenticateAdmin, async (req, res) => {
    try {
        const testimonialsRef = db.collection('testimonials');
        const totalSnapshot = await testimonialsRef.get();
        const pendingSnapshot = await testimonialsRef.where('status', '==', 'pending').get();
        const approvedSnapshot = await testimonialsRef.where('status', '==', 'approved').get();
        const deletedSnapshot = await testimonialsRef.where('status', '==', 'deleted').get();

        const totalCount = totalSnapshot.size;
        const pendingCount = pendingSnapshot.size;
        const approvedCount = approvedSnapshot.size;
        const deletedCount = deletedSnapshot.size;

        const pendingTestimonials = [];
        pendingSnapshot.forEach(doc => {
            pendingTestimonials.push({ id: doc.id, ...doc.data() });
        });

        res.render('adminDashboard', {
            totalCount,
            pendingCount,
            approvedCount,
            deletedCount,
            pendingTestimonials
        });
    } catch (error) {
        console.error('Error fetching dashboard data:', error);
        res.status(500).send('Error loading dashboard.');
    }
});

// 5. Admin View All Testimonials
app.get('/admin/testimonials', authenticateAdmin, async (req, res) => {
    try {
        const testimonialsRef = db.collection('testimonials');
        const snapshot = await testimonialsRef.orderBy('submissionDate', 'desc').get();
        const testimonials = [];
        snapshot.forEach(doc => {
            testimonials.push({ id: doc.id, ...doc.data() });
        });
        res.render('adminTestimonials', { testimonials });
    } catch (error) {
        console.error('Error fetching testimonials for admin:', error);
        res.status(500).send('Error loading testimonials for admin.');
    }
});

// 6. Generate One-Time Testimonial Link (Admin only)
app.post('/admin/generate-link', authenticateAdmin, async (req, res) => {
    try {
        const token = uuidv4();
        const createdAt = admin.firestore.FieldValue.serverTimestamp();
        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + LINK_EXPIRY_HOURS);

        await db.collection('testimonialLinks').doc(token).set({
            createdAt,
            expiresAt: admin.firestore.Timestamp.fromDate(expiresAt),
            isUsed: false
        });

        const testimonialLink = `${req.protocol}://${req.get('host')}/testimonial/${token}`;
        res.status(200).json({ message: 'Link generated successfully!', link: testimonialLink });
    } catch (error) {
        console.error('Error generating testimonial link:', error);
        res.status(500).json({ error: 'Failed to generate link.' });
    }
});

// 7. Testimonial Form Page (Accessed via one-time link)
app.get('/testimonial/:token', async (req, res) => {
    const { token } = req.params;
    try {
        const linkDoc = await db.collection('testimonialLinks').doc(token).get();

        if (!linkDoc.exists) {
            return res.status(404).send('Testimonial link not found or invalid.');
        }

        const linkData = linkDoc.data();
        const currentTime = new Date();

        if (linkData.isUsed || linkData.expiresAt.toDate() < currentTime) {
            return res.status(400).send('Testimonial link is expired or has already been used.');
        }

        res.render('testimonialForm', { token });
    } catch (error) {
        console.error('Error validating testimonial link:', error);
        res.status(500).send('An error occurred while validating the link.');
    }
});

// 8. Handle Testimonial Submission
app.post('/submit-testimonial', upload.single('picture'), async (req, res) => {
    const { token, name, role, company, message } = req.body;
    const file = req.file;

    if (!token || !name || !message) {
        return res.status(400).send('Missing required fields (token, name, message).');
    }

    try {
        const linkDocRef = db.collection('testimonialLinks').doc(token);
        const linkDoc = await linkDocRef.get();

        if (!linkDoc.exists) {
            return res.status(404).send('Testimonial link not found or invalid.');
        }

        const linkData = linkDoc.data();
        const currentTime = new Date();

        if (linkData.isUsed || linkData.expiresAt.toDate() < currentTime) {
            return res.status(400).send('Testimonial link is expired or has already been used.');
        }

        let pictureUrl = 'https://placehold.co/100x100/CCCCCC/000000?text=No+Img'; // Default placeholder URL

        if (file) {
            const uploadResult = await cloudinary.uploader.upload(
                `data:${file.mimetype};base64,${file.buffer.toString('base64')}`,
                {
                    folder: 'testimonial_pictures',
                    public_id: uuidv4()
                }
            );
            pictureUrl = uploadResult.secure_url;
        }

        await db.collection('testimonials').add({
            name,
            role: role || 'N/A',
            company: company || 'N/A',
            message,
            pictureUrl: pictureUrl,
            submissionDate: admin.firestore.FieldValue.serverTimestamp(),
            status: 'pending'
        });

        await linkDocRef.update({ isUsed: true });

        res.status(200).send('Testimonial submitted successfully! It will be reviewed by an admin.');
    } catch (error) {
        console.error('Error submitting testimonial or uploading picture:', error);
        if (error instanceof multer.MulterError) {
            if (error.code === 'LIMIT_FILE_SIZE') {
                return res.status(413).send('Image file is too large (max 5MB).');
            }
            return res.status(400).send(error.message);
        } else if (error.message.includes('Only image files are allowed!')) {
            return res.status(400).send('Please upload only image files.');
        } else {
            console.error('Cloudinary upload error:', error.response ? error.response.data : error.message);
            return res.status(500).send('An error occurred during image upload or submission.');
        }
    }
});

// 9. API to Approve Testimonial (Admin only)
app.patch('/api/testimonials/:id/approve', authenticateAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        await db.collection('testimonials').doc(id).update({ status: 'approved' });
        res.status(200).json({ message: 'Testimonial approved successfully.' });
    } catch (error) {
        console.error('Error approving testimonial:', error);
        res.status(500).json({ error: 'Failed to approve testimonial.' });
    }
});

// 10. API to Delete Testimonial (Admin only)
app.delete('/api/testimonials/:id/delete', authenticateAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        await db.collection('testimonials').doc(id).update({ status: 'deleted' });
        res.status(200).json({ message: 'Testimonial deleted successfully.' });
    } catch (error) {
        console.error('Error deleting testimonial:', error);
        res.status(500).json({ error: 'Failed to delete testimonial.' });
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
