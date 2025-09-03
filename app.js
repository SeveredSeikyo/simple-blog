const express = require('express');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const ModelClient = require("@azure-rest/ai-inference").default;
const { isUnexpected } = require("@azure-rest/ai-inference");
const { AzureKeyCredential } = require("@azure/core-auth");

const app = express();
const port = 3020;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-change-it';

// Ensure images directory exists
const imagesDir = path.join(__dirname, 'images');
if (!fs.existsSync(imagesDir)) {
    fs.mkdirSync(imagesDir, { recursive: true });
}

// Initialize SQLite database
const dbPath = process.env.NODE_ENV === 'production' ? './data/sqlite.db' : './sqlite.db';
const db = new sqlite3.Database(dbPath);

// Create tables if they don't exist
db.serialize(() => {
    // Users table
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    `);

    // Posts table with user_id foreign key
        db.run(`
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            author TEXT NOT NULL,
            date DATETIME DEFAULT CURRENT_TIMESTAMP,
            description TEXT NOT NULL,
            image TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('.'));
app.use('/images', express.static('images'));

// Auth middleware to verify JWT
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).send('Access denied. No token provided.');
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (ex) {
        res.status(400).send('Invalid token.');
    }
};

// Configure multer for image uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'images/');
    },
    filename: (req, file, cb) => {
        const uniqueName = `${Date.now()}-${uuidv4()}${path.extname(file.originalname)}`;
        cb(null, uniqueName);
    }
});

const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|webp/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Only image files are allowed'));
        }
    },
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    }
});

// --- API Routes ---

// --- Auth Routes ---

// POST /api/register - Register a new user
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send('Username and password are required');
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const query = `INSERT INTO users (username, password) VALUES (?, ?)`;
    db.run(query, [username, hashedPassword], function(err) {
        if (err) {
            if (err.message.includes('UNIQUE constraint failed')) {
                return res.status(409).send('Username already exists');
            }
            console.error('Database error in POST /api/register:', err.message);
            return res.status(500).send('Database error');
        }
        res.status(201).json({ id: this.lastID, username: username });
    });
});

// POST /api/login - Login a user
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send('Username and password are required');
    }

    const query = `SELECT * FROM users WHERE username = ?`;
    db.get(query, [username], async (err, user) => {
        if (err) {
            console.error('Database error in POST /api/login:', err.message);
            return res.status(500).send('Database error');
        }
        if (!user) {
            return res.status(400).send('Invalid username or password');
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).send('Invalid username or password');
        }

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    });
});

// GET /api/post - Get posts by author
app.get('/api/post', (req, res) => {
    const { author } = req.query;

    if (!author || author.trim() === '') {
        return res.status(400).send('Author is required');
    }

    const query = `
        SELECT p.id, p.user_id, p.date, p.description, p.image, p.author
        FROM posts p
        WHERE p.author = ?
        ORDER BY p.date DESC
    `;

    db.all(query, [author], (err, rows) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send('Database error');
        }

        res.json(rows);
    });
});


// --- Blog Post Routes ---

// POST /api/post - Create a new blog post (Protected)
app.post('/api/post', [verifyToken, upload.single('image')], (req, res) => {
    const { description } = req.body;
    
    if (!description || description.trim() === '') {
        return res.status(400).send('Description is required');
    }
    
    const imageFilename = req.file ? req.file.filename : null;
    const userId = req.user.id;
    const author = req.user.username;

    const query = `INSERT INTO posts (user_id, author, description, image) VALUES (?, ?, ?, ?)`;
    
    db.run(query, [userId, author, description.trim(), imageFilename], function(err) {
        if (err) {
            console.error('Database error in POST /api/post:', err.message);
            return res.status(500).send('Database error');
        }
        
        res.status(201).json({
            id: this.lastID,
            message: 'Post created successfully'
        });
    });
});

// GET /api/today - Get posts from today (Public)
app.get('/api/today', (req, res) => {
    const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD format
    
    const query = `
        SELECT p.id, p.user_id, p.date, p.description, p.image, p.author
        FROM posts p
        WHERE date(p.date) = date(?)
        ORDER BY p.date DESC
    `;
    
    db.all(query, [today], (err, rows) => {
        if (err) {
            console.error('Database error in GET /api/today:', err.message);
            return res.status(500).send('Database error');
        }
        
        res.json(rows);
    });
});

// GET /api/post/today - Get posts from today by author
app.get('/api/post/today', (req, res) => {
    const { author } = req.query;
    const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD format

    if (!author || author.trim() === '') {
        return res.status(400).send('Author is required');
    }

    const query = `
        SELECT p.id, p.user_id, p.date, p.description, p.image, p.author
        FROM posts p
        WHERE date(p.date) = date(?) AND p.author = ?
        ORDER BY p.date DESC
    `;

    db.all(query, [today, author], (err, rows) => {
        if (err) {
            console.error('Database error in GET /api/post/today:', err.message);
            return res.status(500).send('Database error');
        }

        res.json(rows);
    });
});

app.get('/generate-linkedIn-post', async (req, res) => {
    const { author } = req.query;

    if (!author) {
        return res.status(400).json({ error: 'Author is required' });
    }

    try {
        const today = new Date().toISOString().split('T')[0];
        const query = `
            SELECT description
            FROM posts
            WHERE author = ? AND date(date) = ?
        `;

        db.all(query, [author, today], async (err, rows) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ error: 'Failed to fetch posts' });
            }

            if (!rows.length) {
                return res.status(404).json({ error: 'No posts found for today' });
            }

            const descriptions = rows.map(row => row.description);

            const GITHUB_TOKEN = process.env.API_KEY;
            const client = ModelClient(
                "https://models.github.ai/inference",
                new AzureKeyCredential(GITHUB_TOKEN)
            );

            const systemPrompt = `
            You are a professional content writer specializing in LinkedIn posts for the tech community. 
            Your role is to turn raw blog entries (given in JSON) into engaging, concise, and professional LinkedIn posts. 
            
            RULES:
            - Always use the given JSON as the sole source of content (do not invent unrelated topics).
            - Extract the "description" field as the blog content.
            - Summarize the main idea clearly.
            - Add a personal or reflective angle if possible.
            - Keep the tone friendly but professional (no jargon overload).
            - Encourage engagement with a question or call-to-action.
            - Length: 100–200 words.
            - If "image" is not null, suggest a 1-line caption.
            
            RETURN FORMAT:
            Return only valid JSON in the following format:
            {
              "linkedin_post": "final LinkedIn post text here"
            }
            `;

            const userPrompt = `
            Here is today’s blog post in JSON format:

            ${JSON.stringify(descriptions, null, 2)}

            Task:
            1. Extract the title and main idea from "description".
            2. Rewrite it as a LinkedIn post (100–200 words).
            3. Keep the tone professional + personal.
            4. If an "image" is present, add a one-line caption suggestion.
            5. Return the final LinkedIn post strictly as JSON with key "linkedin_post".
            `;

            const response = await client.path("/chat/completions").post({
                body: {
                    messages: [
                        { role: "system", content: systemPrompt },
                        { role: "user", content: userPrompt }
                    ],
                    model: "xai/grok-3-mini",
                    max_tokens: 1024,
                    temperature: 1,
                    top_p: 1,
                    response_format: { type: "json_object" }
                }
            });

            // Debug log full response
            console.log("Raw API response:", JSON.stringify(response.body, null, 2));

            if (!response.body || !response.body.choices || response.body.choices.length === 0) {
                return res.status(500).json({ error: "No choices returned", details: response.body });
            }

            const resultText = response.body.choices[0].message.content;

            let result;
            try {
                result = JSON.parse(resultText);
            } catch (e) {
                console.error("Non-JSON output from model:", resultText);
                return res.status(500).json({ error: "Model did not return valid JSON" });
            }

            res.json(result);
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to generate LinkedIn post' });
    }
});


// GET /api/all - Get all posts (Public)
app.get('/api/all', (req, res) => {
    const query = `
        SELECT p.id, p.user_id, p.date, p.description, p.image, p.author
        FROM posts p
        ORDER BY p.date DESC
    `;
    
    db.all(query, [], (err, rows) => {
        if (err) {
            console.error('Database error in GET /api/all:', err.message);
            return res.status(500).send('Database error');
        }
        
        res.json(rows);
    });
});

// GET /api/search - Search for posts (Public)
app.get('/api/search', (req, res) => {
    const { term } = req.query;

    if (!term || term.trim() === '') {
        return res.status(400).send('Search term is required');
    }

    const query = `
        SELECT p.id, p.user_id, p.date, p.description, p.image, p.author
        FROM posts p
        WHERE p.description LIKE ?
        ORDER BY p.date DESC
    `;
    
    db.all(query, [`%${term}%`], (err, rows) => {
        if (err) {
            console.error('Database error in GET /api/search:', err.message);
            return res.status(500).send('Database error');
        }
        
        res.json(rows);
    });
});

// PUT /api/post/:id - Update a blog post (Protected & Ownership required)
app.put('/api/post/:id', [verifyToken, upload.single('image')], (req, res) => {
    const postId = parseInt(req.params.id);
    const { description, removeImage } = req.body;
    const userId = req.user.id;

    if (!postId || isNaN(postId)) {
        return res.status(400).send('Invalid post ID');
    }
    
    if (!description || description.trim() === '') {
        return res.status(400).send('Description is required');
    }
    
    // First, get the current post to check ownership and handle image deletion
    db.get('SELECT user_id, image FROM posts WHERE id = ?', [postId], (err, currentPost) => {
        if (err) {
            console.error('Database error in PUT /api/post/:id (get post):', err.message);
            return res.status(500).send('Database error');
        }
        
        if (!currentPost) {
            return res.status(404).send('Post not found');
        }

        if (currentPost.user_id !== userId) {
            return res.status(403).send('Forbidden: You do not own this post');
        }
        
        let newImageFilename = currentPost.image; // Keep current image by default
        
        // Handle new image upload
        if (req.file) {
            newImageFilename = req.file.filename;
            
            // Delete old image file if it exists
            if (currentPost.image) {
                const oldImagePath = path.join(__dirname, 'images', currentPost.image);
                fs.unlink(oldImagePath, (err) => {
                    if (err) console.log('Could not delete old image:', err);
                });
            }
        }
        // Handle image removal
        else if (removeImage === 'true') {
            newImageFilename = null;
            
            // Delete current image file if it exists
            if (currentPost.image) {
                const oldImagePath = path.join(__dirname, 'images', currentPost.image);
                fs.unlink(oldImagePath, (err) => {
                    if (err) console.log('Could not delete image:', err);
                });
            }
        }
        
        // Update the post
        const query = `UPDATE posts SET description = ?, image = ? WHERE id = ?`;
        
        db.run(query, [description.trim(), newImageFilename, postId], function(err) {
            if (err) {
                console.error('Database error in PUT /api/post/:id (update post):', err.message);
                return res.status(500).send('Database error');
            }
            
            res.json({
                id: postId,
                message: 'Post updated successfully'
            });
        });
    });
});

// DELETE /api/post/:id - Delete a blog post (Protected & Ownership required)
app.delete('/api/post/:id', verifyToken, (req, res) => {
    const postId = parseInt(req.params.id);
    const userId = req.user.id;

    if (!postId || isNaN(postId)) {
        return res.status(400).send('Invalid post ID');
    }
    
    // First, get the post to check ownership and delete associated image file
    db.get('SELECT user_id, image FROM posts WHERE id = ?', [postId], (err, post) => {
        if (err) {
            console.error('Database error in DELETE /api/post/:id (get post):', err.message);
            return res.status(500).send('Database error');
        }
        
        if (!post) {
            return res.status(404).send('Post not found');
        }

        if (post.user_id !== userId) {
            return res.status(403).send('Forbidden: You do not own this post');
        }
        
        // Delete the post from database
        db.run('DELETE FROM posts WHERE id = ?', [postId], function(err) {
            if (err) {
                console.error('Database error in DELETE /api/post/:id (delete post):', err.message);
                return res.status(500).send('Database error');
            }
            
            // Delete associated image file if it exists
            if (post.image) {
                const imagePath = path.join(__dirname, 'images', post.image);
                fs.unlink(imagePath, (err) => {
                    if (err) console.log('Could not delete image file:', err);
                });
            }
            
            res.json({
                message: 'Post deleted successfully'
            });
        });
    });
});

// GET / - Serve the main HTML file
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Error handling middleware
app.use((error, req, res, next) => {
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).send('File too large');
        }
    }
    
    if (error.message === 'Only image files are allowed') {
        return res.status(400).send('Only image files are allowed');
    }
    
    console.error('Unhandled error:', error);
    res.status(500).send('Internal server error');
});

// Handle 404
app.use((req, res) => {
    res.status(404).send('Page not found');
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('Shutting down gracefully...');
    db.close((err) => {
        if (err) {
            console.error('Error closing database:', err);
        } else {
            console.log('Database connection closed.');
        }
        process.exit(0);
    });
});

// Start server
app.listen(port, '0.0.0.0', () => {
    console.log(`Blog app running on http://localhost:${port}`);
});
