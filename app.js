const express = require('express');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const port = 3020;

// Ensure images directory exists
const imagesDir = path.join(__dirname, 'images');
if (!fs.existsSync(imagesDir)) {
    fs.mkdirSync(imagesDir, { recursive: true });
}

// Initialize SQLite database
const dbPath = process.env.NODE_ENV === 'production' ? './data/sqlite.db' : './sqlite.db';
const db = new sqlite3.Database(dbPath);

// Create table if it doesn't exist
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date DATETIME DEFAULT CURRENT_TIMESTAMP,
            description TEXT NOT NULL,
            image TEXT
        )
    `);
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('.'));
app.use('/images', express.static('images'));

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

// API Routes

// POST /api/post - Create a new blog post
app.post('/api/post', upload.single('image'), (req, res) => {
    const { description } = req.body;
    
    if (!description || description.trim() === '') {
        return res.status(400).send('Description is required');
    }
    
    const imageFilename = req.file ? req.file.filename : null;
    
    const query = `INSERT INTO posts (description, image) VALUES (?, ?)`;
    
    db.run(query, [description.trim(), imageFilename], function(err) {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send('Database error');
        }
        
        res.status(201).json({
            id: this.lastID,
            message: 'Post created successfully'
        });
    });
});

// GET /api/today - Get posts from today
app.get('/api/today', (req, res) => {
    const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD format
    
    const query = `
        SELECT id, date, description, image 
        FROM posts 
        WHERE date(date) = date(?)
        ORDER BY date DESC
    `;
    
    db.all(query, [today], (err, rows) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send('Database error');
        }
        
        res.json(rows);
    });
});

// GET /api/all - Get all posts
app.get('/api/all', (req, res) => {
    const query = `
        SELECT id, date, description, image 
        FROM posts 
        ORDER BY date DESC
    `;
    
    db.all(query, [], (err, rows) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send('Database error');
        }
        
        res.json(rows);
    });
});

// GET /api/search - Search for posts
app.get('/api/search', (req, res) => {
    const { term } = req.query;

    if (!term || term.trim() === '') {
        return res.status(400).send('Search term is required');
    }

    const query = `
        SELECT id, date, description, image 
        FROM posts 
        WHERE description LIKE ?
        ORDER BY date DESC
    `;
    
    db.all(query, [`%${term}%`], (err, rows) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send('Database error');
        }
        
        res.json(rows);
    });
});

// PUT /api/post/:id - Update a blog post
app.put('/api/post/:id', upload.single('image'), (req, res) => {
    const postId = parseInt(req.params.id);
    const { description, removeImage } = req.body;
    
    if (!postId || isNaN(postId)) {
        return res.status(400).send('Invalid post ID');
    }
    
    if (!description || description.trim() === '') {
        return res.status(400).send('Description is required');
    }
    
    // First, get the current post to handle image deletion
    db.get('SELECT image FROM posts WHERE id = ?', [postId], (err, currentPost) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send('Database error');
        }
        
        if (!currentPost) {
            return res.status(404).send('Post not found');
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
                console.error('Database error:', err);
                return res.status(500).send('Database error');
            }
            
            if (this.changes === 0) {
                return res.status(404).send('Post not found');
            }
            
            res.json({
                id: postId,
                message: 'Post updated successfully'
            });
        });
    });
});

// DELETE /api/post/:id - Delete a blog post
app.delete('/api/post/:id', (req, res) => {
    const postId = parseInt(req.params.id);
    
    if (!postId || isNaN(postId)) {
        return res.status(400).send('Invalid post ID');
    }
    
    // First, get the post to delete associated image file
    db.get('SELECT image FROM posts WHERE id = ?', [postId], (err, post) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send('Database error');
        }
        
        if (!post) {
            return res.status(404).send('Post not found');
        }
        
        // Delete the post from database
        db.run('DELETE FROM posts WHERE id = ?', [postId], function(err) {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).send('Database error');
            }
            
            if (this.changes === 0) {
                return res.status(404).send('Post not found');
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
    console.log(`API endpoints:`);
    console.log(`  POST /api/post - Create new post`);
    console.log(`  GET  /api/today - Get today's posts`);
    console.log(`  GET  /api/all - Get all posts`);
    console.log(`  GET  /api/search?term={query} - Search posts`);
});