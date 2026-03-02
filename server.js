import express from 'express';
import cors from 'cors';
import { Client } from 'pg';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import axios from 'axios'
import 'dotenv/config'; // Add this to the very top of your file

const dbClient = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false // This line forces Node to trust the Neon certificate
    }
});

dbClient.connect()
    .then(() => console.log('✅ Successfully connected to Neon PostgreSQL!'))
    .catch(err => console.error('❌ Database connection error:', err.stack));

const app = express();
app.use(cors());
app.use(express.json()); // CRITICAL: Allows Express to read req.body




// Replace this with a strong, hidden environment variable in production


// SIGNUP ROUTE
app.post('/api/signup', async (req, res) => {
    try {
        const { email, password } = req.body;

        // 1. Hash the password (salt rounds = 10)
        const hashedPassword = await bcrypt.hash(password, 10);

        // 2. Save the user to the database
        const result = await dbClient.query(
            'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email',
            [email, hashedPassword]
        );

        const newUser = result.rows[0];

        // 3. Create a JWT token so they are instantly logged in
        const token = jwt.sign({ userId: newUser.id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.status(201).json({ user: newUser, token });
    } catch (err) {
        // Error code 23505 means unique violation (email already exists)
        if (err.code === '23505') {
            res.status(400).json({ error: 'Email already in use.' });
        } else {
            res.status(500).json({ error: err.message });
        }
    }
});

// LOGIN ROUTE
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // 1. Find the user by email
        const result = await dbClient.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        // 2. Compare the typed password with the hashed password in the DB
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        // 3. Generate a new JWT token
        // Inside your app.post('/api/login') route
        const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.json({ 
            user: { 
                id: user.id, 
                email: user.email, 
                is_premium: user.is_premium,
                free_applies: user.free_applies // ADD THIS LINE
            }, 
            token 
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// MIDDLEWARE: We will use this in the next step to protect the "Mark as Applied" route
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Format: "Bearer <token>"

    if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token.' });
        req.user = user; // Attach the user ID to the request
        next();
    });
};

// ... (Keep your existing GET /api/jobs route down here) ...
app.get('/api/jobs', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = 50; 
        const offset = (page - 1) * limit;

        const titleQuery = req.query.title || '';
        const locationQuery = req.query.location || '';
        const departmentQuery = req.query.department || '';

        // 1. Check if the user is logged in by looking for a token
        let userId = null;
        const authHeader = req.headers['authorization'];
        if (authHeader) {
            const token = authHeader.split(' ')[1];
            try {
                const decoded = jwt.verify(token, JWT_SECRET); // Must match your secret
                userId = decoded.userId;
            } catch (e) {
                // Ignore expired/invalid tokens and just show the public feed
            }
        }

        // 2. Build the query. If userId exists, add the exclusion subquery.
        let query = `
            SELECT * FROM jobs 
            WHERE title ILIKE $1 
              AND location ILIKE $2 
              AND department ILIKE $3
        `;
        
        const queryParams = [`%${titleQuery}%`, `%${locationQuery}%`, `%${departmentQuery}%`, limit, offset];

        if (userId) {
            query += ` AND id NOT IN (SELECT job_id FROM applied_jobs WHERE user_id = $6) `;
            queryParams.push(userId);
        }

        query += ` ORDER BY updated_at DESC LIMIT $4 OFFSET $5;`;
        
        // Update the final res.json() response at the bottom of your /api/login route
        const result = await dbClient.query(query, queryParams);
        res.json(result.rows); // Make sure it looks exactly like this
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// NEW: Route to mark a job as applied
app.post('/api/jobs/apply', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId; // Extracted from the verified JWT
        const { jobId } = req.body;

        await dbClient.query(
            'INSERT INTO applied_jobs (user_id, job_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
            [userId, jobId]
        );

        res.json({ success: true, message: 'Job marked as applied.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/jobs/applied', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        
        const query = `
            SELECT jobs.*, applied_jobs.applied_at 
            FROM jobs 
            INNER JOIN applied_jobs ON jobs.id = applied_jobs.job_id 
            WHERE applied_jobs.user_id = $1 
            ORDER BY applied_jobs.applied_at DESC;
        `;
        
        const result = await dbClient.query(query, [userId]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Add this above your app.listen line
app.post('/api/user/upgrade', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        
        // In a production environment, you would also verify the Flutterwave transaction ID here
        await dbClient.query('UPDATE users SET is_premium = TRUE WHERE id = $1', [userId]);
        
        res.json({ success: true, message: 'Account upgraded to premium.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/user/cancel', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        
        const userResult = await dbClient.query('SELECT email FROM users WHERE id = $1', [userId]);
        if (userResult.rows.length === 0) return res.status(404).json({ error: 'User not found' });
        const email = userResult.rows[0].email;

        const flwSecret = process.env.FLWSEC_KEY; 
        
        const subResponse = await axios.get(`https://api.flutterwave.com/v3/subscriptions?email=${email}`, {
            headers: { 'Authorization': `Bearer ${flwSecret}` }
        });

        const subscriptions = subResponse.data.data;
        if (subscriptions && subscriptions.length > 0) {
            const activeSub = subscriptions.find(sub => sub.status === 'active');
            if (activeSub) {
                await axios.put(`https://api.flutterwave.com/v3/subscriptions/${activeSub.id}/cancel`, {}, {
                    headers: { 'Authorization': `Bearer ${flwSecret}` }
                });
            }
        }

        await dbClient.query('UPDATE users SET is_premium = FALSE WHERE id = $1', [userId]);
        
        res.json({ success: true, message: 'Subscription successfully cancelled.' });
    } catch (err) {
        console.error('Cancellation error:', err.response ? err.response.data : err.message);
        res.status(500).json({ error: 'Failed to cancel subscription.' });
    }
});
app.post('/api/user/use-free-apply', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const result = await dbClient.query(
            'UPDATE users SET free_applies = free_applies - 1 WHERE id = $1 AND free_applies > 0 RETURNING free_applies',
            [userId]
        );
        
        if (result.rows.length === 0) {
            return res.status(403).json({ error: 'No free applies left' });
        }
        
        res.json({ success: true, free_applies: result.rows[0].free_applies });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.listen(5000, () => console.log('API running on port 5000'));