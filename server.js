import express from 'express';
import cors from 'cors';
import { Client } from 'pg';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import axios from 'axios';
import 'dotenv/config'; 

const dbClient = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false 
    }
});

dbClient.connect()
    .then(() => console.log('✅ Successfully connected to Neon PostgreSQL!'))
    .catch(err => console.error('❌ Database connection error:', err.stack));

const app = express();
app.use(cors());
app.use(express.json()); 

const JWT_SECRET = process.env.JWT_SECRET;

// SIGNUP ROUTE
app.post('/api/signup', async (req, res) => {
    try {
        const { email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);

        const result = await dbClient.query(
            'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, is_premium, free_applies',
            [email, hashedPassword]
        );

        const newUser = result.rows[0];
        const token = jwt.sign({ userId: newUser.id }, JWT_SECRET, { expiresIn: '7d' });

        res.status(201).json({ user: newUser, token });
    } catch (err) {
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
        const result = await dbClient.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });

        res.json({ 
            user: { 
                id: user.id, 
                email: user.email, 
                is_premium: user.is_premium,
                free_applies: user.free_applies 
            }, 
            token 
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// MIDDLEWARE
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 

    if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token.' });
        req.user = user; 
        next();
    });
};

// GET JOBS (Secure Feed - No apply links sent)
app.get('/api/jobs', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = 50; 
        const offset = (page - 1) * limit;

        const titleQuery = req.query.title || '';
        const locationQuery = req.query.location || '';
        const departmentQuery = req.query.department || '';

        let userId = null;
        const authHeader = req.headers['authorization'];
        if (authHeader) {
            const token = authHeader.split(' ')[1];
            try {
                const decoded = jwt.verify(token, process.env.JWT_SECRET); 
                userId = decoded.userId;
            } catch (e) {
                // Ignore expired/invalid tokens and just show the public feed
            }
        }

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
        
        const result = await dbClient.query(query, queryParams);
        res.json(result.rows); 
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// SECURE APPLY GATEKEEPER
app.get('/api/jobs/:id/apply', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const jobId = req.params.id;

        // 1. Fetch user status
        const userQuery = await dbClient.query('SELECT is_premium, free_applies FROM users WHERE id = $1', [userId]);
        const user = userQuery.rows[0];

        if (!user) return res.status(404).json({ error: 'User not found.' });

        // 2. Block if free applies are empty and they aren't premium
        if (!user.is_premium && user.free_applies <= 0) {
            return res.status(403).json({ 
                error: 'Premium required', 
                message: 'You have used all your free applies. Please upgrade to Premium.' 
            });
        }

        // 3. Fetch the secure apply link
        const jobQuery = await dbClient.query('SELECT apply_url FROM jobs WHERE id = $1', [jobId]);
        const job = jobQuery.rows[0];

        if (!job) return res.status(404).json({ error: 'Job not found.' });

        // 4. Deduct a free apply if they are not premium
        if (!user.is_premium) {
            await dbClient.query('UPDATE users SET free_applies = free_applies - 1 WHERE id = $1', [userId]);
        }

        // 5. Automatically log the job as applied
        await dbClient.query(
            'INSERT INTO applied_jobs (user_id, job_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
            [userId, jobId]
        );

        // 6. Return the secure link to the frontend
        res.json({ apply_url: job.apply_url });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// GET APPLIED JOBS
app.get('/api/jobs/applied', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        
        const query = `
            SELECT jobs.id, jobs.company_token, jobs.title, jobs.location, jobs.department, applied_jobs.applied_at 
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

// UPGRADE TO PREMIUM
app.post('/api/user/upgrade', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        await dbClient.query('UPDATE users SET is_premium = TRUE WHERE id = $1', [userId]);
        res.json({ success: true, message: 'Account upgraded to premium.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// CANCEL PREMIUM
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
        res.status(500).json({ error: 'Failed to cancel subscription.' });
    }
});

app.listen(5000, () => console.log('API running on port 5000'));