const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
require('dotenv').config();


const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());
app.use(
  cors({
    origin: 'https://naijagamer.netlify.app',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

// MySQL connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER, 
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// Function to connect to the database with retries
const connectToDatabase = async () => {
  let retries = 5;  // Max retries
  while (retries) {
    try {
      await db; 
      console.log('Connected to the database');
      break;  
    } catch (err) {
      console.error('Database connection failed:', err.message);
      retries -= 1;
      if (retries === 0) {
        console.error('Max retries reached. Exiting process.');
        process.exit(1); 
      }
      console.log(`Retrying... (${5 - retries} attempt(s) left)`);
      await new Promise(res => setTimeout(res, 5000)); 
    }
  }
};

// Connect to the database
connectToDatabase();

const generateToken = (userId) => {
  return jwt.sign(
    { user_id: userId }, 
    'secretkey',   
    { expiresIn: '24h' }  
  );
};

// Register endpoint
app.post('/register', async (req, res) => {
  const { username, password, email, phone_number } = req.body;

  if (!username || !password || (!email && !phone_number)) {
    return res.status(400).json({ error: 'Username, password, and either email or phone number are required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user data into the database
    db.query(
      'INSERT INTO users (username, password, balance, email, phone_number) VALUES (?, ?, ?, ?, ?)',
      [username, hashedPassword, 1000, email, phone_number], 
      (err, result) => {
        if (err) {
          if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ error: 'Username, email, or phone number already exists' });
          }
          console.error('Error registering user:', err);
          return res.status(500).json({ error: 'Error registering user' });
        }

        // Generate a token after successful registration
        const token = generateToken(result.insertId);
        res.status(201).json({ message: 'User registered successfully', token });
      }
    );
  } catch (error) {
    console.error('Error during registration:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  db.query('SELECT * FROM users WHERE username = ?', [username], (err, result) => {
    if (err || result.length === 0) {
      console.error('Error finding user or user not found:', err);
      return res.status(400).json({ error: 'Invalid username or password' });
    }

    const user = result[0];
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err || !isMatch) {
        return res.status(400).json({ error: 'Invalid username or password' });
      }

      const token = generateToken(user.user_id);
      res.status(200).json({ token });
    });
  });
});

// Get and update user balance
app.route('/balance')
  .get((req, res) => {
    const token = req.headers['authorization'];

    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    jwt.verify(token, 'secretkey', (err, decoded) => {
      if (err) {
        return res.status(401).json({ error: 'Invalid token' });
      }

      db.query('SELECT balance FROM users WHERE user_id = ?', [decoded.user_id], (err, result) => {  
        if (err || result.length === 0) {
          console.error('Error fetching balance or user not found:', err);
          return res.status(500).json({ error: 'Error fetching balance' });
        }
        res.status(200).json({ balance: result[0].balance });
      });
    });
  })
  .post((req, res) => {
    const { balance } = req.body;
    const token = req.headers['authorization'];

    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }
    if (balance === undefined || isNaN(balance)) {
      return res.status(400).json({ error: 'Valid balance value required' });
    }
    jwt.verify(token, 'secretkey', (err, decoded) => {
      if (err) {
        return res.status(401).json({ error: 'Invalid token' });
      }

      db.query('UPDATE users SET balance = ? WHERE user_id = ?', [balance, decoded.user_id], (err, result) => {
        if (err) {
          console.error('Error updating balance:', err);
          return res.status(500).json({ error: 'Error updating balance' });
        }
        if (result.affectedRows === 0) {
          return res.status(404).json({ error: 'User not found' });
        }
        res.status(200).json({ message: 'Balance updated successfully' });
      });
    });
  });

// Store game outcome
app.post('/outcome', (req, res) => {
  const token = req.headers['authorization'];
  const { betAmount, numberOfPanels, outcome, payout, jackpot_type } = req.body;

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  jwt.verify(token, 'secretkey', (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    // Fetch current balance
    db.query('SELECT balance FROM users WHERE user_id = ?', [decoded.user_id], (err, result) => {  
      if (err || result.length === 0) {
        return res.status(500).json({ error: 'Error fetching balance' });
      }
      const balanceAfter = currentBalance + payout - betAmount;
      const currentBalance = result[0].balance;
      if (betAmount > currentBalance) {
        return res.status(400).json({ error: 'Insufficient balance' });
      };

// Log game outcome
const query = `
  INSERT INTO game_outcomes (user_id, bet_amount, panels, outcome, payout, balance_after, jackpot_type, created_at)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`;
const values = [decoded.user_id, betAmount, numberOfPanels, JSON.stringify(outcome), payout, balanceAfter, jackpot_type, new Date()];

db.query(query, values, (err) => {
  if (err) {
    return res.status(500).json({ error: 'Error logging game outcome' });
  }

  // Update user balance
  db.query('UPDATE users SET balance = ? WHERE user_id = ?', [balanceAfter, decoded.user_id], (err) => {
    if (err) {
      console.error('Error updating user balance:', err);
      return res.status(500).json({ error: 'Error updating user balance' });
    }
    
    res.status(200).json({
      message: 'Game outcome processed successfully',
      balanceAfter,
          });
        });
      });
    });
  });
});

// Endpoint to get the last 50 jackpot winners
app.get('/winners', (req, res) => {
  db.query('SELECT username, jackpot_type, payout, created_at FROM game_outcomes ORDER BY created_at DESC LIMIT 50', (err, result) => {
    if (err) {
      console.error('Error fetching winners:', err);
      return res.status(500).json({ error: 'Error fetching winners' });
    }

    // Map winners into a formatted message
    const winners = result.map((winner) => {
      return `${winner.username} has won a ${winner.jackpot_type} jackpot for N${winner.payout.toLocaleString()}!!!`;
    });

    res.status(200).json({ winners });
  });
});

// Add user-info endpoint
app.get('/user-info', (req, res) => {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  jwt.verify(token, 'secretkey', (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    db.query(
      'SELECT username, balance FROM users WHERE user_id = ?',
      [decoded.user_id],
      (err, result) => {
        if (err || result.length === 0) {
          console.error('Error fetching user info or user not found:', err);
          return res.status(500).json({ error: 'Error fetching user info' });
        }
        res.status(200).json({
          username: result[0].username,
          balance: result[0].balance,
        });
      }
    );
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on ${PORT}`);
});
