const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
require('dotenv').config(); // This loads environment variables from the .env file


const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());
app.use(
  cors({
    origin: 'http://127.0.0.1:5500',
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
      await db; // Await the connection (as it's a promise)
      console.log('Connected to the database');
      break;  // Exit the loop if connection is successful
    } catch (err) {
      console.error('Database connection failed:', err.message);
      retries -= 1;
      if (retries === 0) {
        console.error('Max retries reached. Exiting process.');
        process.exit(1); // Exit process after max retries
      }
      console.log(`Retrying... (${5 - retries} attempt(s) left)`);
      await new Promise(res => setTimeout(res, 5000)); // Wait 5 seconds before retry
    }
  }
};

// Connect to the database
connectToDatabase();

// Helper function to generate JWT
const generateToken = (userId) => {
  return jwt.sign(
    { user_id: userId }, // Payload including user ID
    'secretkey',     // Secret key for signing the token
    { expiresIn: '24h' }  // Token expiration time (24 hours)
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
      [username, hashedPassword, 1000, email || null, phone_number || null], // Use null if email or phone_number is not provided
      (err, result) => {
        if (err) {
          if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ error: 'Username, email, or phone number already exists' });
          }
          console.error('Error registering user:', err);
          return res.status(500).json({ error: 'Error registering user' });
        }

        // Generate a token after successful registration
        const token = generateToken(result.insertId); // Use the ID of the newly created user
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

      const token = generateToken(user.user_id);  // Ensure user.id is passed here
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
  const { betAmount, numberOfPanels, outcome, payout } = req.body;

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
        console.error('Error fetching balance or user not found:', err);
        return res.status(500).json({ error: 'Error fetching balance' });
      }

      const currentBalance = result[0].balance;
      // if (betAmount > currentBalance) {
      //   return res.status(400).json({ error: 'Insufficient balance' });
      // }

      const newBalance = currentBalance + payout - betAmount;

// Log game outcome in `game_outcomes` table
const query = `
  INSERT INTO game_outcomes (user_id, bet_amount, panels, outcome, payout, balance_after, created_at)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`;
const values = [decoded.user_id, betAmount, numberOfPanels, JSON.stringify(outcome), payout, newBalance, new Date()];

db.query(query, values, (err) => {
  if (err) {
    console.error('Error logging game outcome:', err);
    return res.status(500).json({ error: 'Error logging game outcome' });
  }

  // Update user balance
  db.query('UPDATE users SET balance = ? WHERE user_id = ?', [newBalance, decoded.user_id], (err) => {
    if (err) {
      console.error('Error updating user balance:', err);
      return res.status(500).json({ error: 'Error updating user balance' });
    }
    
    res.status(200).json({
      message: 'Game outcome processed successfully',
      newBalance,
          });
        });
      });
    });
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
      'SELECT username, balance FROM users WHERE user_id = ?',  // Ensure 'id' is used here
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
  console.log(`Server is running on http://localhost:${PORT}`);
});
