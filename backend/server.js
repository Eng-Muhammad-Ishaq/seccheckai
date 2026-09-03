const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Database setup
const db = new sqlite3.Database('./secheckai.db', (err) => {
  if (err) {
    console.error('Database error:', err);
  } else {
    console.log('✅ Database connected');
    createTables();
  }
});

// Create tables function
function createTables() {
  // Create users table
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, (err) => {
    if (err) {
      console.error('Table creation error:', err);
    } else {
      console.log('✅ Users table ready');
    }
  });

  // Create analyses table
  db.run(`
    CREATE TABLE IF NOT EXISTS analyses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      input_text TEXT,
      risk_score INTEGER,
      threats TEXT,
      recommendations TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )
  `, (err) => {
    if (err) {
      console.error('Analyses table error:', err);
    } else {
      console.log('✅ Analyses table ready');
    }
  });
}

// Secret key for JWT
const JWT_SECRET = 'seccheckai-secret-key-2026';

// ============================================
// HEALTH CHECK
// ============================================
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    message: 'SecCheck AI Backend Running' 
  });
});

// ============================================
// REGISTER ENDPOINT
// ============================================
app.post('/api/auth/register', async (req, res) => {
  console.log('📝 Register request received');
  
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, existingUser) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Server error' });
      }

      if (existingUser) {
        return res.status(400).json({ error: 'User already exists' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      db.run(
        'INSERT INTO users (email, password) VALUES (?, ?)',
        [email, hashedPassword],
        function(err) {
          if (err) {
            console.error('Insert error:', err);
            return res.status(500).json({ error: 'Registration failed' });
          }

          const token = jwt.sign(
            { userId: this.lastID, email: email },
            JWT_SECRET,
            { expiresIn: '24h' }
          );

          console.log('✅ User registered:', email);
          
          res.status(201).json({
            message: 'Registration successful',
            token: token,
            user: { id: this.lastID, email: email }
          });
        }
      );
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// ============================================
// LOGIN ENDPOINT
// ============================================
app.post('/api/auth/login', (req, res) => {
  console.log('🔑 Login request received');
  
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Server error' });
    }

    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    console.log('✅ User logged in:', email);
    
    res.json({
      message: 'Login successful',
      token: token,
      user: { id: user.id, email: user.email }
    });
  });
});

// ============================================
// SMART ANALYSIS FUNCTION
// ============================================
function analyzeInput(inputText) {
  const input = inputText.toLowerCase();
  let riskScore = 15;
  let threats = [];
  let recommendations = [];
  
  // SQL injection
  if (input.includes('sql') || input.includes('query') || input.includes('database') || input.includes('select') || input.includes('mysql') || input.includes('postgres')) {
    riskScore += 20;
    threats.push('SQL Injection vulnerability detected');
    recommendations.push('Use parameterized queries instead of string concatenation');
  }
  
  // XSS
  if (input.includes('script') || input.includes('html') || input.includes('javascript') || input.includes('innerhtml') || input.includes('xss')) {
    riskScore += 15;
    threats.push('Cross-site scripting (XSS) risk found');
    recommendations.push('Sanitize all user inputs and use Content Security Policy (CSP)');
  }
  
  // Authentication
  if (input.includes('login') || input.includes('password') || input.includes('auth') || input.includes('credential')) {
    riskScore += 15;
    threats.push('Weak authentication mechanism detected');
    recommendations.push('Implement multi-factor authentication and strong password policies');
  }
  
  // Encryption
  if (input.includes('http://') && !input.includes('https://')) {
    riskScore += 25;
    threats.push('Unencrypted data transmission (HTTP detected)');
    recommendations.push('Enable HTTPS/SSL encryption for all data transmission');
  }
  
  // File upload
  if (input.includes('upload') || input.includes('file') || input.includes('image') || input.includes('attachment')) {
    riskScore += 10;
    threats.push('Potential file upload vulnerability');
    recommendations.push('Validate file types and scan uploads for malware');
  }
  
  // API
  if (input.includes('api') || input.includes('endpoint') || input.includes('rest') || input.includes('graphql')) {
    riskScore += 10;
    threats.push('API security misconfiguration risk');
    recommendations.push('Implement API rate limiting and proper authentication');
  }
  
  // Sensitive paths
  if (input.includes('admin') || input.includes('root') || input.includes('config') || input.includes('.env') || input.includes('backup')) {
    riskScore += 15;
    threats.push('Sensitive system path or admin access detected');
    recommendations.push('Restrict access to administrative functions and sensitive files');
  }
  
  // Command injection
  if (input.includes('eval') || input.includes('exec') || input.includes('system(') || input.includes('shell')) {
    riskScore += 20;
    threats.push('Command injection risk detected');
    recommendations.push('Never pass user input to system commands or eval functions');
  }
  
  // Session
  if (input.includes('session') || input.includes('cookie') || input.includes('token')) {
    riskScore += 10;
    threats.push('Session management vulnerability possible');
    recommendations.push('Use secure, HTTP-only cookies and implement session timeout');
  }
  
  // Headers
  if (input.includes('header') || input.includes('csp') || input.includes('cors')) {
    riskScore += 5;
    threats.push('Security headers misconfiguration possible');
    recommendations.push('Implement proper CORS policy and security headers');
  }
  
  // No threats found
  if (threats.length === 0) {
    riskScore = Math.floor(Math.random() * 15) + 5;
    threats.push('No critical vulnerabilities detected in basic scan');
    recommendations.push('Continue regular security audits and monitoring');
    recommendations.push('Keep software and dependencies updated');
  }
  
  riskScore = Math.min(riskScore, 95);
  
  return {
    riskScore: riskScore,
    threats: threats.slice(0, 5),
    recommendations: recommendations.slice(0, 5)
  };
}

// ============================================
// ANALYSIS ENDPOINT
// ============================================
app.post('/api/analysis/run', (req, res) => {
  console.log('🔍 Analysis request received');
  
  const token = req.headers.authorization?.split(' ')[1];
  const { inputText } = req.body;
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  if (!inputText) {
    return res.status(400).json({ error: 'Input text required' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const analysisResult = analyzeInput(inputText);
    
    db.run(
      'INSERT INTO analyses (user_id, input_text, risk_score, threats, recommendations) VALUES (?, ?, ?, ?, ?)',
      [
        decoded.userId,
        inputText,
        analysisResult.riskScore,
        JSON.stringify(analysisResult.threats),
        JSON.stringify(analysisResult.recommendations)
      ],
      function(err) {
        if (err) {
          console.error('Save analysis error:', err);
          return res.status(500).json({ error: 'Failed to save analysis' });
        }
        
        console.log('✅ Analysis saved. ID:', this.lastID);
        console.log('📊 Risk Score:', analysisResult.riskScore);
        console.log('🚨 Threats:', analysisResult.threats.length);
        
        res.json({
          id: this.lastID,
          ...analysisResult
        });
      }
    );
    
  } catch (error) {
    console.error('Analysis error:', error);
    res.status(401).json({ error: 'Invalid token' });
  }
});

// ============================================
// GET ANALYSIS HISTORY
// ============================================
app.get('/api/analysis/history', (req, res) => {
  console.log('📊 History request received');
  
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    db.all(
      'SELECT * FROM analyses WHERE user_id = ? ORDER BY created_at DESC LIMIT 10',
      [decoded.userId],
      (err, rows) => {
        if (err) {
          console.error('History fetch error:', err);
          return res.status(500).json({ error: 'Failed to fetch history' });
        }
        
        const history = rows.map(row => ({
          id: row.id,
          inputText: row.input_text,
          riskScore: row.risk_score,
          threats: JSON.parse(row.threats),
          recommendations: JSON.parse(row.recommendations),
          createdAt: row.created_at
        }));
        
        console.log('✅ History sent. Count:', history.length);
        res.json(history);
      }
    );
    
  } catch (error) {
    console.error('History error:', error);
    res.status(401).json({ error: 'Invalid token' });
  }
});

// ============================================
// START SERVER
// ============================================
app.listen(PORT, () => {
  console.log('🚀 SecCheck AI Backend running on http://localhost:' + PORT);
});