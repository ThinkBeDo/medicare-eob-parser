const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// In production, these should come from environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const JWT_EXPIRE = process.env.JWT_EXPIRE || '1h';
const SALT_ROUNDS = 10;

// User storage (in production, this should be a database)
const users = new Map();

// Hash password
async function hashPassword(password) {
  return await bcrypt.hash(password, SALT_ROUNDS);
}

// Verify password
async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

// Generate JWT token
function generateToken(userId, role = 'user') {
  return jwt.sign(
    { userId, role, timestamp: Date.now() },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRE }
  );
}

// Verify JWT token
function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
}

// Register user
async function registerUser(username, password, role = 'user') {
  if (users.has(username)) {
    throw new Error('User already exists');
  }
  
  const hashedPassword = await hashPassword(password);
  const user = {
    id: Date.now().toString(),
    username,
    password: hashedPassword,
    role,
    createdAt: new Date().toISOString(),
    lastLogin: null
  };
  
  users.set(username, user);
  return { id: user.id, username: user.username, role: user.role };
}

// Login user
async function loginUser(username, password) {
  const user = users.get(username);
  if (!user) {
    throw new Error('Invalid credentials');
  }
  
  const isValid = await verifyPassword(password, user.password);
  if (!isValid) {
    throw new Error('Invalid credentials');
  }
  
  // Update last login
  user.lastLogin = new Date().toISOString();
  users.set(username, user);
  
  const token = generateToken(user.id, user.role);
  return {
    token,
    user: {
      id: user.id,
      username: user.username,
      role: user.role
    }
  };
}

// Get user by ID
function getUserById(userId) {
  for (const [username, user] of users) {
    if (user.id === userId) {
      return {
        id: user.id,
        username: user.username,
        role: user.role
      };
    }
  }
  return null;
}

// Initialize default admin user (for demo purposes)
async function initializeDefaultUsers() {
  try {
    await registerUser('admin', 'Admin123!@#', 'admin');
    await registerUser('user', 'User123!@#', 'user');
    console.log('Default users created (admin/Admin123!@#, user/User123!@#)');
  } catch (error) {
    // Users already exist
  }
}

module.exports = {
  hashPassword,
  verifyPassword,
  generateToken,
  verifyToken,
  registerUser,
  loginUser,
  getUserById,
  initializeDefaultUsers
};