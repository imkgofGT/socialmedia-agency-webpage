import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';

const isValidPassword = (password) => {
  return typeof password === 'string' && password.length >= 8 && /\d/.test(password);
};

const getCookieOptions = () => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
  maxAge: 7 * 24 * 60 * 60 * 1000
});

export const signup = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ success: false, message: 'Name, email, and password are required' });
    }

    if (!isValidPassword(password)) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 8 characters and contain at least one number'
      });
    }

    const normalizedEmail = String(email).toLowerCase().trim();

    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser) {
      return res.status(409).json({ success: false, message: 'Email is already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    await User.create({
      name: String(name).trim(),
      email: normalizedEmail,
      password: hashedPassword
    });

    return res.status(201).json({ success: true, message: 'Signup successful' });
  } catch (error) {
    if (error.name === 'ValidationError') {
      return res.status(400).json({ success: false, message: error.message });
    }

    return res.status(500).json({ success: false, message: 'Server error during signup' });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required' });
    }

    const normalizedEmail = String(email).toLowerCase().trim();
    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const { JWT_SECRET } = process.env;
    if (!JWT_SECRET) {
      throw new Error('JWT_SECRET is not set in environment variables');
    }

    const token = jwt.sign({ id: user._id.toString() }, JWT_SECRET, { expiresIn: '7d' });

    res.cookie('token', token, getCookieOptions());
    return res.status(200).json({ success: true, message: 'Login successful' });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Server error during login' });
  }
};

export const logout = async (_req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
  });

  return res.status(200).json({ success: true, message: 'Logout successful' });
};

export const me = async (req, res) => {
  return res.status(200).json({
    success: true,
    user: {
      id: req.user._id,
      name: req.user.name,
      email: req.user.email
    }
  });
};
