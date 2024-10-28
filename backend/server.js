require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected'))
.catch((error) => {
  console.error('MongoDB connection error:', error.message);
  process.exit(1);
});

// User Schema and Model
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  mobile: { type: String, required: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
});
const User = mongoose.model('User', userSchema);

// Certificate Schema and Model
const certificateSchema = new mongoose.Schema({
  certificateId: { type: String, required: true, unique: true },
  userEmail: { type: String, required: true },
  courseName: { type: String, required: true },
  issuedDate: { type: Date, required: true },
  expiryDate: { type: Date, required: true },
  studentName: { type: String, required: true }, // New field for student's name
  issuer: { type: String, required: true }, // New field for issuer's name
});
const Certificate = mongoose.model('Certificate', certificateSchema);
module.exports = Certificate;




// Authentication Middleware
const authMiddleware = async (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'No token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.userId).select('-password');
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Admin Middleware
const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Access denied' });
  next();
};

// Register User
app.post('/api/auth/register', async (req, res) => {
  const { email, mobile, password, role } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, mobile, password: hashedPassword, role });
    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login User
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, role: user.role });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Route to fetch user profile by email
app.get('/api/users/:email', authMiddleware, async (req, res) => {
  const { email } = req.params;

  try {
    const user = await User.findOne({ email }).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add Certificate (Admin only)
app.post('/api/certificates/add', authMiddleware, isAdmin, async (req, res) => {
  const { certificateId, userEmail, courseName, issuedDate, expiryDate,studentName,issuer } = req.body;

  if (!certificateId || !userEmail || !courseName || !issuedDate || !expiryDate) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  const user = await User.findOne({ email: userEmail });
  if (!user) {
    return res.status(404).json({ message: 'User with the provided email does not exist' });
  }

  const existingCertificate = await Certificate.findOne({ certificateId });
  if (existingCertificate) {
    return res.status(400).json({ message: 'Certificate ID already exists' });
  }

  try {
    const newCertificate = new Certificate({
      certificateId,
      userEmail,
      courseName,
      issuedDate: new Date(issuedDate),
      expiryDate: new Date(expiryDate),
      studentName,
      issuer,
    });

    await newCertificate.save();
    res.status(201).json({ message: 'Certificate added successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Verify Certificate by certificateId
app.get('/api/certificates/verify/:certificateId', async (req, res) => {
  const { certificateId } = req.params;
  try {
    const certificate = await Certificate.findOne({ certificateId });
    if (!certificate) return res.status(404).json({ message: 'Certificate not found' });

    const isValid = !certificate.expiryDate || certificate.expiryDate > new Date();
    res.json({ valid: isValid, certificate });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Verify Certificate by Email
app.post('/api/certificates/verify', async (req, res) => {
  const { email } = req.body;

  try {
    const certificate = await Certificate.findOne({ userEmail: email });
    if (certificate) {
      return res.json({ valid: true, certificate });
    } else {
      return res.status(404).json({ valid: false, message: 'No certificate found for this email.' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Error verifying certificate.' });
  }
});










const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
