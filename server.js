// Import necessary modules and models
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { User, Credential, Division, OU } = require('./models'); // Make sure models are correctly imported

const app = express();
app.use(express.json());
app.use(cors());

const port = process.env.PORT || 3030;
const mongoUri = process.env.MONGO_URI;
const jwtSecret = process.env.JWT_SECRET;

mongoose.connect(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Endpoint: User Registration
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.error('Error in registration:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Endpoint: User Login
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user._id, username: user.username, role: user.role }, jwtSecret, { expiresIn: '1h' });

    res.json({ token });
  } catch (err) {
    console.error('Error in login:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Middleware: Authenticate Token
function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, jwtSecret, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Protected Route Example
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: 'This is a protected route', user: req.user });
});

// Endpoint: Fetch Division Credentials
app.get('/division-credentials', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).populate('division');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const credentials = await Credential.find({ division: user.division._id });

    res.json({ credentials });
  } catch (err) {
    console.error('Error fetching division credentials:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Endpoint: Add Credential to a Specific Repository
app.post('/add-credential', authenticateToken, async (req, res) => {
  try {
    const { system, login, password, divisionId } = req.body;

    if (!mongoose.Types.ObjectId.isValid(divisionId)) {
      return res.status(400).json({ message: 'Invalid divisionId format' });
    }

    const division = await Division.findById(divisionId);
    if (!division) {
      return res.status(404).json({ message: 'Division not found' });
    }

    const user = await User.findById(req.user.id);
    if (!user || !user.division.equals(division._id)) {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    const newCredential = new Credential({
      system,
      login,
      password,
      division: division._id,
    });

    await newCredential.save();

    res.status(201).json({ message: 'Credential added successfully', credential: newCredential });
  } catch (err) {
    console.error('Error adding credential:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Endpoint: Update User Credentials
app.put('/update-credentials', authenticateToken, async (req, res) => {
  try {
    const { newPassword } = req.body;

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    user.password = hashedPassword;
    await user.save();

    res.json({ message: 'User credentials updated successfully' });
  } catch (err) {
    console.error('Error updating user credentials:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Endpoint: Assign Division to User
app.put('/assign-division', authenticateToken, async (req, res) => {
  try {
    const { divisionId } = req.body;

    if (!mongoose.Types.ObjectId.isValid(divisionId)) {
      return res.status(400).json({ message: 'Invalid divisionId format' });
    }

    const division = await Division.findById(divisionId);
    if (!division) {
      return res.status(404).json({ message: 'Division not found' });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.division = divisionId;
    await user.save();

    res.json({ message: 'Division assigned successfully' });
  } catch (err) {
    console.error('Error assigning division:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Endpoint: Fetch All OUs
app.get('/ous', authenticateToken, async (req, res) => {
  try {
    const ous = await OU.find();
    res.json({ ous });
  } catch (err) {
    console.error('Error fetching OUs:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Endpoint: Change User Role
app.put('/change-role', authenticateToken, async (req, res) => {
  try {
    const { userId, newRole } = req.body;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.role = newRole;
    await user.save();

    res.json({ message: 'User role updated successfully', user });
  } catch (err) {
    console.error('Error changing user role:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
