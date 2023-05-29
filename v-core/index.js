const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
require('dotenv').config();

// Create Express app
const app = express();

// Body parsing middleware
app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env["DB_STRING"], {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('Failed to connect to MongoDB', err));

// User Schema
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
  },
  username: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    enum: ['admin', 'player'],
    default: 'player',
  },
});

// Race Schema
const raceSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,
  },
  image: {
    type: String,
    required: true,
  },
  description: {
    type: String,
    required: true,
  },
});

// Class Schema
const classSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,
  },
  image: {
    type: String,
    required: true,
  },
  description: {
    type: String,
    required: true,
  },
});

// Models
const User = mongoose.model('User', userSchema);
const Race = mongoose.model('Race', raceSchema);
const Class = mongoose.model('Class', classSchema);

// User Registration
app.post('/register', async (req, res) => {
  try {
    const { email, username, password } = req.body;

    // Check if email or username already exist
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(409).json({ error: 'Email or username already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const user = new User({
      email,
      username,
      password: hashedPassword,
    });

    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('User Registration Error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// User Login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Compare passwords
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Create and return JWT
    const token = jwt.sign({ userId: user._id, role: user.role }, process.env["SECRET_KEY"]);
    res.json({ token });
  } catch (error) {
    console.error('User Login Error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Middleware to authenticate JWT
const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  jwt.verify(token, process.env["SECRET_KEY"], (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    req.user = user;
    next();
  });
};

// Race CRUD Routes
app.get('/races', async (req, res) => {
  try {
    const races = await Race.find();
    res.json(races);
  } catch (error) {
    console.error('Get Races Error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/races', authenticateJWT, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const race = new Race(req.body);
    await race.save();
    res.status(201).json({ message: 'Race created successfully' });
  } catch (error) {
    console.error('Create Race Error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.put('/races/:id', authenticateJWT, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const race = await Race.findByIdAndUpdate(req.params.id, req.body);
    if (!race) {
      return res.status(404).json({ error: 'Race not found' });
    }
    res.json({ message: 'Race updated successfully' });
  } catch (error) {
    console.error('Update Race Error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.delete('/races/:id', authenticateJWT, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const race = await Race.findByIdAndDelete(req.params.id);
    if (!race) {
      return res.status(404).json({ error: 'Race not found' });
    }
    res.json({ message: 'Race deleted successfully' });
  } catch (error) {
    console.error('Delete Race Error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Class CRUD Routes
app.get('/classes', async (req, res) => {
  try {
    const classes = await Class.find();
    res.json(classes);
  } catch (error) {
    console.error('Get Classes Error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/classes', authenticateJWT, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const rpgClass = new Class(req.body);
    await rpgClass.save();
    res.status(201).json({ message: 'Class created successfully' });
  } catch (error) {
    console.error('Create Class Error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.put('/classes/:id', authenticateJWT, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const rpgClass = await Class.findByIdAndUpdate(req.params.id, req.body);
    if (!rpgClass) {
      return res.status(404).json({ error: 'Class not found' });
    }
    res.json({ message: 'Class updated successfully' });
  } catch (error) {
    console.error('Update Class Error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.delete('/classes/:id', authenticateJWT, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const rpgClass = await Class.findByIdAndDelete(req.params.id);
    if (!rpgClass) {
      return res.status(404).json({ error: 'Class not found' });
    }
    res.json({ message: 'Class deleted successfully' });
  } catch (error) {
    console.error('Delete Class Error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Change Password
app.put('/change-password', authenticateJWT, async (req, res) => {
    try {
      const { currentPassword, newPassword } = req.body;
      const user = await User.findById(req.user.userId);
      
      // Check if current password matches
      const isPasswordMatch = await bcrypt.compare(currentPassword, user.password);
      if (!isPasswordMatch) {
        return res.status(401).json({ error: 'Incorrect current password' });
      }
  
      // Update the password
      const hashedNewPassword = await bcrypt.hash(newPassword, 10);
      user.password = hashedNewPassword;
      await user.save();
  
      res.json({ message: 'Password changed successfully' });
    } catch (error) {
      console.error('Change Password Error:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });
  

// Start the server
app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
