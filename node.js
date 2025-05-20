// server.js - Main server file
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { google } = require('googleapis');
const cookieParser = require('cookie-parser');
const path = require('path');
require('dotenv').config();

// Import models
const User = require('./models/User');
const Task = require('./models/Task');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5000',
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/todo_app')
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'Authentication required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ message: 'Invalid or expired token' });
  }
};

// Google OAuth Configuration
const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

// Routes
// User Registration
app.post('/api/users/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists with this email' });
    }
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Create new user
    const user = new User({
      name,
      email,
      password: hashedPassword
    });
    
    await user.save();
    
    // Generate JWT token
    const token = jwt.sign(
      { id: user._id, email: user.email, name: user.name },
      process.env.JWT_SECRET || 'your_jwt_secret',
      { expiresIn: '24h' }
    );
    
    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });
    
    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      },
      token
    });
    
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

// User Login
app.post('/api/users/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }
    
    // Validate password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }
    
    // Generate JWT token
    const token = jwt.sign(
      { id: user._id, email: user.email, name: user.name },
      process.env.JWT_SECRET || 'your_jwt_secret',
      { expiresIn: '24h' }
    );
    
    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });
    
    res.json({
      message: 'Login successful',
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        googleCalendarConnected: !!user.googleRefreshToken
      },
      token
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// User Logout
app.post('/api/users/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out successfully' });
});

// Get Current User
app.get('/api/users/current', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.json({
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        googleCalendarConnected: !!user.googleRefreshToken
      }
    });
    
  } catch (error) {
    console.error('Get current user error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Task Routes
// Get all tasks for a user
app.get('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const tasks = await Task.find({ user: req.user.id }).sort({ createdAt: -1 });
    res.json(tasks);
  } catch (error) {
    console.error('Get tasks error:', error);
    res.status(500).json({ message: 'Server error while fetching tasks' });
  }
});

// Create a new task
app.post('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const { name, description, dueDate, priority, reminder, addToCalendar } = req.body;
    
    const task = new Task({
      name,
      description,
      dueDate,
      priority,
      reminder,
      user: req.user.id
    });
    
    await task.save();
    
    // Add to Google Calendar if requested
    if (addToCalendar) {
      await addTaskToGoogleCalendar(task, req.user.id);
    }
    
    res.status(201).json(task);
    
  } catch (error) {
    console.error('Create task error:', error);
    res.status(500).json({ message: 'Server error while creating task' });
  }
});

// Update a task
app.put('/api/tasks/:id', authenticateToken, async (req, res) => {
  try {
    const { name, description, dueDate, priority, reminder, completed, addToCalendar } = req.body;
    
    const task = await Task.findById(req.params.id);
    
    if (!task) {
      return res.status(404).json({ message: 'Task not found' });
    }
    
    // Check if task belongs to current user
    if (task.user.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Not authorized to update this task' });
    }
    
    // Update task fields
    task.name = name || task.name;
    task.description = description || task.description;
    task.dueDate = dueDate || task.dueDate;
    task.priority = priority || task.priority;
    task.reminder = reminder || task.reminder;
    
    if (completed !== undefined) {
      task.completed = completed;
      task.completedAt = completed ? new Date() : null;
    }
    
    await task.save();
    
    // Update in Google Calendar if needed
    if (addToCalendar && task.googleEventId) {
      await updateTaskInGoogleCalendar(task, req.user.id);
    } else if (addToCalendar) {
      await addTaskToGoogleCalendar(task, req.user.id);
    }
    
    res.json(task);
    
  } catch (error) {
    console.error('Update task error:', error);
    res.status(500).json({ message: 'Server error while updating task' });
  }
});

// Delete a task
app.delete('/api/tasks/:id', authenticateToken, async (req, res) => {
  try {
    const task = await Task.findById(req.params.id);
    
    if (!task) {
      return res.status(404).json({ message: 'Task not found' });
    }
    
    // Check if task belongs to current user
    if (task.user.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Not authorized to delete this task' });
    }
    
    // Remove from Google Calendar if there's an event ID
    if (task.googleEventId) {
      await removeTaskFromGoogleCalendar(task, req.user.id);
    }
    
    await task.deleteOne();
    
    res.json({ message: 'Task deleted successfully' });
    
  } catch (error) {
    console.error('Delete task error:', error);
    res.status(500).json({ message: 'Server error while deleting task' });
  }
});

// Google Calendar Integration
// Generate OAuth URL
app.get('/api/google/auth-url', authenticateToken, (req, res) => {
  const scopes = [
    'https://www.googleapis.com/auth/calendar',
    'https://www.googleapis.com/auth/calendar.events'
  ];
  
  const authUrl = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: scopes,
    prompt: 'consent' // Force to get refresh token
  });
  
  res.json({ authUrl });
});

// Handle OAuth callback
app.get('/api/google/callback', async (req, res) => {
  const { code } = req.query;
  
  try {
    const { tokens } = await oauth2Client.getToken(code);
    
    // Get user info from the token
    const ticket = await oauth2Client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    
    const payload = ticket.getPayload();
    const email = payload.email;
    
    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).send('User not found');
    }
    
    // Save refresh token to user
    user.googleRefreshToken = tokens.refresh_token;
    await user.save();
    
    // Redirect to frontend with success message
    res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:5000'}?google=success`);
    
  } catch (error) {
    console.error('Google OAuth error:', error);
    res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:5000'}?google=error`);
  }
});

// Check Google Calendar connection
app.get('/api/google/status', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.json({ connected: !!user.googleRefreshToken });
    
  } catch (error) {
    console.error('Google status check error:', error);
    res.status(500).json({ message: 'Server error checking Google connection' });
  }
});

// Disconnect Google Calendar
app.post('/api/google/disconnect', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    user.googleRefreshToken = null;
    await user.save();
    
    res.json({ message: 'Google Calendar disconnected successfully' });
    
  } catch (error) {
    console.error('Google disconnect error:', error);
    res.status(500).json({ message: 'Server error disconnecting Google Calendar' });
  }
});

// Helper functions for Google Calendar
async function getAuthenticatedCalendar(userId) {
  const user = await User.findById(userId);
  
  if (!user || !user.googleRefreshToken) {
    throw new Error('User not connected to Google Calendar');
  }
  
  oauth2Client.setCredentials({
    refresh_token: user.googleRefreshToken
  });
  
  return google.calendar({ version: 'v3', auth: oauth2Client });
}

async function addTaskToGoogleCalendar(task, userId) {
  try {
    const calendar = await getAuthenticatedCalendar(userId);
    
    // Create event
    const dueDate = new Date(task.dueDate);
    const endDate = new Date(dueDate);
    endDate.setHours(endDate.getHours() + 1); // Default 1 hour event
    
    const event = {
      summary: task.name,
      description: task.description,
      start: {
        dateTime: dueDate.toISOString(),
        timeZone: 'UTC'
      },
      end: {
        dateTime: endDate.toISOString(),
        timeZone: 'UTC'
      }
    };
    
    // Add reminder if specified
    if (task.reminder && task.reminder !== 'none') {
      event.reminders = {
        useDefault: false,
        overrides: [
          { method: 'popup', minutes: parseInt(task.reminder) }
        ]
      };
    }
    
    const response = await calendar.events.insert({
      calendarId: 'primary',
      resource: event
    });
    
    // Save Google Calendar event ID to task
    task.googleEventId = response.data.id;
    await task.save();
    
    return response;
    
  } catch (error) {
    console.error('Error adding task to Google Calendar:', error);
    throw error;
  }
}

async function updateTaskInGoogleCalendar(task, userId) {
  try {
    const calendar = await getAuthenticatedCalendar(userId);
    
    // Update event
    const dueDate = new Date(task.dueDate);
    const endDate = new Date(dueDate);
    endDate.setHours(endDate.getHours() + 1); // Default 1 hour event
    
    const event = {
      summary: task.name,
      description: task.description,
      start: {
        dateTime: dueDate.toISOString(),
        timeZone: 'UTC'
      },
      end: {
        dateTime: endDate.toISOString(),
        timeZone: 'UTC'
      }
    };
    
    // Add reminder if specified
    if (task.reminder && task.reminder !== 'none') {
      event.reminders = {
        useDefault: false,
        overrides: [
          { method: 'popup', minutes: parseInt(task.reminder) }
        ]
      };
    }
    
    const response = await calendar.events.update({
      calendarId: 'primary',
      eventId: task.googleEventId,
      resource: event
    });
    
    return response;
    
  } catch (error) {
    console.error('Error updating task in Google Calendar:', error);
    throw error;
  }
}

async function removeTaskFromGoogleCalendar(task, userId) {
  try {
    const calendar = await getAuthenticatedCalendar(userId);
    
    await calendar.events.delete({
      calendarId: 'primary',
      eventId: task.googleEventId
    });
    
    return true;
    
  } catch (error) {
    console.error('Error removing task from Google Calendar:', error);
    throw error;
  }
}

// Error Handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});