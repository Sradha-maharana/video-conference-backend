require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const http = require('http');
const socketio = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const io = socketio(server, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"]
  }
});

app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.log('❌ MongoDB Error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// Room Schema
const roomSchema = new mongoose.Schema({
  roomId: String,
  host: String,
  participants: [String],
  createdAt: { type: Date, default: Date.now }
});
const Room = mongoose.model('Room', roomSchema);

// Register Route
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ message: 'User exists' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    user = new User({ name, email, password: hashedPassword });
    await user.save();

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Login Route
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Create Room
app.post('/api/rooms/create', async (req, res) => {
  try {
    const { userId } = req.body;
    const roomId = Math.random().toString(36).substring(2, 10).toUpperCase();
    const room = new Room({ roomId, host: userId, participants: [userId] });
    await room.save();
    res.json({ roomId, room });
  } catch (error) {
    res.status(500).json({ message: 'Error creating room' });
  }
});

// Get Room
app.get('/api/rooms/:roomId', async (req, res) => {
  try {
    const room = await Room.findOne({ roomId: req.params.roomId });
    if (!room) return res.status(404).json({ message: 'Room not found' });
    res.json(room);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching room' });
  }
});

// Socket.IO
const rooms = {};

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('join-room', ({ roomId, userId, userName }) => {
    socket.join(roomId);
    if (!rooms[roomId]) rooms[roomId] = { users: [], messages: [] };
    rooms[roomId].users.push({ socketId: socket.id, userId, userName });
    socket.to(roomId).emit('user-connected', { userId, userName, socketId: socket.id });
    const existingUsers = rooms[roomId].users.filter(u => u.socketId !== socket.id);
    socket.emit('existing-users', existingUsers);
    socket.emit('chat-history', rooms[roomId].messages);
  });

  socket.on('signal', ({ to, signal, from }) => {
    io.to(to).emit('signal', { signal, from });
  });

  socket.on('send-message', ({ roomId, message, userName }) => {
    const msg = { userName, message, timestamp: new Date().toISOString() };
    if (rooms[roomId]) rooms[roomId].messages.push(msg);
    io.to(roomId).emit('new-message', msg);
  });

  socket.on('disconnect', () => {
    Object.keys(rooms).forEach(roomId => {
      if (rooms[roomId]) {
        const userIndex = rooms[roomId].users.findIndex(u => u.socketId === socket.id);
        if (userIndex !== -1) {
          const user = rooms[roomId].users[userIndex];
          rooms[roomId].users.splice(userIndex, 1);
          socket.to(roomId).emit('user-disconnected', { socketId: socket.id, userName: user.userName });
        }
      }
    });
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});