require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const http = require('http');
const socketio = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const app = express();
const server = http.createServer(app);

const io = socketio(server, {
  cors: {
    origin: [
  "http://localhost:3000",
  "https://video-conference-frontend.vercel.app"
],
    methods: ["GET", "POST"]
  }
});

app.use(cors({
  origin: [
  "http://localhost:3000",
  "https://video-conference-frontend.vercel.app"
]
}));

app.use(express.json());

// ✅ Health check endpoint (keeps Render.com instance alive)
app.get('/health', (req, res) => res.json({ status: 'ok' }));

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

// ✅ JWT Auth Middleware
const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>

  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // { userId: '...' }
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid or expired token.' });
  }
};

// ✅ Rate limiting — prevent brute force on auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  message: { message: 'Too many attempts. Please try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false
});

// Register Route
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // ✅ Server-side input validation
    if (!name || name.trim().length < 2) {
      return res.status(400).json({ message: 'Name must be at least 2 characters.' });
    }
    if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
      return res.status(400).json({ message: 'Please provide a valid email address.' });
    }
    if (!password || password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters.' });
    }

    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ message: 'An account with this email already exists.' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    user = new User({ name: name.trim(), email: email.toLowerCase(), password: hashedPassword });
    await user.save();

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Login Route
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    // ✅ Server-side input validation
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required.' });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Create Room — protected
app.post('/api/rooms/create', verifyToken, async (req, res) => {
  try {
    // ✅ userId from verified token, not req.body
    const userId = req.user.userId;
    const roomId = Math.random().toString(36).substring(2, 10).toUpperCase();
    const room = new Room({ roomId, host: userId, participants: [userId] });
    await room.save();
    res.json({ roomId, room });
  } catch (error) {
    res.status(500).json({ message: 'Error creating room' });
  }
});

// Get Room — protected
app.get('/api/rooms/:roomId', verifyToken, async (req, res) => {
  try {
    const room = await Room.findOne({ roomId: req.params.roomId });
    if (!room) return res.status(404).json({ message: 'Room not found' });
    res.json(room);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching room' });
  }
});

// Socket.IO - WebRTC Signaling
const rooms = {};
// waiting: { [roomId]: [{ socketId, userId, userName }] }
const waiting = {};

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('join-room', ({ roomId, userId, userName }) => {
    if (!rooms[roomId]) {
      // First person = host, let them in immediately
      rooms[roomId] = { users: [], messages: [], hostSocketId: socket.id };
      waiting[roomId] = [];

      socket.join(roomId);
      rooms[roomId].users.push({ socketId: socket.id, userId, userName });
      socket.emit('existing-users', []);
      socket.emit('chat-history', []);
      socket.emit('join-approved');
      console.log(`Host ${userName} created room ${roomId}`);
    } else {
      // Room exists — put new user in waiting room, notify host
      if (!waiting[roomId]) waiting[roomId] = [];
      waiting[roomId].push({ socketId: socket.id, userId, userName });

      // Tell the joiner they are waiting
      socket.emit('waiting-for-approval');

      // Notify host to admit/deny
      const hostSocketId = rooms[roomId].hostSocketId;
      io.to(hostSocketId).emit('admission-request', {
        socketId: socket.id,
        userName,
        userId
      });
      console.log(`${userName} is waiting to join ${roomId}`);
    }
  });

  // Host admits a waiting user
  socket.on('admit-user', ({ roomId, socketId }) => {
    const waitingList = waiting[roomId] || [];
    const user = waitingList.find(u => u.socketId === socketId);
    if (!user) return;

    // Remove from waiting list
    waiting[roomId] = waitingList.filter(u => u.socketId !== socketId);

    const admittedSocket = io.sockets.sockets.get(socketId);
    if (!admittedSocket) return;

    admittedSocket.join(roomId);

    const existingUsers = [...rooms[roomId].users];
    rooms[roomId].users.push({ socketId, userId: user.userId, userName: user.userName });

    // Tell admitted user they're in
    admittedSocket.emit('join-approved');
    admittedSocket.emit('existing-users', existingUsers);
    admittedSocket.emit('chat-history', rooms[roomId].messages);

    console.log(`${user.userName} admitted to ${roomId}`);
  });

  // Host denies a waiting user
  socket.on('deny-user', ({ roomId, socketId }) => {
    const waitingList = waiting[roomId] || [];
    waiting[roomId] = waitingList.filter(u => u.socketId !== socketId);

    io.to(socketId).emit('join-denied');
    console.log(`User ${socketId} denied from ${roomId}`);
  });

  // Initiator (new joiner) sends signal to each existing peer
  socket.on('sending-signal', ({ userToSignal, callerID, signal }) => {
    const room = Object.keys(rooms).find(roomId =>
      rooms[roomId].users.some(u => u.socketId === callerID)
    );

    if (room) {
      // ✅ Fixed: send CALLER's info, not the target's
      const caller = rooms[room].users.find(u => u.socketId === callerID);
      io.to(userToSignal).emit('user-connected', {
        signal,
        socketId: callerID,
        userId: caller?.userId,
        userName: caller?.userName
      });
    }
  });

  // Existing peer responds to initiator
  socket.on('returning-signal', ({ callerID, signal }) => {
    io.to(callerID).emit('receiving-returned-signal', {
      signal,
      id: socket.id
    });
  });

  // Chat messages
  socket.on('send-message', ({ roomId, message, userName }) => {
    const msg = { userName, message, timestamp: new Date().toISOString() };
    if (rooms[roomId]) {
      rooms[roomId].messages.push(msg);
    }
    // ✅ Fixed: broadcast to others only — sender adds message locally
    socket.to(roomId).emit('new-message', msg);
  });

  // Disconnect
  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);

    // Remove from any waiting lists
    Object.keys(waiting).forEach(roomId => {
      if (waiting[roomId]) {
        waiting[roomId] = waiting[roomId].filter(u => u.socketId !== socket.id);
      }
    });

    Object.keys(rooms).forEach(async (roomId) => {
      if (rooms[roomId]) {
        const userIndex = rooms[roomId].users.findIndex(u => u.socketId === socket.id);
        if (userIndex !== -1) {
          const user = rooms[roomId].users[userIndex];
          rooms[roomId].users.splice(userIndex, 1);

          socket.to(roomId).emit('user-disconnected', {
            socketId: socket.id,
            userName: user.userName
          });

          // If host left, assign new host or clean up
          if (rooms[roomId].hostSocketId === socket.id) {
            if (rooms[roomId].users.length > 0) {
              rooms[roomId].hostSocketId = rooms[roomId].users[0].socketId;
              io.to(rooms[roomId].hostSocketId).emit('you-are-host');
            }
          }

          // Clean up empty rooms
          if (rooms[roomId].users.length === 0) {
            delete rooms[roomId];
            delete waiting[roomId];
            try {
              await Room.deleteOne({ roomId });
            } catch (err) {
              console.error('Error cleaning up room from DB:', err);
            }
          }
        }
      }
    });
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});