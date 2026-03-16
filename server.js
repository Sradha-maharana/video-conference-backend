require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const http = require('http');
const socketio = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { GoogleGenAI } = require('@google/genai');

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
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

app.get('/health', (req, res) => res.json({ status: 'ok' }));

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.log('❌ MongoDB Error:', err));

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  createdAt: { type: Date, default: Date.now },
  loginHistory: [{
    ip: String,
    userAgent: String,
    timestamp: { type: Date, default: Date.now },
    isAnomalous: Boolean,
    riskScore: Number
  }]
});
const User = mongoose.model('User', userSchema);

const roomSchema = new mongoose.Schema({
  roomId: String,
  host: String,
  participants: [String],
  createdAt: { type: Date, default: Date.now },
  status: { type: String, default: 'active' },
  transcript: [{ userName: String, text: String, timestamp: Date }],
  summary: String
});
const Room = mongoose.model('Room', roomSchema);

const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access denied. No token provided.' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid or expired token.' });
  }
};

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { message: 'Too many attempts. Please try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false
});

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || name.trim().length < 2)
      return res.status(400).json({ message: 'Name must be at least 2 characters.' });
    if (!email || !/^\S+@\S+\.\S+$/.test(email))
      return res.status(400).json({ message: 'Please provide a valid email address.' });
    if (!password || password.length < 6)
      return res.status(400).json({ message: 'Password must be at least 6 characters.' });

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

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: 'Email and password are required.' });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    // --- AI Anomaly Detection ---
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const userAgent = req.headers['user-agent'] || 'Unknown';
    const currentTime = new Date();
    
    let isAnomalous = false;
    let riskScore = 0;

    // Only check for anomalies if there is past history to compare against
    if (user.loginHistory && user.loginHistory.length > 0) {
      const recentHistory = user.loginHistory.slice(-5).map(h => ({
        time: h.timestamp.toISOString(),
        ip: h.ip,
        agent: h.userAgent
      }));

      const prompt = `
        You are a cybersecurity AI monitoring login patterns.
        A user is attempting to log in. Here is their recent login history (last 5 successful logins):
        ${JSON.stringify(recentHistory, null, 2)}
        
        Here is the current login attempt:
        Time: ${currentTime.toISOString()}
        IP Address: ${ip}
        User Agent: ${userAgent}

        Based purely on comparing the current attempt against the historical pattern (time of day, IP consistency, device consistency), calculate an anomaly risk score between 0.0 and 1.0 (where 1.0 is highly anomalous/risky and 0.0 is completely normal). 
        Only return a valid JSON object with {"riskScore": number}. Do not return any other text or markdown formatting.
      `;

      try {
        const response = await ai.models.generateContent({
          model: 'gemini-2.5-flash',
          contents: prompt,
        });
        
        // Clean markdown from response if present
        let cleanedResponse = response.text.replace(/```json/g, '').replace(/```/g, '').trim();
        const result = JSON.parse(cleanedResponse);
        
        if (result.riskScore !== undefined) {
          riskScore = result.riskScore;
          isAnomalous = riskScore > 0.7; // Threshold for anomaly
          console.log(`[AI Anomaly Check] User: ${user.email} | Score: ${riskScore} | Anomalous: ${isAnomalous}`);
        }
      } catch (aiError) {
        console.error("AI Anomaly Detection Error:", aiError);
        // Fail open: don't block login if AI fails
      }
    }

    // Save current login to history
    user.loginHistory.push({
      ip,
      userAgent,
      timestamp: currentTime,
      isAnomalous,
      riskScore
    });
    
    // Keep history manageable (e.g., last 20 logins)
    if (user.loginHistory.length > 20) {
      user.loginHistory.shift(); 
    }
    
    await user.save();
    // ----------------------------

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ 
      token, 
      user: { id: user._id, name: user.name, email: user.email },
      securityAlert: isAnomalous ? {
        message: "We detected an unusual login pattern from your account (new IP or strange time). For your security, please verify this was you.",
        riskScore
      } : null
    });
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/rooms/create', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const roomId = Math.random().toString(36).substring(2, 10).toUpperCase();
    const room = new Room({ roomId, host: userId, participants: [userId] });
    await room.save();
    res.json({ roomId, room });
  } catch (error) {
    res.status(500).json({ message: 'Error creating room' });
  }
});

app.get('/api/rooms/:roomId', verifyToken, async (req, res) => {
  try {
    const room = await Room.findOne({ roomId: req.params.roomId });
    if (!room) return res.status(404).json({ message: 'Room not found' });
    res.json(room);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching room' });
  }
});

app.get('/api/rooms-history', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const pastRooms = await Room.find({
      $or: [{ host: userId }, { participants: userId }],
      status: 'ended'
    }).sort({ createdAt: -1 });
    res.json(pastRooms);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching history' });
  }
});

// Track which room each socket is in: socketId -> roomId
const socketRoomMap = {};
const rooms = {};
const waiting = {};

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('join-room', async ({ roomId, userId, userName }) => {
    try {
      const roomDoc = await Room.findOne({ roomId });
      if (!roomDoc) {
        socket.emit('error', { message: 'Room not found' });
        return;
      }

      if (!rooms[roomId]) {
        rooms[roomId] = { 
          users: [], 
          messages: [],
          transcripts: [],
          hostSocketId: null,
          hostUserId: roomDoc.host 
        };
        waiting[roomId] = [];
      }

      const isHost = userId === rooms[roomId].hostUserId;

      if (isHost) {
        rooms[roomId].hostSocketId = socket.id;
        socket.join(roomId);
        
        // Avoid duplicate users if user refreshed
        rooms[roomId].users = rooms[roomId].users.filter(u => u.userId !== userId);
        rooms[roomId].users.push({ socketId: socket.id, userId, userName });
        socketRoomMap[socket.id] = roomId;

        const existingUsers = rooms[roomId].users
          .filter(u => u.socketId !== socket.id)
          .map(u => ({ socketId: u.socketId, userId: u.userId, userName: u.userName }));

        socket.emit('join-approved');
        socket.emit('you-are-host');
        socket.emit('existing-users', existingUsers);
        socket.emit('chat-history', rooms[roomId].messages);
        
        console.log(`Host ${userName} joined room ${roomId}`);

        // If there are people waiting, notify host
        if (waiting[roomId] && waiting[roomId].length > 0) {
          waiting[roomId].forEach(user => {
            socket.emit('admission-request', { socketId: user.socketId, userName: user.userName, userId: user.userId });
          });
        }
      } else {
        // Put in waiting room
        if (!waiting[roomId]) waiting[roomId] = [];
        waiting[roomId] = waiting[roomId].filter(u => u.userId !== userId);
        waiting[roomId].push({ socketId: socket.id, userId, userName });
        
        socket.emit('waiting-for-approval');

        const hostSocketId = rooms[roomId].hostSocketId;
        if (hostSocketId) {
          io.to(hostSocketId).emit('admission-request', { socketId: socket.id, userName, userId });
        }
        console.log(`${userName} waiting to join ${roomId}`);
      }
    } catch (err) {
      console.error('Error in join-room:', err);
    }
  });

  socket.on('admit-user', ({ roomId, socketId }) => {
    if (!rooms[roomId] || rooms[roomId].hostSocketId !== socket.id) return; // SECURITY FIX
    const waitingList = waiting[roomId] || [];
    const user = waitingList.find(u => u.socketId === socketId);
    if (!user) return;

    waiting[roomId] = waitingList.filter(u => u.socketId !== socketId);

    const admittedSocket = io.sockets.sockets.get(socketId);
    if (!admittedSocket) return;

    admittedSocket.join(roomId);

    // ✅ FIX: Send existing users BEFORE adding new user to the list
    // This prevents the new user from trying to connect to themselves
    const existingUsers = rooms[roomId].users.map(u => ({
      socketId: u.socketId,
      userId: u.userId,
      userName: u.userName
    }));

    // NOW add the new user to the room
    rooms[roomId].users.push({ socketId, userId: user.userId, userName: user.userName });
    socketRoomMap[socketId] = roomId;

    Room.findOneAndUpdate(
      { roomId },
      { $addToSet: { participants: user.userId } }
    ).catch(err => console.error("Error adding participant:", err));

    admittedSocket.emit('join-approved');
    admittedSocket.emit('existing-users', existingUsers);
    admittedSocket.emit('chat-history', rooms[roomId].messages);

    console.log(`${user.userName} admitted to ${roomId}`);
  });

  socket.on('deny-user', ({ roomId, socketId }) => {
    if (!rooms[roomId] || rooms[roomId].hostSocketId !== socket.id) return; // SECURITY FIX
    waiting[roomId] = (waiting[roomId] || []).filter(u => u.socketId !== socketId);
    io.to(socketId).emit('join-denied');
  });

  // ✅ FIX: Use socketRoomMap and socket.id for security
  socket.on('sending-signal', ({ userToSignal, signal }) => {
    const roomId = socketRoomMap[socket.id];
    if (!roomId || !rooms[roomId]) return;

    const caller = rooms[roomId].users.find(u => u.socketId === socket.id);
    io.to(userToSignal).emit('user-connected', {
      signal,
      socketId: socket.id,
      userId: caller?.userId,
      userName: caller?.userName
    });
  });

  socket.on('returning-signal', ({ callerID, signal }) => {
    io.to(callerID).emit('receiving-returned-signal', {
      signal,
      id: socket.id
    });
  });

  socket.on('send-message', ({ roomId, message, userName }) => {
    const msg = { userName, message, timestamp: new Date().toISOString() };
    if (rooms[roomId]) rooms[roomId].messages.push(msg);
    socket.to(roomId).emit('new-message', msg);
  });

  socket.on('send-transcript', ({ roomId, userName, text }) => {
    const entry = { userName, text, timestamp: new Date() };
    if (rooms[roomId]) {
      rooms[roomId].transcripts.push(entry);
      socket.to(roomId).emit('new-transcript', entry);
    }
  });

  socket.on('end-meeting', async ({ roomId }) => {
    if (!rooms[roomId] || rooms[roomId].hostSocketId !== socket.id) return;

    const roomData = rooms[roomId];
    const transcripts = roomData.transcripts || [];
    
    let summary = "No transcription available for this meeting.";
    
    if (transcripts.length > 0) {
      const fullTranscriptText = transcripts
        .map(t => `[${t.timestamp.toISOString()}] ${t.userName}: ${t.text}`)
        .join('\n');
        
      try {
        const prompt = `Please summarize the following meeting transcript. Provide a concise overview of the main topics discussed, key decisions made, and any action items.\n\nTranscript:\n${fullTranscriptText}`;
        const response = await ai.models.generateContent({
          model: 'gemini-2.5-flash',
          contents: prompt,
        });
        summary = response.text || "Failed to generate summary.";
      } catch (error) {
        console.error("Gemini API Error:", error);
        summary = "An error occurred while generating the summary.";
      }
    }

    try {
      await Room.findOneAndUpdate(
        { roomId },
        { 
          status: 'ended',
          transcript: transcripts,
          summary: summary
        }
      );
    } catch (dbError) {
      console.error("Database update error:", dbError);
    }

    // Notify everyone the meeting ended
    io.to(roomId).emit('meeting-ended', { summary });

    // Clean up room in memory
    delete rooms[roomId];
    delete waiting[roomId];
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);

    // Remove from waiting lists
    Object.keys(waiting).forEach(roomId => {
      if (waiting[roomId]) {
        waiting[roomId] = waiting[roomId].filter(u => u.socketId !== socket.id);
      }
    });

    // Remove from room
    const roomId = socketRoomMap[socket.id];
    delete socketRoomMap[socket.id];

    if (roomId && rooms[roomId]) {
      const userIndex = rooms[roomId].users.findIndex(u => u.socketId === socket.id);
      if (userIndex !== -1) {
        const user = rooms[roomId].users[userIndex];
        rooms[roomId].users.splice(userIndex, 1);

        socket.to(roomId).emit('user-disconnected', {
          socketId: socket.id,
          userName: user.userName
        });

        // Handle host disconnect (we keep the room, wait for them to return)
        if (rooms[roomId].hostSocketId === socket.id) {
          rooms[roomId].hostSocketId = null;
        }

        // Clean up empty room from memory
        if (rooms[roomId].users.length === 0) {
          delete rooms[roomId];
          delete waiting[roomId];
          // Rooms are kept in DB so hosts can rejoin.
        }
      }
    }
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});