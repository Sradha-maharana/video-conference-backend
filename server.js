require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const http = require('http');
const socketio = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { GoogleGenAI } = require('@google/genai');
const rateLimit = require('express-rate-limit');

// ── Validate required env vars on startup ─────────────────────────────────
const REQUIRED_ENV = ['MONGODB_URI', 'JWT_SECRET', 'GEMINI_API_KEY'];
REQUIRED_ENV.forEach(key => {
  if (!process.env[key]) {
    console.error(`❌ Missing required env var: ${key}`);
    process.exit(1);
  }
});

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

const app = express();
const server = http.createServer(app);

const ALLOWED_ORIGINS = [
  'http://localhost:3000',
  'https://video-conference-frontend.vercel.app',
];

const io = socketio(server, {
  cors: { origin: ALLOWED_ORIGINS, methods: ['GET', 'POST'] }
});

app.use(cors({ origin: ALLOWED_ORIGINS }));
app.use(express.json({ limit: '2mb' }));

app.get('/health', (req, res) => res.json({ status: 'ok' }));

// ── MongoDB ────────────────────────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => { console.error('❌ MongoDB Error:', err); process.exit(1); });

// ── Schemas ────────────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
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
  roomId: { type: String, required: true, index: true },
  host: String,
  participants: [String],
  createdAt: { type: Date, default: Date.now },
  status: { type: String, default: 'active' },
  transcript: [{ userName: String, text: String, timestamp: Date }],
  summary: String
});
const Room = mongoose.model('Room', roomSchema);

// ── HTTP auth middleware ───────────────────────────────────────────────────
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access denied. No token provided.' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: 'Invalid or expired token.' });
  }
};

// ── Socket auth middleware ─────────────────────────────────────────────────
// SECURITY FIX: every socket connection must carry a valid JWT
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error('Authentication required'));
  try {
    socket.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    next(new Error('Invalid or expired token'));
  }
});

// ── Rate limiter ───────────────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { message: 'Too many attempts. Please try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false
});

// ── Auth routes ────────────────────────────────────────────────────────────
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || name.trim().length < 2)
      return res.status(400).json({ message: 'Name must be at least 2 characters.' });
    if (!email || !/^\S+@\S+\.\S+$/.test(email))
      return res.status(400).json({ message: 'Please provide a valid email address.' });
    if (!password || password.length < 6)
      return res.status(400).json({ message: 'Password must be at least 6 characters.' });

    if (await User.findOne({ email: email.toLowerCase() }))
      return res.status(400).json({ message: 'An account with this email already exists.' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name: name.trim(), email: email.toLowerCase(), password: hashedPassword });
    await user.save();

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: 'Email and password are required.' });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(400).json({ message: 'Invalid credentials' });

    // ── AI Anomaly Detection ─────────────────────────────────────────────
    // FIX: take only the first IP from x-forwarded-for to prevent spoofing
    const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
    const userAgent = req.headers['user-agent'] || 'Unknown';
    const currentTime = new Date();
    let isAnomalous = false;
    let riskScore = 0;

    if (user.loginHistory.length > 0) {
      const recentHistory = user.loginHistory.slice(-5).map(h => ({
        time: h.timestamp.toISOString(),
        ip: h.ip,
        agent: h.userAgent
      }));

      const prompt = `You are a cybersecurity AI monitoring login patterns.
Recent login history (last 5):
${JSON.stringify(recentHistory, null, 2)}

Current attempt:
Time: ${currentTime.toISOString()}
IP: ${ip}
User-Agent: ${userAgent}

Calculate an anomaly risk score 0.0-1.0 (1.0 = highly anomalous).
Return ONLY valid JSON: {"riskScore": number}`;

      try {
        const response = await ai.models.generateContent({
          model: 'gemini-2.5-flash',
          contents: prompt,
        });
        const cleaned = response.text.replace(/```json|```/g, '').trim();
        const result = JSON.parse(cleaned);
        if (typeof result.riskScore === 'number') {
          // FIX: clamp to [0,1] so a bad AI response can't set an out-of-range value
          riskScore = Math.min(1, Math.max(0, result.riskScore));
          isAnomalous = riskScore > 0.7;
          console.log(`[AI Anomaly] ${user.email} | score=${riskScore} | anomalous=${isAnomalous}`);
        }
      } catch (aiError) {
        console.error('AI Anomaly Detection Error:', aiError.message);
        // Fail open — don't block login if AI fails
      }
    }

    user.loginHistory.push({ ip, userAgent, timestamp: currentTime, isAnomalous, riskScore });
    if (user.loginHistory.length > 20) user.loginHistory.shift();
    await user.save();
    // ────────────────────────────────────────────────────────────────────

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({
      token,
      user: { id: user._id, name: user.name, email: user.email },
      securityAlert: isAnomalous ? {
        message: 'We detected an unusual login pattern from your account (new IP or unusual time). Please verify this was you.',
        riskScore
      } : null
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ── Room routes ────────────────────────────────────────────────────────────
app.post('/api/rooms/create', verifyToken, async (req, res) => {
  try {
    const roomId = Math.random().toString(36).substring(2, 10).toUpperCase();
    const room = new Room({ roomId, host: req.user.userId, participants: [req.user.userId] });
    await room.save();
    res.json({ roomId, room });
  } catch (error) {
    console.error('Create room error:', error);
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
    }).sort({ createdAt: -1 }).limit(20); // FIX: cap results to avoid large unbounded reads
    res.json(pastRooms);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching history' });
  }
});

// ── In-memory room state ───────────────────────────────────────────────────
const socketRoomMap = {}; // socketId -> roomId
const rooms = {};         // roomId -> { users, messages, transcripts, hostSocketId, hostUserId }
const waiting = {};       // roomId -> [{ socketId, userId, userName }]

// ── Socket events ──────────────────────────────────────────────────────────
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('join-room', async ({ roomId, userId, userName }) => {
    // SECURITY FIX: ignore userId from client — use the verified JWT identity instead
    const verifiedUserId = socket.user.userId;

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
          hostUserId: roomDoc.host.toString()
        };
        waiting[roomId] = [];
      }

      const isHost = verifiedUserId === rooms[roomId].hostUserId;

      if (isHost) {
        rooms[roomId].hostSocketId = socket.id;
        socket.join(roomId);

        // Deduplicate on reconnect/refresh
        rooms[roomId].users = rooms[roomId].users.filter(u => u.userId !== verifiedUserId);
        rooms[roomId].users.push({ socketId: socket.id, userId: verifiedUserId, userName });
        socketRoomMap[socket.id] = roomId;

        const existingUsers = rooms[roomId].users
          .filter(u => u.socketId !== socket.id)
          .map(({ socketId, userId, userName }) => ({ socketId, userId, userName }));

        socket.emit('join-approved');
        socket.emit('you-are-host');
        socket.emit('existing-users', existingUsers);
        socket.emit('chat-history', rooms[roomId].messages);

        // Flush any pending admission requests to the (re)joined host
        (waiting[roomId] || []).forEach(u => {
          socket.emit('admission-request', { socketId: u.socketId, userName: u.userName, userId: u.userId });
        });

        console.log(`Host ${userName} joined room ${roomId}`);
      } else {
        // Non-host goes to waiting room
        waiting[roomId] = (waiting[roomId] || []).filter(u => u.userId !== verifiedUserId);
        waiting[roomId].push({ socketId: socket.id, userId: verifiedUserId, userName });
        socket.emit('waiting-for-approval');

        const hostSocketId = rooms[roomId].hostSocketId;
        if (hostSocketId) {
          io.to(hostSocketId).emit('admission-request', { socketId: socket.id, userName, userId: verifiedUserId });
        }
        console.log(`${userName} waiting to join ${roomId}`);
      }
    } catch (err) {
      console.error('Error in join-room:', err);
      socket.emit('error', { message: 'Failed to join room' });
    }
  });

  socket.on('admit-user', ({ roomId, socketId }) => {
    // SECURITY: only the verified host socket can admit users
    if (!rooms[roomId] || rooms[roomId].hostSocketId !== socket.id) return;

    const user = (waiting[roomId] || []).find(u => u.socketId === socketId);
    if (!user) return;
    waiting[roomId] = waiting[roomId].filter(u => u.socketId !== socketId);

    const admittedSocket = io.sockets.sockets.get(socketId);
    if (!admittedSocket) return;

    // Send existing users BEFORE adding new user — prevents self-connect bug
    const existingUsers = rooms[roomId].users.map(({ socketId, userId, userName }) => ({ socketId, userId, userName }));

    rooms[roomId].users.push({ socketId, userId: user.userId, userName: user.userName });
    socketRoomMap[socketId] = roomId;
    admittedSocket.join(roomId);

    Room.findOneAndUpdate({ roomId }, { $addToSet: { participants: user.userId } })
      .catch(err => console.error('Error adding participant:', err));

    admittedSocket.emit('join-approved');
    admittedSocket.emit('existing-users', existingUsers);
    admittedSocket.emit('chat-history', rooms[roomId].messages);

    console.log(`${user.userName} admitted to ${roomId}`);
  });

  socket.on('deny-user', ({ roomId, socketId }) => {
    if (!rooms[roomId] || rooms[roomId].hostSocketId !== socket.id) return;
    waiting[roomId] = (waiting[roomId] || []).filter(u => u.socketId !== socketId);
    io.to(socketId).emit('join-denied');
  });

  socket.on('sending-signal', ({ userToSignal, signal }) => {
    const roomId = socketRoomMap[socket.id];
    if (!roomId || !rooms[roomId]) return;
    const caller = rooms[roomId].users.find(u => u.socketId === socket.id);
    io.to(userToSignal).emit('user-connected', {
      signal, socketId: socket.id,
      userId: caller?.userId, userName: caller?.userName
    });
  });

  socket.on('returning-signal', ({ callerID, signal }) => {
    io.to(callerID).emit('receiving-returned-signal', { signal, id: socket.id });
  });

  socket.on('send-message', ({ roomId, message, userName }) => {
    // SECURITY: sender must actually be in this room
    if (socketRoomMap[socket.id] !== roomId) return;
    // Sanitise: strip HTML tags to prevent stored XSS in chat
    const safeMessage = String(message).replace(/</g, '&lt;').replace(/>/g, '&gt;').substring(0, 2000);
    const msg = { userName, message: safeMessage, timestamp: new Date().toISOString() };
    if (rooms[roomId]) rooms[roomId].messages.push(msg);
    socket.to(roomId).emit('new-message', msg);
  });

  socket.on('send-transcript', ({ roomId, userName, text }) => {
    // Allow if in room OR still in waiting list (race condition window between
    // join-approved firing on client and socketRoomMap being populated on server)
    const inRoom = socketRoomMap[socket.id] === roomId;
    const inWaiting = (waiting[roomId] || []).some(u => u.socketId === socket.id);
    if (!inRoom && !inWaiting) return;
    if (!rooms[roomId]) return;
    const entry = { userName, text: String(text).substring(0, 5000), timestamp: new Date() };
    rooms[roomId].transcripts.push(entry);
    io.to(roomId).emit('new-transcript', entry);
    console.log('[Transcript]', userName + ':', entry.text.substring(0, 80));
  });

  socket.on('send-audio-chunk', async ({ roomId, userName, audioData, mimeType }) => {
    console.log(`[AudioChunk] Received from ${userName} for room ${roomId}, size: ${audioData?.length}`);
    const inRoom2 = socketRoomMap[socket.id] === roomId;
    const inWaiting2 = (waiting[roomId] || []).some(u => u.socketId === socket.id);
    if (!rooms[roomId] || (!inRoom2 && !inWaiting2)) {
      console.log(`[AudioChunk] Rejected: user not in room`);
      return;
    }

    // Guard: only accept known safe MIME types
    const allowedMimes = ['audio/webm', 'audio/mp4', 'audio/ogg', 'audio/wav'];
    const safeMime = allowedMimes.includes(mimeType) ? mimeType : 'audio/webm';

    try {
      const response = await ai.models.generateContent({
        model: 'gemini-1.5-flash',
        contents: [
          {
            text: 'Accurately transcribe the following audio. Output ONLY the transcript text, no labels or formatting. If there is no human speech, output nothing.'
          },
          { inlineData: { mimeType: safeMime, data: audioData } }
        ]
      });
      const transcriptText = response.text?.trim();
      if (transcriptText) {
        const entry = { userName, text: transcriptText, timestamp: new Date() };
        rooms[roomId].transcripts.push(entry);
        io.to(roomId).emit('new-transcript', entry);
      }
    } catch (err) {
      console.error('Audio chunk transcription error:', err.message);
    }
  });

  async function generateAndSaveSummary(roomId) {
    if (!rooms[roomId]) return;
    const { transcripts = [] } = rooms[roomId];
    console.log(`[end-meeting] Room ${roomId} has ${transcripts.length} transcript entries`);
    let summary = 'No transcription was available for this meeting.';

    if (transcripts.length > 0) {
      const fullTranscriptText = transcripts
        .map(t => `[${new Date(t.timestamp).toISOString()}] ${t.userName}: ${t.text}`)
        .join('\n');

      const prompt = `You are a meeting assistant. Summarize the following meeting transcript clearly and concisely.

Structure your response with these sections (only include sections that are relevant):
## Overview
A 2-3 sentence summary of what the meeting was about.

## Key Topics Discussed
Bullet points of main subjects covered.

## Decisions Made
Any decisions or conclusions reached (if any).

## Action Items
Tasks or follow-ups mentioned, with owners if named (if any).

## Open Questions
Anything left unresolved (if any).

Transcript:
${fullTranscriptText}`;

      try {
        const response = await ai.models.generateContent({
          model: 'gemini-2.5-flash',
          contents: prompt,
        });
        summary = response.text?.trim() || 'Failed to generate summary.';
      } catch (error) {
        console.error('Gemini summary error:', error.message);
        summary = 'An error occurred while generating the meeting summary.';
      }
    }

    try {
      await Room.findOneAndUpdate(
        { roomId },
        { status: 'ended', transcript: transcripts, summary }
      );
    } catch (dbError) {
      console.error('DB update error on end-meeting:', dbError.message);
    }

    io.to(roomId).emit('meeting-ended', { summary });

    // Clean up in-memory state
    delete rooms[roomId];
    delete waiting[roomId];
    // FIX: also clean up all socketRoomMap entries for this room
    Object.keys(socketRoomMap).forEach(sid => {
      if (socketRoomMap[sid] === roomId) delete socketRoomMap[sid];
    });
  }

  socket.on('end-meeting', async ({ roomId }) => {
    // SECURITY: only the host can end the meeting
    if (!rooms[roomId] || rooms[roomId].hostSocketId !== socket.id) return;
    await generateAndSaveSummary(roomId);
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);

    // Remove from all waiting lists
    Object.keys(waiting).forEach(roomId => {
      waiting[roomId] = (waiting[roomId] || []).filter(u => u.socketId !== socket.id);
    });

    const roomId = socketRoomMap[socket.id];
    delete socketRoomMap[socket.id];

    if (roomId && rooms[roomId]) {
      const idx = rooms[roomId].users.findIndex(u => u.socketId === socket.id);
      if (idx !== -1) {
        const user = rooms[roomId].users[idx];
        rooms[roomId].users.splice(idx, 1);
        socket.to(roomId).emit('user-disconnected', { socketId: socket.id, userName: user.userName });

        if (rooms[roomId].hostSocketId === socket.id) {
          rooms[roomId].hostSocketId = null;
        }

        if (rooms[roomId].users.length === 0) {
          generateAndSaveSummary(roomId).catch(err => console.error("Auto end error:", err));
        }
      }
    }
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));