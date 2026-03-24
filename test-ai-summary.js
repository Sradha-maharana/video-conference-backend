const axios = require('axios');
const io = require('socket.io-client');

async function runTest() {
  try {
    const ts = Date.now();
    // 1. Register a user
    const regRes = await axios.post('http://localhost:5000/api/auth/register', {
      name: `TestUser${ts}`,
      email: `test${ts}@example.com`,
      password: 'password123'
    });
    
    const token = regRes.data.token;
    const user = regRes.data.user;
    console.log("Logged in:", user.email);

    // 2. Create room
    const roomRes = await axios.post('http://localhost:5000/api/rooms/create', {}, {
      headers: { Authorization: `Bearer ${token}` }
    });
    const roomId = roomRes.data.roomId;
    console.log("Room created:", roomId);

    // 3. Connect Socket
    const socket = io('http://localhost:5000');
    
    socket.on('connect', () => {
      console.log("Socket connected:", socket.id);
      socket.emit('join-room', { roomId, userId: user.id, userName: user.name });
    });

    socket.on('join-approved', () => {
      console.log("Join approved.");
      
      socket.emit('send-transcript', {
        roomId,
        userName: user.name,
        text: "Hello everyone, we are testing the AI summary feature."
      });

      setTimeout(() => {
        socket.emit('send-transcript', {
          roomId,
          userName: user.name,
          text: "Let's see if the voice is recorded properly on the server."
        });

        setTimeout(() => {
          console.log("Ending meeting...");
          socket.emit('end-meeting', { roomId });
        }, 1000);
      }, 1000);
    });

    socket.on('meeting-ended', ({ summary }) => {
      console.log("✅ Meeting ended. Summary received:");
      console.log(summary);
      process.exit(0);
    });

    socket.on('error', (err) => {
      console.error("Socket error:", err);
      process.exit(1);
    });

  } catch (err) {
    console.error("Test failed:", err?.response?.data || err);
    process.exit(1);
  }
}

runTest();
