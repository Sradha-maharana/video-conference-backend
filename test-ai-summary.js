const axios = require('axios');
const io = require('socket.io-client');

async function runTest() {
  try {
    const ts = Date.now();

    // 1. Register a fresh user
    const regRes = await axios.post('http://127.0.0.1:5000/api/auth/register', {
      name: `TestUser${ts}`,
      email: `test${ts}@example.com`,
      password: 'password123'
    });

    const token = regRes.data.token;
    const user = regRes.data.user;
    console.log('✅ Registered:', user.email);

    // 2. Create a room (requires auth)
    const roomRes = await axios.post('http://127.0.0.1:5000/api/rooms/create', {}, {
      headers: { Authorization: `Bearer ${token}` }
    });
    const roomId = roomRes.data.roomId;
    console.log('✅ Room created:', roomId);

    // 3. Connect socket — MUST pass token in auth, server now requires it
    const socket = io('http://127.0.0.1:5000', {
      auth: { token }
    });

    // If the server rejects auth, this fires immediately
    socket.on('connect_error', (err) => {
      console.error('❌ Socket auth failed:', err.message);
      process.exit(1);
    });

    socket.on('connect', () => {
      console.log('✅ Socket connected:', socket.id);
      socket.emit('join-room', { roomId, userId: user.id, userName: user.name });
    });

    socket.on('join-approved', () => {
      console.log('✅ Joined as host. Sending transcripts...');

      socket.emit('send-transcript', {
        roomId, userName: user.name,
        text: 'Hello everyone, we are testing the AI summary feature today.'
      });

      setTimeout(() => {
        socket.emit('send-transcript', {
          roomId, userName: user.name,
          text: 'The action item is to integrate the summary into the dashboard by Friday.'
        });

        setTimeout(() => {
          socket.emit('send-transcript', {
            roomId, userName: user.name,
            text: 'We decided to use Gemini for both anomaly detection and meeting summarisation.'
          });

          setTimeout(() => {
            console.log('⏳ Ending meeting...');
            socket.emit('end-meeting', { roomId });
          }, 500);
        }, 500);
      }, 500);
    });

    socket.on('meeting-ended', ({ summary }) => {
      console.log('\n✅ Meeting ended. AI Summary:\n');
      console.log(summary);
      socket.disconnect();
      process.exit(0);
    });

    socket.on('error', (err) => {
      console.error('❌ Socket error:', err);
      process.exit(1);
    });

    // Safety timeout
    setTimeout(() => {
      console.error('❌ Test timed out after 30s');
      process.exit(1);
    }, 30000);

  } catch (err) {
    console.error('❌ Test failed:', err?.response?.data || err.message);
    process.exit(1);
  }
}

runTest();