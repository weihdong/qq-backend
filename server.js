// server.js
const express = require('express');
const WebSocket = require('ws');
const http = require('http');
const cors = require('cors');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// CORS配置
app.use(cors({
  origin: 'http://localhost:5173',
  credentials: true
}));

app.use(express.json());

// 用户存储
const users = new Map();

// 登录/注册接口
app.post('/api/auth', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: '需要用户名和密码' });
  }

  if (!users.has(username)) {
    users.set(username, {
      password,
      friends: new Set(),
      ws: null
    });
  }

  const user = users.get(username);
  if (user.password !== password) {
    return res.status(401).json({ error: '密码错误' });
  }

  res.json({ success: true });
});

// WebSocket处理
wss.on('connection', (ws) => {
  let currentUser = null;

  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data);
      
      switch (msg.type) {
        case 'login':
          if (users.has(msg.username)) {
            currentUser = msg.username;
            users.get(currentUser).ws = ws;
            sendFriendList();
          }
          break;

        case 'add_friend':
          if (users.has(msg.friend)) {
            users.get(currentUser).friends.add(msg.friend);
            sendFriendList();
          }
          break;

        case 'message':
          const target = users.get(msg.to);
          if (target?.ws) {
            target.ws.send(JSON.stringify({
              type: 'message',
              from: currentUser,
              text: msg.text
            }));
          }
          break;
      }
    } catch (err) {
      console.error('消息处理错误:', err);
    }
  });

  function sendFriendList() {
    ws.send(JSON.stringify({
      type: 'friends',
      list: Array.from(users.get(currentUser).friends)
    }));
  }

  ws.on('close', () => {
    if (currentUser) {
      users.get(currentUser).ws = null;
    }
  });
});

server.listen(3000, () => {
  console.log('服务运行在 http://localhost:3000');
});
