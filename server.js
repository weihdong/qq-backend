process.on('warning', (warning) => {
  console.warn('⚠️ Node.js警告:', warning.stack);
});

console.log('🛠️ 环境变量:', {
  NODE_ENV: process.env.NODE_ENV,
  PORT: process.env.PORT,
  MONGODB_URI: process.env.MONGODB_URI ? '已配置' : '未配置'
});

const express = require('express');
const mongoose = require('mongoose');
const WebSocket = require('ws');
const cors = require('cors');
const bcrypt = require('bcrypt');

const HTTP_STATUS = {
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  NOT_FOUND: 404,
  INTERNAL_ERROR: 500,
  CREATED: 201,
  OK: 200
};

const app = express();

const allowedOrigins = [
  'https://qq.085410.xyz',
  'https://qq-rust.vercel.app',
  'http://localhost:5173'
];

const corsOptions = {
  origin: allowedOrigins,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
  credentials: true,
  optionsSuccessStatus: 204
};

app.use(cors(corsOptions));
app.options('*', cors());
app.use(express.json({ limit: '10kb' }));

app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} | Origin: ${req.headers.origin}`);
  next();
});

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://dwh:1122@cluster0.arkqevd.mongodb.net/Cluster0?retryWrites=true&w=majority&appName=Cluster0';

mongoose.connect(MONGODB_URI, {
  serverSelectionTimeoutMS: 15000,
  retryWrites: true,
  ssl: true,
  appName: 'Railway_Deploy'
})
.then(() => console.log('✅ MongoDB连接成功'))
.catch(err => {
  console.error('❌ MongoDB连接失败:', err);
  process.exit(1);
});

// 用户模型
const userSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true,
    unique: true,
    minlength: 3,
    maxlength: 20,
    match: /^[a-zA-Z0-9_]+$/
  },
  password: {
    type: String,
    required: true,
    select: false
  },
  lastLogin: Date
}, { versionKey: false });

const User = mongoose.model('User', userSchema);

// 好友模型
const friendSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  friends: [{
    user: { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: 'User',
      required: true 
    },
    addedAt: {
      type: Date,
      default: Date.now
    }
  }]
}, { timestamps: true });

const Friend = mongoose.model('Friend', friendSchema);

// 消息模型
const messageSchema = new mongoose.Schema({
  from: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  to: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  content: {
    type: String,
    required: true,
    maxlength: 1000
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
});

const Message = mongoose.model('Message', messageSchema);

// 登录路由
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({ error: "用户名和密码不能为空" });
    }

    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({ error: "用户名格式无效" });
    }

    const user = await User.findOne({ username }).select('+password');
    
    if (user) {
      const valid = await bcrypt.compare(password, user.password);
      if (!valid) {
        console.warn(`[登录失败] 密码错误: ${username}`);
        return res.status(HTTP_STATUS.UNAUTHORIZED).json({ error: "认证失败" });
      }
      
      await User.updateOne({ _id: user._id }, { lastLogin: new Date() });
      return res.json({ userId: user._id, username: user.username });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = await User.create({
      username,
      password: hashedPassword,
      lastLogin: new Date()
    });

    await Friend.create({ userId: newUser._id, friends: [] });
    console.log(`[新用户注册] ${username} ID:${newUser._id}`);

    res.status(HTTP_STATUS.CREATED).json({
      userId: newUser._id,
      username: newUser.username
    });

  } catch (error) {
    console.error('[登录错误]', error.stack);
    if (error.name === 'MongoServerError' && error.code === 11000) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({ error: "用户名已被占用" });
    }
    res.status(HTTP_STATUS.INTERNAL_ERROR).json({ error: "服务器错误" });
  }
});

// 获取好友列表
app.get('/api/friends', async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) return res.status(HTTP_STATUS.BAD_REQUEST).json({ error: "需要用户ID" });

    const friendList = await Friend.findOne({ userId })
      .populate('friends.user', 'username')
      .lean();

    if (!friendList) return res.json({ friends: [] });

    const friends = friendList.friends.map(f => ({
      _id: f.user._id,
      username: f.user.username,
      addedAt: f.addedAt
    }));

    res.json({ friends });
  } catch (error) {
    console.error('获取好友列表错误:', error);
    res.status(HTTP_STATUS.INTERNAL_ERROR).json({ error: "获取失败" });
  }
});

// 获取消息记录
app.get('/api/messages', async (req, res) => {
  try {
    const { from, to } = req.query;
    if (!from || !to) return res.status(HTTP_STATUS.BAD_REQUEST).json({ error: "缺少参数" });

    const messages = await Message.find({
      $or: [
        { from, to },
        { from: to, to: from }
      ]
    }).sort({ timestamp: 1 }).lean();

    res.json(messages);
  } catch (error) {
    console.error('获取消息错误:', error);
    res.status(HTTP_STATUS.INTERNAL_ERROR).json({ error: "获取消息失败" });
  }
});

// WebSocket处理
const server = app.listen(process.env.PORT || 3000, '0.0.0.0', () => {
  console.log(`🚀 服务器运行中，端口：${server.address().port}`);
});

const wss = new WebSocket.Server({ server });
const onlineUsers = new Map();

wss.on('connection', (ws, req) => {
  let userId = null;

  ws.on('message', async (message) => {
    try {
      const msgData = JSON.parse(message);
      
      // 处理消息
      if (msgData.type === 'message') {
        const newMessage = new Message({
          from: msgData.from,
          to: msgData.to,
          content: msgData.content
        });
        await newMessage.save();

        // 广播消息
        wss.clients.forEach(client => {
          if (client.readyState === WebSocket.OPEN && 
            (client.userId === msgData.to || client.userId === msgData.from)) {
            client.send(JSON.stringify({
              type: 'message',
              ...newMessage.toJSON()
            }));
          }
        });
      }
      
      // 处理用户连接
      if (msgData.type === 'connect') {
        userId = msgData.userId;
        onlineUsers.set(userId, ws);
        ws.userId = userId;
        
        // 通知好友在线状态
        const friendList = await Friend.findOne({ userId });
        if (friendList) {
          friendList.friends.forEach(friend => {
            const friendWs = onlineUsers.get(friend.user.toString());
            if (friendWs) {
              friendWs.send(JSON.stringify({
                type: 'status',
                userId,
                online: true
              }));
            }
          });
        }
      }
    } catch (error) {
      console.error('WebSocket消息处理错误:', error);
    }
  });

  ws.on('close', () => {
    if (userId) {
      onlineUsers.delete(userId);
      // 通知好友离线状态
      Friend.findOne({ userId }).then(friendList => {
        if (friendList) {
          friendList.friends.forEach(friend => {
            const friendWs = onlineUsers.get(friend.user.toString());
            if (friendWs) {
              friendWs.send(JSON.stringify({
                type: 'status',
                userId,
                online: false
              }));
            }
          });
        }
      });
    }
  });
});

// 其他中间件和路由...

// 优雅关闭
const gracefulShutdown = () => {
  console.log('🛑 收到终止信号，开始清理...');
  server.close(async () => {
    await mongoose.disconnect();
    console.log('✅ 资源清理完成');
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 5000);
};
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

// 全局错误处理
app.use((err, req, res, next) => {
  console.error('⚠️ 全局错误:', err);
  res.status(500).json({ error: "服务器内部错误" });
});