// server.js 完整版
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
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

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
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.log(`🚨 阻止跨域请求来源: ${origin}`);
      callback(new Error('禁止的跨域请求'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 204
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
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

const userSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: [true, '用户名不能为空'], 
    unique: true,
    minlength: [3, '用户名至少需要3个字符'],
    maxlength: [20, '用户名不能超过20个字符'],
    trim: true,
    validate: {
      validator: function(v) {
        return /^[a-zA-Z0-9_]+$/.test(v);
      },
      message: '只能包含字母、数字和下划线'
    }
  },
  password: {
    type: String,
    required: [true, '密码不能为空'],
    select: false,
    minlength: [6, '密码至少需要6个字符']
  },
  createdAt: {
    type: Date,
    default: Date.now,
    index: { expires: '730d' }
  },
  lastLogin: Date,
  friends: [{ 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User' 
  }]
}, {
  versionKey: false,
  toJSON: { 
    virtuals: true,
    transform: function(doc, ret) {
      delete ret.password;
      return ret;
    }
  }
});

const User = mongoose.model('User', userSchema);

const friendSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true 
  },
  friends: [{
    user: { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: 'User',
      required: true 
    },
    nickname: String,
    addedAt: {
      type: Date,
      default: Date.now
    }
  }]
}, {
  timestamps: true
});

const Friend = mongoose.model('Friend', friendSchema);

const messageSchema = new mongoose.Schema({
  from: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true 
  },
  to: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true 
  },
  content: {
    type: String,
    required: true,
    maxlength: [1000, '消息内容不能超过1000字符'],
    trim: true
  },
  read: {
    type: Boolean,
    default: false
  },
  timestamp: { 
    type: Date, 
    default: Date.now,
    index: true 
  }
}, {
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

messageSchema.virtual('formattedTime').get(function() {
  return this.timestamp.toISOString();
});

const Message = mongoose.model('Message', messageSchema);

const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    jwt.verify(token, process.env.JWT_SECRET || 'defaultSecret', (err, user) => {
      if (err) return res.status(HTTP_STATUS.UNAUTHORIZED).json({ error: "无效令牌" });
      req.user = user;
      next();
    });
  } else {
    res.status(HTTP_STATUS.UNAUTHORIZED).json({ error: "缺少认证令牌" });
  }
};

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({ error: "用户名和密码不能为空" });
    }

    const user = await User.findOne({ username }).select('+password');
    if (user) {
      const valid = await bcrypt.compare(password, user.password);
      if (!valid) {
        console.warn(`[登录失败] 密码错误: ${username}`);
        return res.status(HTTP_STATUS.UNAUTHORIZED).json({ error: "认证失败" });
      }
      
      const token = jwt.sign(
        { userId: user._id },
        process.env.JWT_SECRET || 'defaultSecret',
        { expiresIn: '7d' }
      );
      
      return res.json({
        userId: user._id,
        username: user.username,
        token
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = await User.create({
      username,
      password: hashedPassword,
      lastLogin: new Date()
    });

    await Friend.create({ userId: newUser._id, friends: [] });
    console.log(`[新用户注册] ${username} ID:${newUser._id}`);

    const token = jwt.sign(
      { userId: newUser._id },
      process.env.JWT_SECRET || 'defaultSecret',
      { expiresIn: '7d' }
    );

    res.status(HTTP_STATUS.CREATED).json({
      userId: newUser._id,
      username: newUser.username,
      token
    });

  } catch (error) {
    console.error('登录错误:', error);
    res.status(HTTP_STATUS.INTERNAL_ERROR).json({ error: "服务器错误" });
  }
});

app.post('/api/friends', authenticateJWT, async (req, res) => {
  try {
    const { friendUsername } = req.body;
    const userId = req.user.userId;

    if (!friendUsername) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({ error: "需要提供好友用户名" });
    }

    const friend = await User.findOne({ username: friendUsername });
    if (!friend) {
      return res.status(HTTP_STATUS.NOT_FOUND).json({ error: "用户不存在" });
    }

    if (userId === friend._id.toString()) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({ error: "不能添加自己为好友" });
    }

    const existingFriend = await Friend.findOne({
      userId,
      'friends.user': friend._id
    });

    if (existingFriend) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({ error: "已是好友关系" });
    }

    await Friend.updateOne(
      { userId },
      { $push: { friends: { user: friend._id } } },
      { upsert: true }
    );

    await Friend.updateOne(
      { userId: friend._id },
      { $push: { friends: { user: userId } } },
      { upsert: true }
    );

    res.status(HTTP_STATUS.CREATED).json({
      message: "添加好友成功",
      friendId: friend._id,
      username: friend.username
    });

  } catch (error) {
    console.error('添加好友错误:', error);
    res.status(HTTP_STATUS.INTERNAL_ERROR).json({ error: "添加好友失败" });
  }
});

app.get('/api/friends', authenticateJWT, async (req, res) => {
  try {
    const userId = req.user.userId;
    const friendList = await Friend.findOne({ userId })
      .populate('friends.user', 'username')
      .lean();

    if (!friendList) {
      return res.status(HTTP_STATUS.NOT_FOUND).json({ error: "好友列表未找到" });
    }

    const friends = friendList.friends.map(f => ({
      id: f.user._id,
      username: f.user.username,
      addedAt: f.addedAt
    }));

    res.json({ friends });
  } catch (error) {
    console.error('获取好友列表错误:', error);
    res.status(HTTP_STATUS.INTERNAL_ERROR).json({ error: "获取好友列表失败" });
  }
});

app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

const server = app.listen(process.env.PORT || 3000, '0.0.0.0', () => {
  console.log(`🚀 服务器运行中，端口：${server.address().port}`);
});

const wss = new WebSocket.Server({ server });

wss.on('connection', (ws, req) => {
  ws.on('message', (message) => {
    wss.clients.forEach(client => {
      if (client !== ws && client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    });
  });
});

const gracefulShutdown = () => {
  console.log('🛑 收到终止信号，开始清理...');
  server.close(async () => {
    await mongoose.disconnect();
    console.log('✅ 资源清理完成');
    process.exit(0);
  });
  setTimeout(() => {
    console.error('⛔ 清理超时，强制退出');
    process.exit(1);
  }, 5000);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

app.use((err, req, res, next) => {
  console.error('⚠️ 全局错误:', err);
  res.status(500).json({ error: "服务器内部错误" });
});