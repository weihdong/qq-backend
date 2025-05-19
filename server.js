// server.js 免令牌验证版
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

// 用户模型
const userSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true,
    unique: true,
    minlength: 3,
    maxlength: 20,
    trim: true,
    match: /^[a-zA-Z0-9_]+$/
  },
  password: {
    type: String,
    required: true,
    select: false,
    minlength: 6
  },
  createdAt: {
    type: Date,
    default: Date.now
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

// 登录/注册路由
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // 输入验证
    if (!username || !password) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({ error: "用户名和密码不能为空" });
    }

    // 查找用户
    const user = await User.findOne({ username }).select('+password');
    
    // 用户存在验证密码
    if (user) {
      const valid = await bcrypt.compare(password, user.password);
      if (!valid) {
        console.warn(`[登录失败] 密码错误: ${username}`);
        return res.status(HTTP_STATUS.UNAUTHORIZED).json({ error: "认证失败" });
      }
      return res.json({ userId: user._id, username: user.username });
    }

    // 注册新用户
    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = await User.create({
      username,
      password: hashedPassword,
      lastLogin: new Date()
    });

    // 初始化好友列表
    await Friend.create({ userId: newUser._id, friends: [] });
    console.log(`[新用户注册] ${username} ID:${newUser._id}`);

    res.status(HTTP_STATUS.CREATED).json({
      userId: newUser._id,
      username: newUser.username
    });

  } catch (error) {
    console.error('登录错误:', error);
    res.status(HTTP_STATUS.INTERNAL_ERROR).json({ error: "服务器错误" });
  }
});

// 添加好友路由（无需令牌）
app.post('/api/friends', async (req, res) => {
  try {
    const { userId, friendUsername } = req.body;

    // 参数验证
    if (!userId || !friendUsername) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({ error: "缺少必要参数" });
    }

    // 查找目标用户
    const friend = await User.findOne({ username: friendUsername });
    if (!friend) {
      return res.status(HTTP_STATUS.NOT_FOUND).json({ error: "用户不存在" });
    }

    // 防止添加自己
    if (userId === friend._id.toString()) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({ error: "不能添加自己为好友" });
    }

    // 检查是否已是好友
    const existing = await Friend.findOne({
      userId,
      'friends.user': friend._id
    });
    if (existing) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({ error: "已是好友关系" });
    }

    // 添加双向好友关系
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

// 获取好友列表
app.get('/api/friends', async (req, res) => {
  try {
    const { userId } = req.query;
    
    if (!userId) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({ error: "需要用户ID" });
    }

    const friendList = await Friend.findOne({ userId })
      .populate('friends.user', 'username')
      .lean();

    const friends = friendList?.friends.map(f => ({
      id: f.user._id,
      username: f.user.username,
      addedAt: f.addedAt
    })) || [];

    res.json({ friends });

  } catch (error) {
    console.error('获取好友列表错误:', error);
    res.status(HTTP_STATUS.INTERNAL_ERROR).json({ error: "获取失败" });
  }
});

// 健康检查
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// 启动服务器
const server = app.listen(process.env.PORT || 3000, '0.0.0.0', () => {
  console.log(`🚀 服务器运行中，端口：${server.address().port}`);
});

// WebSocket
const wss = new WebSocket.Server({ server });
wss.on('connection', (ws) => {
  ws.on('message', (message) => {
    wss.clients.forEach(client => {
      if (client !== ws && client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    });
  });
});

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