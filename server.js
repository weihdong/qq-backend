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
  CONFLICT: 409,
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
  type: {
    type: String,
    enum: ['text', 'image', 'audio'],
    default: 'text'
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

// 新增用户信息接口
app.get('/api/user/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('username');
    if (!user) return res.status(HTTP_STATUS.NOT_FOUND).json({ error: "用户不存在" });
    res.status(HTTP_STATUS.OK).json(user);
  } catch (error) {
    console.error('获取用户信息错误:', error);
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
// 添加好友路由（最终修正版）
app.post('/api/friends', async (req, res) => {
  try {
    const { userId, friendUsername } = req.body;

    if (!userId || !friendUsername) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({ 
        error: "缺少必要参数",
        code: "MISSING_PARAMETERS" 
      });
    }

    const currentUser = await User.findById(userId);
    if (!currentUser) {
      return res.status(HTTP_STATUS.NOT_FOUND).json({
        error: "用户不存在",
        code: "USER_NOT_FOUND"
      });
    }

    const friendUser = await User.findOne({ username: friendUsername });
    if (!friendUser) {
      return res.status(HTTP_STATUS.NOT_FOUND).json({ 
        error: "目标用户不存在",
        code: "FRIEND_NOT_FOUND" 
      });
    }

    if (userId === friendUser._id.toString()) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        error: "不能添加自己为好友",
        code: "SELF_ADDITION"
      });
    }

    const existingFriend = await Friend.findOne({
      userId,
      'friends.user': friendUser._id
    });
    if (existingFriend) {
      return res.status(HTTP_STATUS.CONFLICT).json({ // 使用已定义的CONFLICT状态码
        error: "已是好友关系",
        code: "ALREADY_FRIENDS"
      });
    }

    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      await Friend.updateOne(
        { userId },
        { $addToSet: { friends: { user: friendUser._id } } },
        { upsert: true, session }
      );

      await Friend.updateOne(
        { userId: friendUser._id },
        { $addToSet: { friends: { user: userId } } },
        { upsert: true, session }
      );

      await session.commitTransaction();
      
      res.status(HTTP_STATUS.CREATED).json({
        message: "添加好友成功",
        friendId: friendUser._id,
        username: friendUser.username
      });

    } catch (error) {
      await session.abortTransaction();
      console.error('事务执行失败:', error);
      return res.status(HTTP_STATUS.INTERNAL_ERROR).json({ 
        error: "添加好友失败",
        code: "ADD_FRIEND_FAILED",
        details: error.message 
      });
    } finally {
      session.endSession();
    }

  } catch (error) {
    console.error('添加好友错误:', error);
    res.status(HTTP_STATUS.INTERNAL_ERROR).json({ 
      error: "添加好友失败",
      code: "ADD_FRIEND_FAILED",
      details: error.message 
    });
  }
});
// WebSocket处理
// WebSocket处理
const server = app.listen(process.env.PORT || 3000, '0.0.0.0', () => {
  console.log(`🚀 服务器运行中，端口：${server.address().port}`);
});

const wss = new WebSocket.Server({ server });
const onlineUsers = new Map();
const HEARTBEAT_INTERVAL = 30;

// server.js - 替换 broadcastFriendStatus 函数
const broadcastFriendStatus = async (userId, isOnline) => {
  try {
    console.log(`📢 广播状态: ${userId} -> ${isOnline ? '在线' : '离线'}`);
    
    const friendList = await Friend.findOne({ userId }).populate('friends.user');
    if (!friendList) return;
    
    // 确保使用正确的 ID 格式
    const userIdStr = userId.toString();
    
    friendList.friends.forEach(friend => {
      const friendId = friend.user._id.toString();
      const friendWs = onlineUsers.get(friendId);
      
      if (friendWs && friendWs.readyState === WebSocket.OPEN) {
        friendWs.send(JSON.stringify({
          type: 'status-update',
          userId: userIdStr,
          status: isOnline,
          timestamp: new Date().toISOString()
        }));
        console.log(`   ➤ 发送给: ${friendId}`);
      }
    });
  } catch (error) {
    console.error('❌ 状态广播错误:', error);
  }
};

// server.js - 替换整个 wss.on('connection') 部分

// WebSocket处理
wss.on('connection', (ws, req) => {
  console.log('🔌 新WebSocket连接请求');
  
  // 从URL参数获取userId
  const urlParams = new URLSearchParams(req.url.split('?')[1]);
  const userId = urlParams.get('userId');
  
  if (!userId) {
    console.log('❌ 未提供userId，关闭连接');
    ws.close(4001, 'Missing userId');
    return;
  }
  
  // 验证用户ID
  User.findById(userId).then(user => {
    if (!user) {
      console.log(`❌ 无效用户ID: ${userId}`);
      ws.close(4002, 'Invalid user ID');
      return;
    }
    
    console.log(`🟢 用户连接: ${user.username} (${userId})`);
    
    // 清理旧连接（如果存在）
    const existingConnection = onlineUsers.get(userId);
    if (existingConnection && existingConnection.readyState === WebSocket.OPEN) {
      console.log(`♻️ 关闭重复连接: ${userId}`);
      existingConnection.close(4003, 'Duplicate connection');
    }
    
    // 存储新连接
    onlineUsers.set(userId, ws);
    ws.userId = userId;
    
    // 发送连接确认
    ws.send(JSON.stringify({
      type: 'system',
      message: 'CONNECTED',
      timestamp: new Date().toISOString()
    }));
    
    // 广播在线状态
    broadcastFriendStatus(userId, true);
    
    // 心跳检测
    let isAlive = true;
    let heartbeatInterval;
    
    const heartbeat = () => {
      if (!isAlive) {
        console.log(`💔 心跳丢失: ${userId}`);
        return ws.terminate();
      }
      isAlive = false;
      ws.ping();
    };
    
    heartbeatInterval = setInterval(heartbeat, HEARTBEAT_INTERVAL * 1000);
    
    ws.on('pong', () => {
      isAlive = true;
      console.log(`💓 心跳正常: ${userId}`);
    });
    
    // 消息处理
    ws.on('message', async (message) => {
      try {
        console.log(`📨 收到消息: ${message.substring(0, 50)}...`);
        const msgData = JSON.parse(message);
        
        // 处理心跳
        if (msgData.type === 'ping') {
          ws.send(JSON.stringify({type: 'pong'}));
          return;
        }
        
        // 处理消息
        if (['text', 'image', 'audio'].includes(msgData.type)) {
          const newMessage = new Message({
            from: msgData.from,
            to: msgData.to,
            content: msgData.content,
            type: msgData.type,
            timestamp: new Date(msgData.timestamp)
          });
          
          await newMessage.save();
          
          // 转换为标准消息格式
          const formattedMsg = {
            _id: newMessage._id.toString(),
            from: newMessage.from.toString(),
            to: newMessage.to.toString(),
            content: newMessage.content,
            type: newMessage.type,
            timestamp: newMessage.timestamp.toISOString()
          };

          // 广播消息给发送方和接收方
          [msgData.to, msgData.from].forEach(targetId => {
            const client = onlineUsers.get(targetId);
            if (client && client.readyState === WebSocket.OPEN) {
              client.send(JSON.stringify(formattedMsg));
              console.log(`📤 发送消息给 ${targetId}`);
            }
          });
        }
      } catch (error) {
        console.error('❌ WebSocket消息处理错误:', error);
      }
    });
    
    // 关闭连接处理
    ws.on('close', async (code, reason) => {
      console.log(`🚪 连接关闭: ${userId} (代码: ${code}, 原因: ${reason})`);
      clearInterval(heartbeatInterval);
      
      if (userId && onlineUsers.get(userId) === ws) {
        onlineUsers.delete(userId);
        await broadcastFriendStatus(userId, false);
      }
    });
    
  }).catch(error => {
    console.error('❌ 用户验证失败:', error);
    ws.close(4003, 'User verification failed');
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