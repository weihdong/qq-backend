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

// 新增：好友状态广播函数
const broadcastFriendStatus = async (userId, isOnline) => {
  try {
    const friendList = await Friend.findOne({ userId });
    if (friendList) {
      friendList.friends.forEach(friend => {
        const friendWs = onlineUsers.get(friend.user.toString());
        if (friendWs) {
          friendWs.send(JSON.stringify({
            type: 'status',
            userId,
            online: isOnline
          }));
        }
      });
    }
  } catch (error) {
    console.error('状态广播错误:', error);
  }
};

wss.on('connection', (ws, req) => {
  let userId = null;
  let isAlive = true;

  // 心跳检测
  const heartbeat = () => {
    if (!isAlive) {
      console.log(`💔 心跳丢失: ${userId}`);
      return ws.terminate();
    }
    isAlive = false;
    ws.ping();
  };

  const interval = setInterval(heartbeat, HEARTBEAT_INTERVAL * 1000);

  ws.on('pong', () => {
    isAlive = true;
    console.log(`💓 心跳正常: ${userId}`);
  });

  ws.on('message', async (message) => {
    try {
      const msgData = JSON.parse(message);
      
      // 合并处理 connect 类型消息
      if (msgData.type === 'connect') {
        // 清理旧连接
        if (userId && onlineUsers.get(userId) === ws) {
          onlineUsers.delete(userId);
        }
        
        userId = msgData.userId;
        onlineUsers.set(userId, ws);
        ws.userId = userId;

        // 发送连接确认
        ws.send(JSON.stringify({
          type: 'system',
          message: 'CONNECTED'
        }));

        // 广播在线状态
        await broadcastFriendStatus(userId, true);
        return;
      }

      // 处理所有类型的消息
      if (['text', 'image', 'audio'].includes(msgData.type)) {
        const newMessage = new Message({
          from: msgData.from,
          to: msgData.to,
          content: msgData.content,
          type: msgData.type
        });
        
        await newMessage.save();

        // 广播消息
        [msgData.to, msgData.from].forEach(targetId => {
          const client = onlineUsers.get(targetId);
          if (client && client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({
              type: 'message',
              ...newMessage.toJSON()
            }));
          }
        });
      }
    } catch (error) {
      console.error('WebSocket消息处理错误:', error);
    }
  });

  ws.on('close', async () => {
    clearInterval(interval);
    if (userId) {
      onlineUsers.delete(userId);
      await broadcastFriendStatus(userId, false);
    }
  });
});

// 其他中间件和路由...
// 新增文件上传功能
const multer = require('multer');
const storage = multer.memoryStorage();
const upload = multer({ 
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB限制
});

// 消息模型修改 - 支持不同类型消息
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
    maxlength: 2000
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

// 新增文件上传路由
app.post('/api/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({ error: "未上传文件" });
    }

    const file = req.file;
    const fileType = file.mimetype.split('/')[0];
    const fileTypeStr = fileType === 'image' ? 'image' : (fileType === 'audio' ? 'audio' : 'file');

    // 将文件保存到GridFS（MongoDB的文件存储系统）
    const bucket = new mongoose.mongo.GridFSBucket(mongoose.connection.db, {
      bucketName: 'uploads'
    });

    const uploadStream = bucket.openUploadStream(`${Date.now()}-${file.originalname}`);
    uploadStream.end(file.buffer);

    uploadStream.on('finish', () => {
      res.status(HTTP_STATUS.CREATED).json({
        url: `/api/file/${uploadStream.id}`,
        type: fileTypeStr,
        originalName: file.originalname,
        size: file.size
      });
    });
  } catch (error) {
    console.error('文件上传错误:', error);
    res.status(HTTP_STATUS.INTERNAL_ERROR).json({ error: "上传失败" });
  }
});

// 新增文件获取路由
app.get('/api/file/:id', async (req, res) => {
  try {
    const bucket = new mongoose.mongo.GridFSBucket(mongoose.connection.db, {
      bucketName: 'uploads'
    });

    const fileId = new mongoose.Types.ObjectId(req.params.id);
    const downloadStream = bucket.openDownloadStream(fileId);

    downloadStream.on('error', (error) => {
      if (error.code === 'ENOENT') {
        return res.status(HTTP_STATUS.NOT_FOUND).json({ error: "文件不存在" });
      }
      throw error;
    });

    downloadStream.pipe(res);
  } catch (error) {
    console.error('文件获取错误:', error);
    res.status(HTTP_STATUS.INTERNAL_ERROR).json({ error: "获取文件失败" });
  }
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