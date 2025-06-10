process.on('warning', (warning) => {
  console.warn('⚠️ Node.js警告:', warning.stack);
});

// 引入必要的模块
const express = require('express');
const mongoose = require('mongoose');
const WebSocket = require('ws');
const cors = require('cors');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');



console.log('🛠️ 环境变量:', {
  NODE_ENV: process.env.NODE_ENV,
  PORT: process.env.PORT,
  MONGODB_URI: process.env.MONGODB_URI ? '已配置' : '未配置'
});

// 确保上传目录存在
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// 提供静态文件访问
const app = express();
app.use('/uploads', express.static(uploadDir));

const HTTP_STATUS = {
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  NOT_FOUND: 404,
  CONFLICT: 409,
  INTERNAL_ERROR: 500,
  CREATED: 201,
  OK: 200
};

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
  console.log(`[${new Date().toISOString()}] ${req.method}${req.url} | Origin: ${req.headers.origin}`);
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


// 新增：会议状态存储
const activeMeetings = new Map();
// 新增：会议信令处理器
function handleMeetingSignal(ws, signal) {
  const { meetingId, userId, action, data } = signal;
  
  switch (action) {
    case 'create':
      // 创建新会议
      activeMeetings.set(meetingId, {
        participants: new Map([[userId, ws]]),
        creator: userId
      });
      break;
      
    case 'join':
      // 加入现有会议
      const meeting = activeMeetings.get(meetingId);
      if (meeting) {
        meeting.participants.set(userId, ws);
        
        // 通知所有参与者有新成员加入
        broadcastToMeeting(meetingId, {
          type: 'meeting-signal',
          action: 'participant-joined',
          userId,
          meetingId
        });
      }
      break;
      
    case 'leave':
      // 离开会议
      const currentMeeting = activeMeetings.get(meetingId);
      if (currentMeeting) {
        currentMeeting.participants.delete(userId);
        
        // 通知所有参与者有成员离开
        broadcastToMeeting(meetingId, {
          type: 'meeting-signal',
          action: 'participant-left',
          userId,
          meetingId
        });
        
        // 如果会议为空则清理
        if (currentMeeting.participants.size === 0) {
          activeMeetings.delete(meetingId);
        }
      }
      break;
      
    case 'offer':
    case 'answer':
    case 'candidate':
      // 转发WebRTC信令给目标用户
      const targetMeeting = activeMeetings.get(meetingId);
      if (targetMeeting && targetMeeting.participants.has(data.targetUserId)) {
        const targetWs = targetMeeting.participants.get(data.targetUserId);
        if (targetWs && targetWs.readyState === WebSocket.OPEN) {
          targetWs.send(JSON.stringify({
            ...signal,
            senderId: userId
          }));
        }
      }
      break;
  }
}

// 辅助函数：向会议所有成员广播消息
function broadcastToMeeting(meetingId, message) {
  const meeting = activeMeetings.get(meetingId);
  if (meeting) {
    for (const [participantId, participantWs] of meeting.participants) {
      if (participantWs.readyState === WebSocket.OPEN) {
        participantWs.send(JSON.stringify(message));
      }
    }
  }
}
// 新增群模型
const groupSchema = new mongoose.Schema({
  code: {
    type: String,
    required: true,
    unique: true,
    minlength: 3,
    maxlength: 6
  },
  name: {
    type: String,
    required: true,
    maxlength: 20
  },
  creator: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  members: [{
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    username: String,
    joinedAt: {
      type: Date,
      default: Date.now
    }
  }],
  createdAt: {
    type: Date,
    default: Date.now
  }
}, { versionKey: false });

const Group = mongoose.model('Group', groupSchema);
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

// 配置文件上传
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage,
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB限制
});

// 修改消息模型
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
  content: String,
  timestamp: {
    type: Date,
    default: Date.now
  },
  type: {
    type: String,
    enum: ['text', 'image', 'audio', 'emoji'],
    default: 'text'
  },
  fileUrl: String,
  chatType: {
    type: String,
    enum: ['private', 'group'],
    default: 'private'
  }
});

const Message = mongoose.model('Message', messageSchema);

// 修改文件上传路由（修复 HTTPS URL）
app.post('/api/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "未上传文件" });
    }
    
    // 动态生成 HTTPS URL（适用于生产环境）
    const isProduction = req.hostname.includes('085410.xyz');
    const protocol = isProduction ? 'https' : 'http';
    const fileUrl = `${protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    
    res.json({ url: fileUrl });
  } catch (error) {
    console.error('文件上传错误:', error);
    res.status(500).json({ error: "上传失败" });
  }
});

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
    console.log(`[新用户注册]${username} ID:${newUser._id}`);

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
// 创建群聊接口
app.post('/api/groups', async (req, res) => {
  try {
    const { userId, groupName } = req.body;
    
    if (!userId) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({ error: "需要用户ID" });
    }
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(HTTP_STATUS.NOT_FOUND).json({ error: "用户不存在" });
    }
    
    // 生成唯一群号
    const generateGroupCode = () => {
      const code = Math.floor(100 + Math.random() * 900).toString();
      return Group.exists({ code }).then(exists => exists ? generateGroupCode() : code);
    };
    
    const code = await generateGroupCode();
    
    const newGroup = await Group.create({
      code,
      name: groupName || `群聊${code}`,
      creator: userId,
      members: [{
        userId,
        username: user.username
      }]
    });
    
    res.status(HTTP_STATUS.CREATED).json({ group: newGroup });
  } catch (error) {
    console.error('创建群聊失败:', error);
    res.status(HTTP_STATUS.INTERNAL_ERROR).json({ error: "创建群聊失败" });
  }
});

// 加入群聊接口
app.post('/api/groups/join', async (req, res) => {
  try {
    const { userId, groupCode } = req.body;
    
    if (!userId || !groupCode) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({ error: "需要用户ID和群号" });
    }
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(HTTP_STATUS.NOT_FOUND).json({ error: "用户不存在" });
    }
    
    const group = await Group.findOne({ code: groupCode });
    if (!group) {
      return res.status(HTTP_STATUS.NOT_FOUND).json({ error: "群聊不存在" });
    }
    
    // 检查是否已经是群成员
    const isMember = group.members.some(member => member.userId.equals(userId));
    if (isMember) {
      return res.status(HTTP_STATUS.CONFLICT).json({ error: "已在群聊中" });
    }
    
    // 添加新成员
    group.members.push({
      userId,
      username: user.username
    });
    
    await group.save();
    
    res.status(HTTP_STATUS.OK).json({ group });
  } catch (error) {
    console.error('加入群聊失败:', error);
    res.status(HTTP_STATUS.INTERNAL_ERROR).json({ error: "加入群聊失败" });
  }
});

// 获取用户群聊列表
app.get('/api/groups', async (req, res) => {
  try {
    const { userId } = req.query;
    
    if (!userId) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({ error: "需要用户ID" });
    }
    
    const groups = await Group.find({ 'members.userId': userId });
    
    res.json({ groups });
  } catch (error) {
    console.error('获取群聊列表失败:', error);
    res.status(HTTP_STATUS.INTERNAL_ERROR).json({ error: "获取群聊列表失败" });
  }
});

// 获取群聊消息
app.get('/api/group-messages', async (req, res) => {
  try {
    const { groupId } = req.query;
    
    if (!groupId) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({ error: "需要群聊ID" });
    }
    
    const messages = await Message.find({
      to: groupId,
      chatType: 'group'
    }).sort({ timestamp: 1 }).lean();
    
    res.json(messages);
  } catch (error) {
    console.error('获取群消息失败:', error);
    res.status(HTTP_STATUS.INTERNAL_ERROR).json({ error: "获取群消息失败" });
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

// 修改 WebSocket 消息处理（确保转发所有信号）
ws.on('message', async (message) => {
  try {
    const msgData = JSON.parse(message);
    // 会议信令处理
    if (msgData.type === 'meeting-signal') {
      handleMeetingSignal(ws, msgData);
      return;
    }
    // 群聊消息处理
    if (msgData.chatType === 'group') {
      const newMessage = new Message({
        ...msgData,
        chatType: 'group'
      });
      
      await newMessage.save();
      
      // 获取群成员
      const group = await Group.findById(msgData.to);
      if (!group) return;
      
      // 广播给所有群成员
      group.members.forEach(member => {
        const memberId = member.userId.toString();
        const client = onlineUsers.get(memberId);
        if (client && client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify({
            type: 'group-message',
            data: {
              ...newMessage.toObject(),
              _id: newMessage._id.toString(),
              timestamp: newMessage.timestamp.toISOString()
            }
          }));
        }
      });
      
      return;
    }
    // 视频信号处理 - 确保转发所有类型
    if (msgData.type === 'video-signal') {
      const targetUser = msgData.to;
      const targetWs = onlineUsers.get(targetUser);
      
      if (targetWs && targetWs.readyState === WebSocket.OPEN) {
        // 添加发送方ID
        const forwardData = {
          ...msgData,
          from: userId || msgData.from
        };
        
        console.log(`转发视频信号: ${userId} -> ${targetUser}`, forwardData.signalType);
        targetWs.send(JSON.stringify(forwardData));
      } else {
        console.log(`目标用户 ${targetUser} 不在线，无法转发视频信号`);
        
        // 通知发送方
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({
            type: 'system',
            message: `用户 ${targetUser} 不在线，无法建立视频通话`
          }));
        }
      }
    }
    
    
    // 连接处理
    if (msgData.type === 'connect') {
      // 清理旧连接（防止重复）
      if (userId && onlineUsers.get(userId) === ws) {
        onlineUsers.delete(userId);
      }
      
      userId = msgData.userId;
      onlineUsers.set(userId, ws);
      ws.userId = userId;

      ws.send(JSON.stringify({
        type: 'system',
        message: 'CONNECTED'
      }));

      await broadcastFriendStatus(userId, true);
      return;
    }

      // 处理所有消息类型
      if (['text', 'image', 'audio', 'emoji'].includes(msgData.type)) {
        const newMessage = new Message({
          from: msgData.from,
          to: msgData.to,
          content: msgData.content,
          type: msgData.type,
          fileUrl: msgData.fileUrl,
          timestamp: new Date(msgData.timestamp || Date.now())
        });
        
        await newMessage.save();

        // 广播消息 - 确保包含所有必要字段
        const messageToSend = {
          ...newMessage.toObject(),
          _id: newMessage._id.toString(),
          timestamp: newMessage.timestamp.toISOString()
        };

        [msgData.to, msgData.from].forEach(targetId => {
          const client = onlineUsers.get(targetId);
          if (client && client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({
              type: 'message', // 统一为'message'类型
              data: messageToSend
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
