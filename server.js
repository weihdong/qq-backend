const express = require('express');
const mongoose = require('mongoose');
const WebSocket = require('ws');
const cors = require('cors');

const app = express();

app.use(cors({
    origin: 'https://qq.085410.xyz',
    methods: ['POST', 'GET', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    preflightContinue: false,
    optionsSuccessStatus: 204
  }))
  
  // 显式处理OPTIONS请求
  app.options('*', (req, res) => {
    res.sendStatus(204)
  })

// ========== 数据库配置 ==========
const MONGODB_URI = 'mongodb+srv://dwh:1122@cluster0.arkqevd.mongodb.net/Cluster0?retryWrites=true&w=majority';

// ========== 数据模型 ==========
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);

const friendSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
});
const Friend = mongoose.model('Friend', friendSchema);

const messageSchema = new mongoose.Schema({
  from: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  to: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: true },
  timestamp: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', messageSchema);

// ========== 数据库连接 ==========
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB连接成功'))
.catch(err => {
  console.error('MongoDB连接失败:', err.message);
  process.exit(1);
});

// ========== REST API ==========
// 登录/注册
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: '用户名和密码不能为空' });
    }

    let user = await User.findOne({ username });
    
    if (!user) {
      user = await User.create({ username, password });
    } else if (user.password !== password) {
      return res.status(401).json({ error: '密码错误' });
    }

    res.json({ userId: user._id, username: user.username });
    
  } catch (error) {
    console.error('登录错误:', error);
    res.status(500).json({ error: '登录失败' });
  }
});

// 添加好友
app.post('/api/friends', async (req, res) => {
  try {
    const { userId, friendName } = req.body;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ error: '无效的用户ID' });
    }

    const friend = await User.findOne({ username: friendName });
    if (!friend) return res.status(404).json({ error: '用户不存在' });

    const existing = await Friend.findOne({ userId, friends: friend._id });
    if (existing) return res.status(409).json({ error: '已是好友' });

    await Friend.updateOne(
      { userId },
      { $addToSet: { friends: friend._id } },
      { upsert: true }
    );

    res.json({ 
      success: true,
      friend: { _id: friend._id, username: friend.username }
    });

  } catch (error) {
    console.error('添加好友错误:', error);
    res.status(500).json({ error: '添加好友失败' });
  }
});

// 获取好友列表
app.get('/api/friends', async (req, res) => {
  try {
    const { userId } = req.query;

    const friendData = await Friend.findOne({ userId })
      .populate('friends', 'username')
      .exec();

    res.json(friendData?.friends || []);
    
  } catch (error) {
    console.error('获取好友错误:', error);
    res.status(500).json({ error: '获取好友失败' });
  }
});

// 获取消息记录
app.get('/api/messages', async (req, res) => {
  try {
    const { from, to } = req.query;
    
    const messages = await Message.find({
      $or: [
        { from, to },
        { from: to, to: from }
      ]
    }).sort('timestamp');

    res.json(messages);
    
  } catch (error) {
    console.error('获取消息错误:', error);
    res.status(500).json({ error: '获取消息失败' });
  }
});

// ========== WebSocket ==========
const server = app.listen(process.env.PORT || 3000, () => {
  console.log(`服务器运行中，端口：${process.env.PORT || 3000}`);
});

// WebSocket部分保持原有代码不变
const wss = new WebSocket.Server({ server });
const onlineUsers = new Map();

wss.on('connection', (ws, req) => {
  // 从查询参数获取userId
  const userId = new URL(req.url, `http://${req.headers.host}`).searchParams.get('userId');
  ws.userId = userId;
  onlineUsers.set(userId, true);
  broadcastStatus(userId, true);

  ws.on('message', async (message) => {
    try {
      const msg = JSON.parse(message);
      
      if (!msg.from || !msg.to || !msg.content) {
        return ws.send(JSON.stringify({ error: "无效消息格式" }));
      }

      const newMessage = await Message.create(msg);
      
      // 精准发送给相关客户端
      wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN && 
          (client.userId === msg.from || client.userId === msg.to)) {
          client.send(JSON.stringify(newMessage));
        }
      });
    } catch (error) {
      console.error('消息处理错误:', error);
    }
    const heartbeat = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'heartbeat' }));
        }
      }, 30000);
    
      // 连接关闭处理
    ws.on('close', () => {
    clearInterval(heartbeat);
    onlineUsers.delete(userId);
    broadcastStatus(userId, false);
    });
  });
});
// 广播状态变化
function broadcastStatus(userId, isOnline) {
    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({
          type: 'status-update',
          userId,
          status: isOnline
        }));
      }
    });
  }