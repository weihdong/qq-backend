const express = require('express');
const mongoose = require('mongoose');
const WebSocket = require('ws');
const cors = require('cors');
const url = require('url');
const bcrypt = require('bcrypt');
// 在文件顶部添加常量定义
const HTTP_STATUS = {
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  INTERNAL_ERROR: 500,
  CREATED: 201,
  OK: 200
};
// 初始化Express应用
const app = express();

// ================== 关键修复：中间件顺序重构 ==================
// 1. CORS配置（必须最先定义）
const corsOptions = {
  origin: ['https://qq.085410.xyz', 'http://localhost:5173'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 204
};

// 2. 应用CORS中间件（必须在路由之前）
app.use(cors(corsOptions));

// 3. 处理预检请求（必须放在所有路由之前）
app.options('*', cors(corsOptions));

// 4. 请求体解析中间件（必须在路由之前）
app.use(express.json({ limit: '10kb' }));
// server.js
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`)
  next()
})
// ================== 数据库配置 ==================
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://dwh:1122@cluster0.arkqevd.mongodb.net/Cluster0?retryWrites=true&w=majority&appName=Cluster0';

// server.js 修改数据库连接部分
mongoose.connect(MONGODB_URI)
  .then(() => console.log('MongoDB连接成功'))
  .catch(err => {
    console.error('MongoDB连接失败:', err)
    process.exit(1) // 确保连接失败时退出进程
  })

// ================== 数据模型 ==================
const userSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true, 
    unique: true,
    minlength: 3,
    maxlength: 20
  },
  password: {
    type: String,
    required: true,
    select: false // 默认不返回密码字段
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
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

// 基础路由
app.get('/', (_req, res) => {  // 使用 _req 表示忽略参数
  res.send('Backend is running');
});

// 健康检查
app.get('/health', (_req, res) => {  // 使用 _req 表示忽略参数
  const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
  res.json({  // 自动设置200状态码
    status: 'ok',
    timestamp: new Date().toISOString(),
    database: dbStatus,
    version: process.env.npm_package_version || '1.0.1'  // 动态获取版本号
  });
});



app.post('/api/login', async (req, res) => {
  try {
    const { username: rawUsername, password: rawPassword } = req.body;
    const username = rawUsername?.trim();
    const password = rawPassword?.trim();

    // 增强输入验证
    if (!username || !password) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        error: "用户名和密码不能为空",
        code: "INVALID_INPUT"
      });
    }

    if (username.length < 3 || username.length > 20) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        error: "用户名长度需在3-20个字符之间",
        code: "INVALID_USERNAME"
      });
    }

    if (password.length < 6) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        error: "密码长度至少需要6个字符",
        code: "WEAK_PASSWORD"
      });
    }

    // 检查用户是否存在
    const existingUser = await User.findOne({ username }).select('+password');
    
    if (existingUser) {
      // 验证密码（使用bcrypt加密）
      const isPasswordValid = await bcrypt.compare(password, existingUser.password);
      
      if (!isPasswordValid) {
        return res.status(HTTP_STATUS.UNAUTHORIZED).json({
          error: "密码错误",
          code: "INVALID_CREDENTIALS"
        });
      }

      return res.status(HTTP_STATUS.OK).json({
        userId: existingUser._id,
        username: existingUser.username,
        createdAt: existingUser.createdAt
      });
    }

    // 创建新用户（自动注册）
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({
      username,
      password: hashedPassword, // 存储加密后的密码
      createdAt: new Date()
    });

    return res.status(HTTP_STATUS.CREATED).json({
      userId: newUser._id,
      username: newUser.username,
      createdAt: newUser.createdAt
    });

  } catch (error) {
    console.error('[登录错误]', {
      error: error.stack,
      timestamp: new Date().toISOString()
    });

    // 处理重复用户名错误
    if (error.code === 11000) { // MongoDB重复键错误
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        error: "用户名已被占用",
        code: "USERNAME_EXISTS"
      });
    }

    return res.status(HTTP_STATUS.INTERNAL_ERROR).json({
      error: "服务器内部错误，请稍后再试",
      code: "SERVER_ERROR",
      reference: error.referenceId || Date.now().toString(36) // 错误追踪ID
    });
  }
});

// ================== WebSocket 配置 ==================
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 服务器运行中，端口：${PORT}`);
});

const wss = new WebSocket.Server({ noServer: true });

// server.js 升级事件处理
server.on('upgrade', (req, socket, head) => {
  const origin = req.headers.origin
  if (!corsOptions.origin.includes(origin)) {
    console.log(`🚫 拒绝非法来源: ${origin}`)
    return socket.destroy()
  }
  
  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit('connection', ws, req)
  })
})

wss.on('connection', (ws, req) => {
  const query = url.parse(req.url, true).query;
  const userId = query.userId;

  // 连接日志
  console.log(`📡 用户连接: ${userId || '未知用户'}`);
  
  ws.userId = userId;
  
  // 心跳检测
  const heartbeatInterval = setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) ws.ping();
  }, 25000);

  ws.on('close', () => {
    clearInterval(heartbeatInterval);
    console.log(`❌ 用户断开: ${userId || '未知用户'}`);
  });

  // 消息处理
  ws.on('message', async (data) => {
    try {
      const msg = JSON.parse(data);
      
      if (!msg.from || !msg.to || !msg.content) {
        return ws.send(JSON.stringify({
          status: "error",
          code: 400,
          message: "消息格式无效"
        }));
      }

      const newMessage = await Message.create(msg);
      
      // 广播消息
      wss.clients.forEach(client => {
        if ([WebSocket.OPEN].includes(client.readyState) && 
          [msg.from, msg.to].includes(client.userId)) {
          client.send(JSON.stringify(newMessage));
        }
      });
    } catch (error) {
      console.error('消息处理错误:', error);
      ws.send(JSON.stringify({
        status: "error",
        code: 500,
        message: "消息处理失败"
      }));
    }
  });
});

// ================== 全局错误处理 ==================
app.use((err, req, res, next) => {
  console.error('⚠️ 全局错误:', err.stack);
  res.status(500).json({
    status: "error",
    code: 500,
    message: "服务器内部错误"
  });
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('未处理的Promise拒绝:', reason.stack || reason);
});

process.on('uncaughtException', (err) => {
  console.error('💥 未捕获异常:', err.stack);
  process.exit(1);
});

// 在server.js最后添加
process.on('unhandledRejection', (reason, promise) => {
  console.error('未处理的Promise拒绝:', reason)
  // 可选：发送警报或进行优雅关闭
})

process.on('uncaughtException', (err) => {
  console.error('未捕获异常:', err.stack)
  // 优雅关闭
  server.close(() => process.exit(1))
})