// 在server.js开头添加
process.on('warning', (warning) => {
  console.warn('⚠️ Node.js警告:', warning.stack);
});

// 启动日志
console.log('🛠️ 环境变量:', {
  NODE_ENV: process.env.NODE_ENV,
  PORT: process.env.PORT,
  MONGODB_URI: process.env.MONGODB_URI ? '已配置' : '未配置'
});

const express = require('express');
const mongoose = require('mongoose');
const WebSocket = require('ws');
const cors = require('cors');
const url = require('url');
const bcrypt = require('bcrypt');

// 1. 常量定义优化
const HTTP_STATUS = {
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  INTERNAL_ERROR: 500,
  CREATED: 201,
  OK: 200
};

const app = express();

// 2. 增强CORS配置（修复关键问题）
const allowedOrigins = [
  'https://qq.085410.xyz',
  'https://qq-rust.vercel.app', // 添加Vercel部署域名
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

// 3. 中间件顺序调整（关键）
app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // 处理所有OPTIONS请求
app.use(express.json({ limit: '10kb' }));

// 4. 请求日志中间件
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} | Origin: ${req.headers.origin}`);
  next();
});

// 5. 数据库连接优化（修复Mongoose警告）
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://dwh:1122@cluster0.arkqevd.mongodb.net/Cluster0?retryWrites=true&w=majority&appName=Cluster0';

mongoose.connect(MONGODB_URI, {
  serverSelectionTimeoutMS: 15000,
  retryWrites: true,
  ssl: true, // 必须添加SSL
  appName: 'Railway_Deploy' // 明确应用名称
})
.then(() => console.log('✅ MongoDB连接成功'))
.catch(err => {
  console.error('❌ MongoDB连接失败:', err);
  process.exit(1);
});

// 6. 数据模型（保持不变）
const userSchema = new mongoose.Schema({ /* 原有内容 */ });
const User = mongoose.model('User', userSchema);

const friendSchema = new mongoose.Schema({ /* 原有内容 */ });
const Friend = mongoose.model('Friend', friendSchema);

const messageSchema = new mongoose.Schema({ /* 原有内容 */ });
const Message = mongoose.model('Message', messageSchema);

// 7. 适配Railway的健康检查（关键修改）
// 专为Railway设计的健康检查
app.get('/railway-healthz', (req, res) => {
  const dbReady = mongoose.connection.readyState === 1;
  res.status(dbReady ? 200 : 503).json({
    db: dbReady ? 'ready' : 'down',
    timestamp: Date.now()
  });
});

app.get('/', (req, res) => {
  res.send('🚀 后端服务运行中 | ' + new Date().toISOString());
});

// 8. 登录路由优化（错误处理增强）
app.post('/api/login', async (req, res) => {
  try {
    const { username: rawUsername, password: rawPassword } = req.body;
    const username = rawUsername?.trim();
    const password = rawPassword?.trim();

    // 输入验证
    if (!username || !password) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        error: "用户名和密码不能为空",
        code: "INVALID_INPUT"
      });
    }

    // 用户查询（修复密码验证）
    const user = await User.findOne({ username }).select('+password');
    
    if (user) {
      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) {
        return res.status(HTTP_STATUS.UNAUTHORIZED).json({
          error: "密码错误",
          code: "INVALID_CREDENTIALS"
        });
      }
      return res.json({
        userId: user._id,
        username: user.username
      });
    }

    // 创建新用户
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({
      username,
      password: hashedPassword
    });

    return res.status(HTTP_STATUS.CREATED).json({
      userId: newUser._id,
      username: newUser.username
    });

  } catch (error) {
    // 增强错误处理
    if (error.code === 11000) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        error: "用户名已存在",
        code: "DUPLICATE_USERNAME"
      });
    }
    console.error('[登录错误]', error.stack);
    return res.status(HTTP_STATUS.INTERNAL_ERROR).json({
      error: "服务器错误",
      code: "SERVER_ERROR"
    });
  }
});

// 9. WebSocket服务器配置（关键修复）
const server = app.listen(process.env.PORT || 3000, '0.0.0.0', () => {
  console.log(`🚀 服务器运行中，端口：${server.address().port}`);
});

const wss = new WebSocket.Server({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  const origin = req.headers.origin;
  
  // 严格来源验证
  if (!allowedOrigins.includes(origin)) {
    console.log(`⛔ 拒绝非法WebSocket连接: ${origin}`);
    return socket.destroy();
  }

  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit('connection', ws, req);
  });
});

wss.on('connection', (ws, req) => {
  // ...原有逻辑保持不变，增加心跳检测
  ws.isAlive = true;
  
  const heartbeat = setInterval(() => {
    if (!ws.isAlive) {
      console.log(`💔 心跳丢失: ${ws.userId}`);
      return ws.terminate();
    }
    ws.isAlive = false;
    ws.ping();
  }, 30000);

  ws.on('pong', () => {
    ws.isAlive = true;
    console.log(`💓 心跳正常: ${ws.userId}`);
  });

  const interval = setInterval(() => {
    if (!ws.isAlive) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  }, 30000);

  ws.on('close', () => {
    clearInterval(heartbeat);
    console.log(`❌ 用户断开: ${ws.userId}`);
  });
});

// 10. 优雅关闭处理（修复容器重启问题）
const gracefulShutdown = () => {
  console.log('🛑 收到终止信号，开始清理...');
  
  // 1. 关闭HTTP服务器
  server.close(async () => {
    // 2. 关闭WebSocket连接
    wss.clients.forEach(client => client.close());
    
    // 3. 关闭数据库
    await mongoose.disconnect();
    
    console.log('✅ 资源清理完成');
    process.exit(0);
  });

  // 强制退出计时器
  setTimeout(() => {
    console.error('⛔ 清理超时，强制退出');
    process.exit(1);
  }, 8000);
};

process.on('SIGTERM', gracefulShutdown); // Railway终止信号
process.on('SIGINT', gracefulShutdown);  // 本地Ctrl+C

// 11. 全局错误处理（必须放在最后）
app.use((err, req, res, next) => {
  console.error('⚠️ 全局错误:', err.stack);
  res.status(500).json({
    error: "服务器内部错误",
    code: "INTERNAL_ERROR"
  });
});