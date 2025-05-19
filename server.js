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

// ================== 数据模型（完整版） ==================
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
    index: { expires: '730d' } // 自动过期（2年）
  },
  lastLogin: Date,
  friends: [{ 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User' 
  }]
}, {
  versionKey: false, // 移除__v字段
  toJSON: { 
    virtuals: true,
    transform: function(doc, ret) {
      delete ret.password; // 始终排除密码字段
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
  timestamps: true // 自动添加createdAt和updatedAt
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

// ================== 登录路由（完整修复版） ==================
app.post('/api/login', async (req, res) => {
  const startTime = Date.now();
  try {
    // 1. 输入处理
    const { username: rawUsername, password: rawPassword } = req.body;
    const username = rawUsername?.trim().substring(0, 20); // 限制长度
    const password = rawPassword?.trim();

    // 2. 基础验证
    if (!username || !password) {
      console.warn('[登录警告] 空输入:', { username: !!username, password: !!password });
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        error: "用户名和密码不能为空",
        code: "INVALID_INPUT",
        requestId: req.headers['x-request-id']
      });
    }

    // 3. 高级验证
    const usernameValid = /^[a-zA-Z0-9_]{3,20}$/.test(username);
    const passwordValid = password.length >= 6 && password.length <= 100;
    
    if (!usernameValid || !passwordValid) {
      console.warn('[登录警告] 无效格式:', { usernameValid, passwordValid });
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        error: "用户名或密码格式无效",
        code: "INVALID_FORMAT",
        details: {
          usernameRules: "3-20位字母数字下划线",
          passwordRules: "6-100位字符"
        }
      });
    }

    // 4. 用户查询（带锁机制防止重复注册）
    const existingUser = await User.findOne({ username })
      .select('+password')
      .setOptions({
        maxTimeMS: 5000, // 查询超时
        collation: { locale: 'en', strength: 2 } // 不区分大小写
      })
      .lean();

    // 5. 用户存在情况
    if (existingUser) {
      // 5.1 验证密码
      const passwordMatch = await bcrypt.compare(password, existingUser.password)
        .catch(err => {
          console.error('[密码验证错误]', err);
          throw new Error('密码验证失败');
        });

      if (!passwordMatch) {
        console.warn('[登录失败] 密码错误:', username);
        return res.status(HTTP_STATUS.UNAUTHORIZED).json({
          error: "认证失败",
          code: "AUTH_FAILED", // 不明确提示密码错误
          retryAfter: 60 // 重试间隔
        });
      }

      // 5.2 更新最后登录时间
      await User.updateOne(
        { _id: existingUser._id },
        { $set: { lastLogin: new Date() } }
      );

      // 5.3 生成访问令牌（示例）
      const token = jwt.sign(
        { userId: existingUser._id },
        process.env.JWT_SECRET || 'defaultSecret',
        { expiresIn: '7d' }
      );

      return res.json({
        userId: existingUser._id,
        username: existingUser.username,
        token,
        expiresIn: 604800 // 7天秒数
      });
    }

    // 6. 新用户注册
    const hashedPassword = await bcrypt.hash(password, 12); // 增强salt轮数
    const newUser = await User.create({
      username,
      password: hashedPassword,
      lastLogin: new Date()
    });

    // 7. 初始化好友列表
    await Friend.create({
      userId: newUser._id,
      friends: []
    });

    console.log(`[新用户注册] ${username} ID:${newUser._id}`);

    return res.status(HTTP_STATUS.CREATED).json({
      userId: newUser._id,
      username: newUser.username,
      initialSetupRequired: true
    });

  } catch (error) {
    // 8. 错误处理
    const errorId = crypto.randomBytes(4).toString('hex');
    console.error(`[登录错误][${errorId}]`, {
      error: error.stack,
      input: { username: rawUsername?.trim(), password: '***' },
      duration: Date.now() - startTime + 'ms'
    });

    // 8.1 处理MongoDB错误
    if (error.name === 'MongoServerError') {
      if (error.code === 11000) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          error: "用户名不可用",
          code: "USERNAME_TAKEN",
          suggestion: "尝试添加数字或下划线"
        });
      }
      return res.status(HTTP_STATUS.INTERNAL_ERROR).json({
        error: "数据库错误",
        code: "DB_ERROR",
        reference: errorId
      });
    }

    // 8.2 通用错误响应
    return res.status(HTTP_STATUS.INTERNAL_ERROR).json({
      error: "处理请求时发生意外错误",
      code: "UNEXPECTED_ERROR",
      reference: errorId,
      timestamp: new Date().toISOString()
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