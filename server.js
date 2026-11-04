require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// 阿里云数据库连接串（优先读取环境变量，默认回退至你的指定 URI）
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://aleafs%40aliyun.com:Xl32cVfKQ6SJ@120.55.50.18:27017/CorporateDB?authSource=admin';

// 基础中间件
app.use(express.json());
app.use(cookieParser());

// 静态资源托管（允许放置额外的 CSS/JS/资源文件）
app.use(express.static(path.join(__dirname, 'public')));

// --- 数据库模型（保持非常规字段：u_serial_identifier 与 p_cipher_digest） ---
const UserSchema = new mongoose.Schema({
  u_serial_identifier: { type: String, unique: true, required: true },
  p_cipher_digest: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
}, { strict: false });

const User = mongoose.model('User', UserSchema);

const Session = mongoose.model('Session', new mongoose.Schema({
  sessionId: { type: String, unique: true, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now, expires: 7 * 86400 }
}));

const StudyProgress = mongoose.model('StudyProgress', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  courseName: { type: String, required: true },
  belongTo: { type: String, default: '未分类' },
  courseUrl: { type: String, required: true },
  lastChapterIndex: { type: Number, default: 0 },
  completedChapters: [{ type: Number }],
  quizScores: [{ chapterIndex: Number, score: Number, total: Number }],
  updatedAt: { type: Date, default: Date.now }
}).index({ userId: 1, courseName: 1 }, { unique: true }));

// 连接 MongoDB 实例
mongoose.connect(MONGODB_URI)
  .then(() => console.log('[DB] Connected successfully to CorporateDB.'))
  .catch(err => console.error('[DB] Connection error:', err));

// --- 鉴权中间件 ---
async function authMiddleware(req, res, next) {
  const sessionId = req.cookies.sessionId;
  if (!sessionId) return res.status(401).json({ error: '未登录' });

  const session = await Session.findOne({ sessionId }).populate('userId');
  if (!session || !session.userId) {
    res.clearCookie('sessionId');
    return res.status(401).json({ error: 'Session 无效' });
  }
  req.user = session.userId;
  next();
}

// ==================== 接口路由 ====================

// 1. 用户注册
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password || password.length < 6) {
      return res.status(400).json({ error: '用户名与密码必填，且密码长度需不少于 6 位' });
    }

    const exists = await User.findOne({
      $or: [
        { u_serial_identifier: username },
        { username: username }
      ]
    });
    if (exists) {
      return res.status(400).json({ error: '该用户已被注册' });
    }

    const hashedSecret = await bcrypt.hash(password, 10);
    const newUser = await User.create({
      u_serial_identifier: username,
      p_cipher_digest: hashedSecret
    });

    const sessionId = crypto.randomUUID();
    await Session.create({ sessionId, userId: newUser._id });

    res.cookie('sessionId', sessionId, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 7 * 86400 * 1000
    });

    res.json({ success: true, username });
  } catch (e) {
    res.status(500).json({ error: '注册失败: ' + e.message });
  }
});

// 2. 用户登录
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: '请填写完整的用户名和密码' });
    }

    const user = await User.findOne({
      $or: [
        { u_serial_identifier: username },
        { username: username }
      ]
    });

    if (!user) {
      return res.status(401).json({ error: '用户不存在' });
    }

    const secretHash = user.p_cipher_digest || user.password || user.passwordHash || user.pwd;
    if (!secretHash) {
      return res.status(500).json({ error: '未在该记录中找到对应的凭证密文' });
    }

    let isMatch = false;
    try {
      isMatch = await bcrypt.compare(password, secretHash);
    } catch (bcryptErr) {
      isMatch = (password === secretHash);
    }

    if (!isMatch) {
      return res.status(401).json({ error: '密码错误' });
    }

    const sessionId = crypto.randomUUID();
    await Session.create({ sessionId, userId: user._id });

    res.cookie('sessionId', sessionId, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 7 * 86400 * 1000
    });

    const displayName = user.u_serial_identifier || user.username;
    res.json({ success: true, username: displayName });
  } catch (e) {
    res.status(500).json({ error: '登录处理异常: ' + e.message });
  }
});

// 3. 用户登出
app.post('/api/auth/logout', async (req, res) => {
  if (req.cookies.sessionId) {
    await Session.deleteOne({ sessionId: req.cookies.sessionId });
  }
  res.clearCookie('sessionId');
  res.json({ success: true });
});

// 4. 当前登录态校验
app.get('/api/auth/me', authMiddleware, (req, res) => {
  const name = req.user.u_serial_identifier || req.user.username;
  res.json({ authenticated: true, username: name });
});

// 5. 抓取课程列表并逐行解析（支持中英混合双引号、单行容错）
app.get('/api/courses', authMiddleware, async (req, res) => {
  try {
    const targetUrl = 'https://studyindex-cg1.pages.dev/list.txt';
    const response = await fetch(targetUrl);
    if (!response.ok) {
      throw new Error(`HTTP 状态异常: ${response.status}`);
    }
    const rawText = await response.text();

    const lines = rawText.split(/\r?\n/);
    const courses = [];
    const quotePattern = `["'“”]`;
    const nameRegex = new RegExp(`NAME\\s*=\\s*${quotePattern}(.*?)${quotePattern}`, 'i');
    const belongRegex = new RegExp(`BELONG_TO\\s*=\\s*${quotePattern}(.*?)${quotePattern}`, 'i');
    const urlRegex = new RegExp(`URL\\s*=\\s*${quotePattern}(.*?)${quotePattern}`, 'i');

    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line) continue;

      const nameMatch = line.match(nameRegex);
      const belongMatch = line.match(belongRegex);
      const urlMatch = line.match(urlRegex);

      if (nameMatch && urlMatch) {
        courses.push({
          name: nameMatch[1].trim(),
          belongTo: belongMatch ? belongMatch[1].trim() : '未分类',
          url: urlMatch[1].trim()
        });
      }
    }

    res.json({ courses });
  } catch (e) {
    console.error('[Fetch Courses Error]', e);
    res.status(500).json({ error: '获取课程列表失败: ' + e.message });
  }
});

// 6. 课程 JSON 代理（防跨域与 GitHub Raw 自动重写）
app.get('/api/course-content', authMiddleware, async (req, res) => {
  try {
    let target = req.query.url;
    if (!target) return res.status(400).json({ error: '缺少 URL 参数' });

    if (target.includes('github.com') && target.includes('/blob/')) {
      target = target.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/');
    }
    const r = await fetch(target);
    if (!r.ok) throw new Error(`Fetch failed with status ${r.status}`);
    res.json(await r.json());
  } catch (e) {
    res.status(500).json({ error: '获取课程内容失败: ' + e.message });
  }
});

// 7. 每日概况与统计
app.get('/api/progress/summary', authMiddleware, async (req, res) => {
  try {
    const userId = req.user._id;
    const lastProgress = await StudyProgress.findOne({ userId }).sort({ updatedAt: -1 });
    const sevenDaysAgo = new Date(Date.now() - 7 * 86400 * 1000);
    const weeklyRecords = await StudyProgress.find({ userId, updatedAt: { $gte: sevenDaysAgo } }).sort({ updatedAt: -1 });
    const all = await StudyProgress.find({ userId });

    res.json({
      lastProgress,
      weeklyRecords,
      allProgressMap: all.reduce((acc, c) => ({ ...acc, [c.courseName]: c }), {})
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 8. 上传章节进度与答题成绩
app.post('/api/progress/update', authMiddleware, async (req, res) => {
  try {
    const { courseName, belongTo, courseUrl, chapterIndex, quizResult } = req.body;
    let p = await StudyProgress.findOne({ userId: req.user._id, courseName });

    if (!p) {
      p = new StudyProgress({
        userId: req.user._id,
        courseName,
        belongTo,
        courseUrl,
        lastChapterIndex: chapterIndex,
        completedChapters: [chapterIndex],
        quizScores: []
      });
    } else {
      p.lastChapterIndex = chapterIndex;
      if (!p.completedChapters.includes(chapterIndex)) p.completedChapters.push(chapterIndex);
    }

    if (quizResult && typeof quizResult.score === 'number') {
      const idx = p.quizScores.findIndex(q => q.chapterIndex === chapterIndex);
      if (idx >= 0) {
        p.quizScores[idx] = { chapterIndex, score: quizResult.score, total: quizResult.total };
      } else {
        p.quizScores.push({ chapterIndex, score: quizResult.score, total: quizResult.total });
      }
    }

    p.updatedAt = new Date();
    await p.save();
    res.json({ success: true, progress: p });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ==================== 静态文件绝对干净托管 ====================
// 使用 res.sendFile 直接向浏览器流式传送 public/index.html，彻底切断 Node.js 对前端模板字符串的解析
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 启动服务
app.listen(PORT, () => {
  console.log(`[JR AI Server] running on http://localhost:${PORT}`);
});
