/**
 * JR AI - Study Hub Core Server
 */
const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const axios = require('axios');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  console.error('[Error] MONGODB_URI is not defined in environment variables!');
  process.exit(1);
}

// 基础中间件
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ==================== MongoDB 架构设计 ====================
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('[DB] MongoDB Connected Successfully'))
  .catch(err => console.error('[DB] Connection Error:', err));

// 用户集合
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  passwordHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

// Session 集合 (带自动过期 TTL)
const SessionSchema = new mongoose.Schema({
  sessionId: { type: String, unique: true, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now, expires: '7d' } // 7天过期
});

// 学习进度与测验集合
const ProgressSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  courseName: { type: String, required: true },
  belongTo: { type: String, required: true },
  chapterId: { type: String, required: true },
  completed: { type: Boolean, default: false },
  quizScore: { type: Number, default: 0 },
  quizAnswers: { type: Object, default: {} },
  updatedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Session = mongoose.model('Session', SessionSchema);
const Progress = mongoose.model('Progress', ProgressSchema);

// ==================== 身份验证中间件 ====================
async function authMiddleware(req, res, next) {
  const sessionId = req.cookies.sid;
  if (!sessionId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  try {
    const session = await Session.findOne({ sessionId }).populate('userId');
    if (!session || !session.userId) {
      res.clearCookie('sid');
      return res.status(401).json({ success: false, message: 'Session 已失效，请重新登录' });
    }
    req.user = session.userId;
    next();
  } catch (err) {
    return res.status(500).json({ success: false, message: '认证服务异常' });
  }
}

// ==================== 用户认证 API ====================
app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, message: '账号或密码不能为空' });
  }

  try {
    const existing = await User.findOne({ username });
    if (existing) {
      return res.status(400).json({ success: false, message: '该用户名已被注册' });
    }
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    await User.create({ username, passwordHash });
    res.json({ success: true, message: '注册成功，请直接登录' });
  } catch (err) {
    res.status(500).json({ success: false, message: '注册失败，请稍后再试' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ success: false, message: '用户不存在' });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: '密码错误' });
    }

    // 生成随机高强度 Session ID
    const sessionId = crypto.randomBytes(32).toString('hex');
    await Session.create({ sessionId, userId: user._id });

    // 存储 Session ID 到 HTTP-Only Cookie 中
    res.cookie('sid', sessionId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7天
    });

    res.json({ success: true, user: { username: user.username } });
  } catch (err) {
    res.status(500).json({ success: false, message: '登录异常' });
  }
});

app.post('/api/auth/logout', async (req, res) => {
  const sessionId = req.cookies.sid;
  if (sessionId) {
    await Session.deleteOne({ sessionId });
    res.clearCookie('sid');
  }
  res.json({ success: true, message: '已安全登出' });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  res.json({ success: true, user: { username: req.user.username } });
});

// ==================== 学习内容拉取与解析 ====================
// 解析 list.txt 格式: NAME="...",BELONG_TO="...",URL="..."
function parseCourseList(rawText) {
  const lines = rawText.split('\n');
  const list = [];
  const regex = /NAME=["“](.*?)["”]\s*,\s*BELONG_TO=["“](.*?)["”]\s*,\s*URL=["“](.*?)["”]/i;

  for (let line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const match = trimmed.match(regex);
    if (match) {
      list.push({
        name: match[1],
        belongTo: match[2],
        url: match[3]
      });
    }
  }
  return list;
}

app.get('/api/courses', authMiddleware, async (req, res) => {
  try {
    const response = await axios.get('https://studyindex.pages.dev/list.txt', { timeout: 8000 });
    const courses = parseCourseList(response.data);

    // 查询该用户已有的学习概况
    const userProgress = await Progress.find({ userId: req.user._id });
    const progressMap = {};
    userProgress.forEach(p => {
      if (!progressMap[p.courseName]) progressMap[p.courseName] = [];
      progressMap[p.courseName].push(p);
    });

    const enrichedCourses = courses.map(course => {
      const records = progressMap[course.name] || [];
      const completedCount = records.filter(r => r.completed).length;
      return {
        ...course,
        recordsCount: records.length,
        completedCount
      };
    });

    res.json({ success: true, courses: enrichedCourses });
  } catch (err) {
    console.error('[Course List Fetch Error]:', err.message);
    res.status(500).json({ success: false, message: '无法获取课程列表' });
  }
});

// 代理读取课程源代码与交互 JSON
app.get('/api/course/content', authMiddleware, async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ success: false, message: '缺少课程 URL' });

  try {
    // 自动将 GitHub Blob 转换为 raw 格式（若适用）
    let targetUrl = url;
    if (targetUrl.includes('github.com') && targetUrl.includes('/blob/')) {
      targetUrl = targetUrl.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/');
    }

    const response = await axios.get(targetUrl, { timeout: 10000 });
    res.json({ success: true, data: response.data });
  } catch (err) {
    res.status(500).json({ success: false, message: '读取课程资源失败' });
  }
});

// ==================== 进度存储与仪表盘统计 ====================
// 上报答题情况与完成状态
app.post('/api/progress/save', authMiddleware, async (req, res) => {
  const { courseName, belongTo, chapterId, completed, quizScore, quizAnswers } = req.body;

  try {
    const record = await Progress.findOneAndUpdate(
      { userId: req.user._id, courseName, chapterId },
      {
        belongTo,
        completed,
        quizScore,
        quizAnswers,
        updatedAt: new Date()
      },
      { upsert: true, new: true }
    );

    res.json({ success: true, record });
  } catch (err) {
    res.status(500).json({ success: false, message: '进度保存失败' });
  }
});

// 获取“每日概况”：断点续学 + 本周成果
app.get('/api/dashboard/overview', authMiddleware, async (req, res) => {
  try {
    // 1. 最近一次学习项目（断点续学）
    const lastSession = await Progress.findOne({ userId: req.user._id })
      .sort({ updatedAt: -1 });

    // 2. 本周成果（近7天）
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

    const weeklyRecords = await Progress.find({
      userId: req.user._id,
      updatedAt: { $gte: sevenDaysAgo }
    });

    const completedThisWeek = weeklyRecords.filter(r => r.completed).length;
    const avgScore = weeklyRecords.length > 0 
      ? Math.round(weeklyRecords.reduce((acc, cur) => acc + (cur.quizScore || 0), 0) / weeklyRecords.length)
      : 0;

    res.json({
      success: true,
      lastSession: lastSession || null,
      weeklyStats: {
        totalInteractions: weeklyRecords.length,
        completedChapters: completedThisWeek,
        avgScore
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: '获取看板数据失败' });
  }
});

// 启动服务
app.listen(PORT, () => {
  console.log(`[JR AI Server] Running on http://localhost:${PORT}`);
});
