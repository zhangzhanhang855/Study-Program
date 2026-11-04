require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://aleafs%40aliyun.com:Xl32cVfKQ6SJ@120.55.50.18:27017/CorporateDB?authSource=admin';

app.use(express.json());
app.use(cookieParser());

// --- 数据库模型 ---
// 将字段正式统一为 username 与 password，开启 strict: false 兼容老字段
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
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

// --- 鉴权路由 ---
// 1. 注册：以 password 字段名存入密文
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password || password.length < 6) {
      return res.status(400).json({ error: '用户名与密码必填，且密码长度需不少于 6 位' });
    }
    
    if (await User.findOne({ username })) {
      return res.status(400).json({ error: '该用户名已存在' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ username, password: hashedPassword });

    const sessionId = crypto.randomUUID();
    await Session.create({ sessionId, userId: user._id });

    res.cookie('sessionId', sessionId, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 7 * 86400 * 1000
    });
    
    res.json({ success: true, username: user.username });
  } catch (e) {
    res.status(500).json({ error: '注册失败: ' + e.message });
  }
});

// 2. 登录：平滑兼容 password、passwordHash 及明文
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: '请填写完整的用户名和密码' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: '用户不存在' });
    }

    // 兼容取值：优先读取 password，备选读取历史字段 passwordHash 或 pwd
    const storedSecret = user.password || user.passwordHash || user.pwd;
    if (!storedSecret) {
      return res.status(500).json({ error: '此账号尚未录入有效密码字段，请重新注册' });
    }

    let isMatch = false;
    try {
      // 尝试按 bcrypt 哈希算法进行比对
      isMatch = await bcrypt.compare(password, storedSecret);
    } catch (bcryptErr) {
      // 容错：如果数据库历史录入的是纯明文密码，做兜底匹配
      isMatch = (password === storedSecret);
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

    res.json({ success: true, username: user.username });
  } catch (e) {
    res.status(500).json({ error: '登录处理异常: ' + e.message });
  }
});

app.post('/api/auth/logout', async (req, res) => {
  if (req.cookies.sessionId) {
    await Session.deleteOne({ sessionId: req.cookies.sessionId });
  }
  res.clearCookie('sessionId');
  res.json({ success: true });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  res.json({ authenticated: true, username: req.user.username });
});

// --- 列表与内容代理 ---
app.get('/api/courses', authMiddleware, async (req, res) => {
  try {
    const r = await fetch('https://studyindex-cg1.pages.dev/list.txt');
    const text = await r.text();
    const regex = /NAME\s*=\s*["“”](.*?)["“”]\s*,\s*BELONG_TO\s*=\s*["“”](.*?)["“”]\s*,\s*URL\s*=\s*["“”](.*?)["“”]/g;
    const courses = [];
    let m;
    while ((m = regex.exec(text)) !== null) {
      courses.push({ name: m[1].trim(), belongTo: m[2].trim(), url: m[3].trim() });
    }
    res.json({ courses });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/course-content', authMiddleware, async (req, res) => {
  try {
    let target = req.query.url;
    if (target.includes('github.com') && target.includes('/blob/')) {
      target = target.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/');
    }
    const r = await fetch(target);
    res.json(await r.json());
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// --- 学习进度存取 ---
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

// --- 前端静态托管 ---
app.get('/', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>JR AI 智能研学中枢</title>
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Google+Sans:wght@400;500;700&display=swap">
  <style>
    :root { --bg: #0c0f14; --card: rgba(26,32,44,0.65); --border: rgba(255,255,255,0.1); --blue: #3b82f6; --text: #f3f4f6; --sub: #9ca3af; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--text); font-family: 'Google Sans', sans-serif; min-height: 100vh; display: flex; flex-direction: column; }
    header { backdrop-filter: blur(20px); background: rgba(12,15,20,0.7); border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; padding: 16px 32px; position: sticky; top: 0; z-index: 50; }
    main { flex: 1; max-width: 1100px; width: 100%; margin: 0 auto; padding: 32px 24px; }
    .glass { background: var(--card); backdrop-filter: blur(16px); border: 1px solid var(--border); border-radius: 16px; padding: 24px; }
    .btn { background: var(--blue); color: #fff; border: none; padding: 10px 18px; border-radius: 8px; cursor: pointer; font-weight: 600; }
    .btn-ghost { background: transparent; border: 1px solid var(--border); color: var(--sub); padding: 6px 12px; border-radius: 8px; cursor: pointer; }
    .overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.85); backdrop-filter: blur(20px); display: flex; align-items: center; justify-content: center; z-index: 100; }
    .input { width: 100%; background: rgba(0,0,0,0.3); border: 1px solid var(--border); border-radius: 8px; padding: 10px; color: #fff; margin-bottom: 14px; outline: none; }
    .card-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 16px; margin-top: 14px; }
    .course-item { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 16px; cursor: pointer; transition: 0.2s; }
    .course-item:hover { transform: translateY(-3px); border-color: rgba(255,255,255,0.3); }
    .quiz-opt { background: rgba(255,255,255,0.04); border: 1px solid var(--border); padding: 12px; border-radius: 8px; margin-top: 8px; cursor: pointer; }
    .quiz-opt.selected { border-color: var(--blue); background: rgba(59,130,246,0.2); }
  </style>
</head>
<body>
  <header>
    <div style="font-weight:700;">JR AI 学研终端</div>
    <div>
      <span id="userNameDisplay">检测中...</span>
      <button class="btn-ghost" id="logoutBtn" style="display:none; margin-left:12px;" onclick="logout()">登出</button>
    </div>
  </header>

  <div class="overlay" id="authModal" style="display:none;">
    <div class="glass" style="max-width:360px; width:100%;">
      <h3 id="authTitle" style="margin-bottom:12px;">访问会话验证</h3>
      <input type="text" id="username" class="input" placeholder="用户名" />
      <input type="password" id="password" class="input" placeholder="密码" />
      <button class="btn" style="width:100%;" onclick="submitAuth()">确认登录</button>
      <div style="margin-top:12px; text-align:center;">
        <a href="javascript:void(0)" onclick="toggleReg()" style="color:var(--blue); font-size:0.85rem;" id="regToggleText">没有账号？点击注册</a>
      </div>
    </div>
  </div>

  <main id="portal">
    <div class="glass" style="margin-bottom:24px;">
      <h3 style="margin-bottom:8px;">📌 每日概况</h3>
      <div id="resumeBox" style="color:var(--sub);">正在获取进度...</div>
    </div>
    <h3>课程图谱</h3>
    <div id="courseList" class="card-grid"></div>
  </main>

  <main id="study" style="display:none;">
    <button class="btn-ghost" onclick="exitStudy()" style="margin-bottom:16px;">← 返回目录</button>
    <div class="glass">
      <h2 id="studyTitle"></h2>
      <div id="chapterIndex" style="color:var(--sub); font-size:0.9rem; margin: 8px 0 16px 0;"></div>
      <div id="studyContent" style="line-height:1.7;"></div>
      <div id="quizArea" style="margin-top:20px;"></div>
      <div style="margin-top:24px; display:flex; justify-content:space-between;">
        <button class="btn-ghost" id="prevBtn" onclick="moveChapter(-1)">上一节</button>
        <button class="btn" id="nextBtn" onclick="moveChapter(1)">完成并同步</button>
      </div>
    </div>
  </main>

  <script>
    let isReg = false, activeCourse = null, courseData = null, chIdx = 0, curAns = null;

    window.onload = checkAuth;

    async function checkAuth() {
      try {
        const res = await fetch('/api/auth/me');
        if (res.ok) {
          const d = await res.json();
          document.getElementById('userNameDisplay').innerText = '学员: ' + d.username;
          document.getElementById('logoutBtn').style.display = 'inline-block';
          document.getElementById('authModal').style.display = 'none';
          initDashboard();
        } else {
          document.getElementById('authModal').style.display = 'flex';
        }
      } catch(e) { document.getElementById('authModal').style.display = 'flex'; }
    }

    function toggleReg() {
      isReg = !isReg;
      document.getElementById('authTitle').innerText = isReg ? '注册新学员' : '访问会话验证';
      document.getElementById('regToggleText').innerText = isReg ? '已有账号？去登录' : '没有账号？点击注册';
    }

    async function submitAuth() {
      const u = document.getElementById('username').value.trim();
      const p = document.getElementById('password').value.trim();
      const ep = isReg ? '/api/auth/register' : '/api/auth/login';
      const r = await fetch(ep, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ username: u, password: p }) });
      if (r.ok) location.reload();
      else alert((await r.json()).error);
    }

    async function logout() {
      await fetch('/api/auth/logout', { method: 'POST' });
      location.reload();
    }

    async function initDashboard() {
      const [sumRes, curRes] = await Promise.all([fetch('/api/progress/summary'), fetch('/api/courses')]);
      const { lastProgress } = await sumRes.json();
      const { courses } = await curRes.json();

      document.getElementById('resumeBox').innerHTML = lastProgress
        ? '上次学到 <strong>' + lastProgress.courseName + '</strong>（第 ' + (lastProgress.lastChapterIndex + 1) + ' 节）'
        : '暂无进行中的科目，请在下方点击开启。';

      const wrap = document.getElementById('courseList');
      wrap.innerHTML = '';
      courses.forEach(c => {
        const d = document.createElement('div');
        d.className = 'course-item';
        d.innerHTML = '<span style="font-size:0.75rem; color:#60a5fa;">' + c.belongTo + '</span><h4 style="margin-top:6px;">' + c.name + '</h4>';
        d.onclick = () => startCourse(c);
        wrap.appendChild(d);
      });
    }

    async function startCourse(c) {
      activeCourse = c;
      const r = await fetch('/api/course-content?url=' + encodeURIComponent(c.url));
      courseData = await r.json();
      chIdx = 0;
      document.getElementById('portal').style.display = 'none';
      document.getElementById('study').style.display = 'block';
      document.getElementById('studyTitle').innerText = c.name;
      renderCh();
    }

    function renderCh() {
      const ch = courseData.chapters[chIdx];
      document.getElementById('chapterIndex').innerText = '第 ' + (chIdx + 1) + ' / ' + courseData.chapters.length + ' 节：' + ch.title;
      document.getElementById('studyContent').innerHTML = ch.content;
      curAns = null;

      const qBox = document.getElementById('quizArea');
      qBox.innerHTML = '';
      if (ch.quiz) {
        qBox.innerHTML = '<strong>随堂测验：' + ch.quiz.question + '</strong>';
        ch.quiz.options.forEach((opt, i) => {
          const o = document.createElement('div');
          o.className = 'quiz-opt';
          o.innerText = opt;
          o.onclick = () => {
            qBox.querySelectorAll('.quiz-opt').forEach(el => el.classList.remove('selected'));
            o.classList.add('selected');
            curAns = i;
          };
          qBox.appendChild(o);
        });
      }
      document.getElementById('prevBtn').disabled = (chIdx === 0);
    }

    async function moveChapter(dir) {
      const ch = courseData.chapters[chIdx];
      let score = null;
      if (ch.quiz && curAns !== null) {
        score = { score: curAns === ch.quiz.answerIndex ? 100 : 0, total: 100 };
      }
      await fetch('/api/progress/update', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({
          courseName: activeCourse.name,
          belongTo: activeCourse.belongTo,
          courseUrl: activeCourse.url,
          chapterIndex: chIdx,
          quizResult: score
        })
      });

      const next = chIdx + dir;
      if (next >= 0 && next < courseData.chapters.length) {
        chIdx = next;
        renderCh();
      } else if (next >= courseData.chapters.length) {
        alert('恭喜完成本科目！');
        exitStudy();
      }
    }

    function exitStudy() {
      document.getElementById('study').style.display = 'none';
      document.getElementById('portal').style.display = 'block';
      initDashboard();
    }
  </script>
</body>
</html>`);
});

app.listen(PORT, () => console.log('[JR AI Server] running on http://localhost:' + PORT));
