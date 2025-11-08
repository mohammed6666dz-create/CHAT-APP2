import dotenv from 'dotenv';
import express from 'express';
import http from 'http';
import cors from 'cors';
import helmet from 'helmet';
import bodyParser from 'body-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { nanoid } from 'nanoid';
import { Server as SocketIOServer } from 'socket.io';

dotenv.config();

const app = express();
app.use(helmet());
app.use(cors());
app.use(bodyParser.json({ limit: '1mb' }));

const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST', 'PUT']
  }
});

const { PORT = 4000, JWT_SECRET } = process.env;

if (!JWT_SECRET) {
  console.error('JWT_SECRET is required');
  process.exit(1);
}

const usersById = new Map();
const usersByUsername = new Map();
const messages = [];

const createToken = user =>
  jwt.sign({ sub: user.id, username: user.username }, JWT_SECRET, { expiresIn: '12h' });

const toPublicUser = user => ({
  id: user.id,
  username: user.username,
  profile: user.profile
});

const sanitizeProfile = profile => ({
  displayName: typeof profile?.displayName === 'string' ? profile.displayName : '',
  bio: typeof profile?.bio === 'string' ? profile.bio : '',
  avatarUrl: typeof profile?.avatarUrl === 'string' ? profile.avatarUrl : ''
});

const authenticate = (req, res, next) => {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const token = header.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = usersById.get(payload.sub);
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
  }
};

app.post('/auth/register', (req, res) => {
  const { username, password, profile = {} } = req.body || {};
  if (typeof username !== 'string' || username.trim().length < 3) {
    return res.status(400).json({ error: 'Invalid username' });
  }
  if (typeof password !== 'string' || password.length < 6) {
    return res.status(400).json({ error: 'Invalid password' });
  }
  const normalizedUsername = username.trim().toLowerCase();
  if (usersByUsername.has(normalizedUsername)) {
    return res.status(409).json({ error: 'User already exists' });
  }
  const user = {
    id: nanoid(),
    username: username.trim(),
    passwordHash: bcrypt.hashSync(password, 10),
    profile: sanitizeProfile(profile)
  };
  usersById.set(user.id, user);
  usersByUsername.set(normalizedUsername, user);
  const token = createToken(user);
  res.status(201).json({ token, user: toPublicUser(user) });
});

app.post('/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid credentials' });
  }
  const normalizedUsername = username.trim().toLowerCase();
  const user = usersByUsername.get(normalizedUsername);
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = createToken(user);
  res.json({ token, user: toPublicUser(user) });
});

app.get('/profile', authenticate, (req, res) => {
  res.json({ user: toPublicUser(req.user) });
});

app.put('/profile', authenticate, (req, res) => {
  const incomingProfile = req.body?.profile || {};
  const currentProfile = req.user.profile;
  const updatedProfile = {
    displayName:
      typeof incomingProfile.displayName === 'string'
        ? incomingProfile.displayName
        : currentProfile.displayName,
    bio:
      typeof incomingProfile.bio === 'string'
        ? incomingProfile.bio
        : currentProfile.bio,
    avatarUrl:
      typeof incomingProfile.avatarUrl === 'string'
        ? incomingProfile.avatarUrl
        : currentProfile.avatarUrl
  };
  req.user.profile = updatedProfile;
  res.json({ user: toPublicUser(req.user) });
});

const extractSocketToken = socket => {
  if (typeof socket.handshake.auth?.token === 'string') {
    return socket.handshake.auth.token;
  }
  const header = socket.handshake.headers?.authorization;
  if (typeof header === 'string' && header.startsWith('Bearer ')) {
    return header.slice(7);
  }
  return null;
};

io.use((socket, next) => {
  const token = extractSocketToken(socket);
  if (!token) {
    return next(new Error('Unauthorized'));
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = usersById.get(payload.sub);
    if (!user) {
      return next(new Error('Unauthorized'));
    }
    socket.user = user;
    next();
  } catch {
    next(new Error('Unauthorized'));
  }
});

io.on('connection', socket => {
  socket.emit('chat:history', messages.slice(-50));
  socket.on('chat:message', payload => {
    const text = typeof payload?.text === 'string' ? payload.text.trim() : '';
    if (!text) {
      return;
    }
    const message = {
      id: nanoid(),
      userId: socket.user.id,
      username: socket.user.username,
      text,
      timestamp: new Date().toISOString()
    };
    messages.push(message);
    if (messages.length > 1000) {
      messages.shift();
    }
    io.emit('chat:message', message);
  });
});
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// اجعل مجلد public يستضيف الملفات الثابتة
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
