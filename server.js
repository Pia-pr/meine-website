// --- Imports ---
import express from 'express';
import path from 'path';
import session from 'express-session';
import fs from 'fs';
import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

// --- Setup ---
const app = express();
const port = 3000;
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const dbPath = './users.json';

// --- Middleware ---
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(session({
  secret: 'meinGeheimnis',
  resave: false,
  saveUninitialized: true,
}));
app.use(express.static(path.resolve('Seiten')));
app.use('/downloads', express.static(path.resolve('downloads')));

// --- Helper Functions ---
if (!fs.existsSync(dbPath)) fs.writeFileSync(dbPath, JSON.stringify([]));

function getUsers() {
  return JSON.parse(fs.readFileSync(dbPath, 'utf8'));
}

function saveAllUsers(users) {
  fs.writeFileSync(dbPath, JSON.stringify(users, null, 2));
}

function saveUser(user) {
  const users = getUsers();
  users.push(user);
  saveAllUsers(users);
}

// --- Persistent Login Middleware ---
app.use((req, res, next) => {
  if (req.cookies.rememberMe && !req.session.isLoggedIn) {
    const users = getUsers();
    const user = users.find(u => u.benutzername === req.cookies.rememberMe);
    if (user) {
      req.session.isLoggedIn = true;
      req.session.username = user.benutzername;
    }
  }
  next();
});

// --- Auth Routes ---
app.post('/login', (req, res) => {
  const { benutzername, passwort, rememberMe } = req.body;
  const users = getUsers();
  const user = users.find(u => u.benutzername === benutzername);

  if (user && bcrypt.compareSync(passwort, user.passwort)) {
    user.lastLogin = new Date().toISOString();
    saveAllUsers(users);

    req.session.isLoggedIn = true;
    req.session.username = benutzername;

    if (rememberMe) {
      res.cookie('rememberMe', benutzername, {
        maxAge: 30 * 24 * 60 * 60 * 1000,
        httpOnly: true
      });
    }

    res.redirect('/Login.html');
  } else {
    res.sendFile(path.resolve('Seiten/Falsch.html'));
  }
});

app.post('/register', (req, res) => {
  const { benutzername, passwort, passwortBestätigen } = req.body;
  if (!benutzername || !passwort || !passwortBestätigen) {
    return res.status(400).send('Alle Felder sind erforderlich.');
  }
  if (passwort !== passwortBestätigen) {
    return res.status(400).send('Die Passwörter stimmen nicht überein.');
  }

  const users = getUsers();
  if (users.some(u => u.benutzername === benutzername)) {
    return res.status(400).send('Benutzername bereits vergeben.');
  }

  const hashedPassword = bcrypt.hashSync(passwort, 10);
  const user = { benutzername, passwort: hashedPassword };
  saveUser(user);

  res.sendFile(path.resolve('Seiten/Login.html'));
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('rememberMe');
    res.redirect('/');
  });
});

// --- Page Routes ---
app.get('/', (req, res) => {
  if (req.session.isLoggedIn) {
    res.sendFile(path.resolve('Seiten/Login.html'));
  } else {
    res.sendFile(path.resolve('Seiten/Startseite.html'));
  }
});

app.get('/Login.html', (req, res) => {
  if (!req.session.isLoggedIn) return res.redirect('/');
  if (req.session.username === 'Piaa') {
    res.sendFile(path.resolve('Seiten/Login_OP.html'));
  } else {
    res.sendFile(path.resolve('Seiten/Login.html'));
  }
});

app.get('/OP.html', (req, res) => {
  if (!req.session.isLoggedIn || req.session.username !== 'Piaa') {
    return res.redirect('/');
  }
  res.sendFile(path.resolve('Seiten/OP.html'));
});

const protectedPages = ['Liste.html', 'Profil.html', 'uebermich.html'];
protectedPages.forEach(page => {
  app.get(`/${page}`, (req, res) => {
    if (req.session.isLoggedIn) {
      res.sendFile(path.resolve(`Seiten/${page}`));
    } else {
      res.redirect('/');
    }
  });
});

// --- OP API: Zeige letzte Logins ---
app.get('/api/logins', (req, res) => {
  if (!req.session.isLoggedIn || req.session.username !== 'Piaa') {
    return res.status(403).send('Nicht erlaubt');
  }
  const users = getUsers();
  const logins = users.map(u => ({
    benutzername: u.benutzername,
    lastLogin: u.lastLogin || 'Nie'
  }));
  res.json(logins);
});

// --- Datei-Download Route ---
app.get('/download/:filename', (req, res) => {
  const filePath = path.resolve('downloads', req.params.filename);
  if (fs.existsSync(filePath)) {
    res.download(filePath);
  } else {
    res.status(404).send('Datei nicht gefunden.');
  }
});

// --- Server starten ---
app.listen(port, () => {
  console.log(`Server läuft unter http://localhost:${port}`);
});
