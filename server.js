import express from 'express';
import path from 'path';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import {
  getUsers,
  getUserByUsername,
  addUser,
  updateLastLogin
} from './db.js';
import dotenv from 'dotenv';
dotenv.config({ path: '/etc/secrets/.env' });


dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(
  session({
    secret: 'meinGeheimnis',
    resave: false,
    saveUninitialized: true,
  })
);

// Middleware: Auto-Login durch Cookie
app.use(async (req, res, next) => {
  if (!req.session.isLoggedIn && req.cookies.rememberMe) {
    const user = await getUserByUsername(req.cookies.rememberMe);
    if (user) {
      req.session.isLoggedIn = true;
      req.session.username = user.benutzername;
    }
  }
  next();
});

// POST: Login
app.post('/login', async (req, res) => {
  const { benutzername, passwort, rememberMe } = req.body;
  const user = await getUserByUsername(benutzername);

  if (user && bcrypt.compareSync(passwort, user.passwort)) {
    req.session.isLoggedIn = true;
    req.session.username = benutzername;

    const now = new Date().toISOString();
    await updateLastLogin(benutzername, now);

    if (rememberMe) {
      res.cookie('rememberMe', benutzername, {
        maxAge: 30 * 24 * 60 * 60 * 1000,
        httpOnly: true,
      });
    }

    return res.redirect('/Login.html');
  } else {
    return res.sendFile(path.resolve(__dirname, 'Seiten/Falsch.html'));
  }
});

// POST: Registrierung
app.post('/register', async (req, res) => {
  const { benutzername, passwort, passwortBestätigen } = req.body;

  if (!benutzername || !passwort || !passwortBestätigen) {
    return res.status(400).send('Alle Felder sind erforderlich.');
  }

  if (passwort !== passwortBestätigen) {
    return res.status(400).send('Passwörter stimmen nicht überein.');
  }

  const existing = await getUserByUsername(benutzername);
  if (existing) {
    return res.status(400).send('Benutzername bereits vergeben.');
  }

  const hashed = bcrypt.hashSync(passwort, 10);
  await addUser(benutzername, hashed);

  res.sendFile(path.resolve(__dirname, 'Seiten/Login.html'));
});

// GET: Login-Logs (nur für OP)
app.get('/api/logins', async (req, res) => {
  if (!req.session.isLoggedIn || req.session.username !== 'Piaa') {
    return res.status(403).send('Nicht erlaubt');
  }

  const users = await getUsers();
  const logins = users.map(user => ({
    benutzername: user.benutzername,
    lastLogin: (user.login_history?.slice(-1)[0]) || 'Nie',
  }));
  res.json(logins);
});

// OP-Seite
app.get('/OP.html', (req, res) => {
  if (!req.session.isLoggedIn || req.session.username !== 'Piaa') {
    return res.redirect('/');
  }
  res.sendFile(path.resolve(__dirname, 'Seiten/OP.html'));
});

// Benutzer auflisten (nur OP)
app.get('/api/users', async (req, res) => {
  if (!req.session.isLoggedIn || req.session.username !== 'Piaa') {
    return res.status(403).send('Nicht erlaubt');
  }
  try {
    const result = await pool.query('SELECT benutzername FROM users ORDER BY benutzername ASC');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Fehler beim Abrufen der Benutzer');
  }
});

// Benutzer hinzufügen (nur OP)
app.post('/api/users', async (req, res) => {
  if (!req.session.isLoggedIn || req.session.username !== 'Piaa') {
    return res.status(403).send('Nicht erlaubt');
  }
  const { benutzername, passwort } = req.body;
  if (!benutzername || !passwort) {
    return res.status(400).send('Benutzername und Passwort erforderlich');
  }
  try {
    const hashedPassword = bcrypt.hashSync(passwort, 10);
    await pool.query(
      'INSERT INTO users (benutzername, passwort, login_history) VALUES ($1, $2, $3)',
      [benutzername, hashedPassword, []]
    );
    res.status(201).send('Benutzer hinzugefügt');
  } catch (err) {
    if (err.code === '23505') {
      res.status(400).send('Benutzername bereits vergeben');
    } else {
      console.error(err);
      res.status(500).send('Fehler beim Hinzufügen');
    }
  }
});

// Benutzer löschen (nur OP, Piaa kann nicht gelöscht werden)
app.delete('/api/users/:benutzername', async (req, res) => {
  const { benutzername } = req.params;
  if (!req.session.isLoggedIn || req.session.username !== 'Piaa') {
    return res.status(403).send('Nicht erlaubt');
  }
  if (benutzername === 'Piaa') {
    return res.status(400).send('OP-Benutzer kann nicht gelöscht werden');
  }
  try {
    await pool.query('DELETE FROM users WHERE benutzername = $1', [benutzername]);
    res.send('Benutzer gelöscht');
  } catch (err) {
    console.error(err);
    res.status(500).send('Fehler beim Löschen');
  }
});


// Login-Routing
app.get('/Login.html', (req, res) => {
  if (!req.session.isLoggedIn) {
    return res.redirect('/');
  }

  if (req.session.username === 'Piaa') {
    return res.sendFile(path.resolve(__dirname, 'Seiten/Login_OP.html'));
  } else {
    return res.sendFile(path.resolve(__dirname, 'Seiten/Login.html'));
  }
});

// Statische Seiten
['Profil.html', 'uebermich.html', 'Liste.html'].forEach(page => {
  app.get(`/${page}`, (req, res) => {
    if (!req.session.isLoggedIn) {
      return res.redirect('/');
    }
    res.sendFile(path.resolve(__dirname, 'Seiten', page));
  });
});

// Startseite
app.get('/', (req, res) => {
  res.sendFile(path.resolve(__dirname, 'Seiten/Startseite.html'));
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('rememberMe');
    res.redirect('/');
  });
});

// Downloads
app.use('/downloads', express.static(path.resolve(__dirname, 'downloads')));

// Dateien zum Download anbieten
app.get('/download/:filename', (req, res) => {
  const { filename } = req.params;
  const filePath = path.resolve(__dirname, 'downloads', filename);

  res.download(filePath, filename, (err) => {
    if (err) {
      console.error('Fehler beim Download:', err);
      res.status(500).send('Fehler beim Herunterladen.');
    }
  });
});

// Statische Dateien
app.use(express.static(path.resolve(__dirname, 'Seiten')));

// Server starten
app.listen(port, () => {
  console.log(`Server läuft auf http://localhost:${port}`);
});
