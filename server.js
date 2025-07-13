import express from 'express';
import path from 'path';
import session from 'express-session';
import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
dotenv.config();

import { getUsers, getUserByUsername, addUser, updateLastLogin } from './db.js';

const app = express();
const port = 3000;

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(
  session({
    secret: 'meinGeheimnis',
    resave: false,
    saveUninitialized: true,
  })
);

// Middleware: Cookie "rememberMe" prüfen und Session setzen
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

// Login Route (POST)
app.post('/login', async (req, res) => {
  const { benutzername, passwort, rememberMe } = req.body;
  const user = await getUserByUsername(benutzername);

  if (user && bcrypt.compareSync(passwort, user.passwort)) {
    req.session.isLoggedIn = true;
    req.session.username = benutzername;

    // Login-Zeit speichern
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
    return res.sendFile(path.resolve('Seiten/Falsch.html'));
  }
});

// Startseite
app.get('/', (req, res) => {
  if (req.session.isLoggedIn) {
    return res.redirect('/Login.html');
  }
  res.sendFile(path.resolve('Seiten/Startseite.html'));
});

// Login-Seite (GET)
app.get('/Login.html', (req, res) => {
  if (!req.session.isLoggedIn) {
    return res.redirect('/');
  }

  if (req.session.username === 'Piaa') {
    return res.sendFile(path.resolve('Seiten/Login_OP.html'));
  } else {
    return res.sendFile(path.resolve('Seiten/Login.html'));
  }
});

// API: Alle Benutzer abrufen (nur für OP)
app.get('/api/users', async (req, res) => {
  if (!req.session.isLoggedIn || req.session.username !== 'Piaa') {
    return res.status(403).json({ error: 'Nicht erlaubt' });
  }
  const users = await getUsers();
  res.json(users);
});

// Registrierung (POST)
app.post('/register', async (req, res) => {
  const { benutzername, passwort, passwortBestätigen } = req.body;
  if (!benutzername || !passwort || !passwortBestätigen) {
    return res.status(400).send('Alle Felder sind erforderlich.');
  }
  if (passwort !== passwortBestätigen) {
    return res.status(400).send('Die Passwörter stimmen nicht überein.');
  }

  const existingUser = await getUserByUsername(benutzername);
  if (existingUser) {
    return res.status(400).send('Benutzername bereits vergeben.');
  }

  const hashedPassword = bcrypt.hashSync(passwort, 10);
  await addUser(benutzername, hashedPassword);

  res.sendFile(path.resolve('Seiten/Login.html'));
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('rememberMe');
    res.redirect('/');
  });
});

// OP-Seite (nur für OP)
app.get('/OP.html', (req, res) => {
  if (!req.session.isLoggedIn || req.session.username !== 'Piaa') {
    return res.redirect('/');
  }
  res.sendFile(path.resolve('Seiten/OP.html'));
});

// Weitere geschützte Seiten
const protectedPages = ['Liste.html', 'Profil.html', 'uebermich.html'];
protectedPages.forEach((page) => {
  app.get(`/${page}`, (req, res) => {
    if (!req.session.isLoggedIn) {
      return res.redirect('/');
    }
    res.sendFile(path.resolve('Seiten', page));
  });
});

// Statische Dateien
app.use(express.static(path.resolve('Seiten')));
app.use('/downloads', express.static(path.resolve('downloads')));

// Download-Route
app.get('/download/:filename', (req, res) => {
  const { filename } = req.params;
  const filePath = path.resolve('downloads', filename);

  if (fs.existsSync(filePath)) {
    res.download(filePath, filename, (err) => {
      if (err) {
        console.error('Fehler beim Download:', err);
        res.status(500).send('Fehler beim Download der Datei.');
      }
    });
  } else {
    res.status(404).send('Datei nicht gefunden.');
  }
});

app.listen(port, () => {
  console.log(`Server läuft unter http://localhost:${port}`);
});
