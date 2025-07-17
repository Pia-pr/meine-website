import express from 'express';
import path from 'path';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { pool, getUsers, getUserByUsername, addUser, updateLastLogin, deleteUserByUsername } from './db.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json()); // Für JSON Body parsing
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
    try {
      const user = await getUserByUsername(req.cookies.rememberMe);
      if (user) {
        req.session.isLoggedIn = true;
        req.session.username = user.benutzername;
      }
    } catch (err) {
      console.error('Fehler beim Auto-Login:', err);
    }
  }
  next();
});

// POST: Login
app.post('/login', async (req, res) => {
  const { benutzername, passwort, rememberMe } = req.body;
  try {
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
  } catch (err) {
    console.error('Fehler beim Login:', err);
    res.status(500).send('Serverfehler');
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

  try {
    const existing = await getUserByUsername(benutzername);
    if (existing) {
      return res.status(400).send('Benutzername bereits vergeben.');
    }

    const hashed = bcrypt.hashSync(passwort, 10);
    await addUser(benutzername, hashed);

    res.sendFile(path.resolve(__dirname, 'Seiten/Login.html'));
  } catch (err) {
    console.error('Fehler bei der Registrierung:', err);
    res.status(500).send('Serverfehler bei der Registrierung.');
  }
});

// GET: Letzte 5 Logins pro Benutzer (nur für OP)
app.get('/api/logins', async (req, res) => {
  if (!req.session.isLoggedIn || req.session.username !== 'Piaa') {
    return res.status(403).send('Nicht erlaubt');
  }

  try {
    const users = await getUsers();
    const logins = users.map(user => ({
      benutzername: user.benutzername,
      login_history: user.login_history || []
    }));
    res.json(logins);
  } catch (err) {
    console.error('Fehler beim Laden der Logins:', err);
    res.status(500).send('Fehler beim Laden der Logins');
  }
});


// Benutzer auflisten (nur OP)
app.get('/api/users', async (req, res) => {
  if (!req.session.isLoggedIn || req.session.username !== 'Piaa') {
    return res.status(403).send('Nicht erlaubt');
  }
  try {
    const users = await getUsers();
    res.json(users.map(u => ({ benutzername: u.benutzername })));
  } catch (err) {
    console.error('Fehler beim Abrufen der Benutzer:', err);
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
    await addUser(benutzername, hashedPassword);
    res.status(201).send('Benutzer hinzugefügt');
  } catch (err) {
    if (err.code === '23505') {
      res.status(400).send('Benutzername bereits vergeben');
    } else {
      console.error('Fehler beim Hinzufügen:', err);
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
    await deleteUserByUsername(benutzername);
    res.send('Benutzer gelöscht');
  } catch (err) {
    console.error('Fehler beim Löschen:', err);
    res.status(500).send('Fehler beim Löschen');
  }
});
// Passwort ändern (für alle Benutzer erlaubt – nur OP darf UI sehen)
app.post('/api/users/:benutzername/passwort', async (req, res) => {
  const { benutzername } = req.params;
  const { neuesPasswort } = req.body;

  if (!req.session.isLoggedIn || req.session.username !== 'Piaa') {
    return res.status(403).send('Nicht erlaubt');
  }

  if (!neuesPasswort || neuesPasswort.length < 4) {
    return res.status(400).send('Ungültiges Passwort');
  }

  try {
    const hashed = bcrypt.hashSync(neuesPasswort, 10);
    await pool.query(
      'UPDATE users SET passwort = $1 WHERE benutzername = $2',
      [hashed, benutzername]
    );
    res.send('Passwort aktualisiert');
  } catch (err) {
    console.error('Fehler beim Passwort-Update:', err);
    res.status(500).send('Fehler beim Aktualisieren des Passworts');
  }
});


// OP-Seite
app.get('/OP.html', (req, res) => {
  if (!req.session.isLoggedIn || req.session.username !== 'Piaa') {
    return res.redirect('/');
  }
  res.sendFile(path.resolve(__dirname, 'Seiten/OP.html'));
});

// Login-Seite mit Zugriffssteuerung
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

// Geschützte Seiten
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

// Datei-Download
app.get('/download/:filename', (req, res) => {
  const { filename } = req.params;
  const filePath = path.resolve(__dirname, 'downloads', filename);

  res.download(filePath, filename, err => {
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
