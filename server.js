import express from 'express';
import path from 'path';
import session from 'express-session';
import fs from 'fs';
import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';

const app = express();
const port = 3000;

// Middleware: Formulardaten parsen
app.use(express.urlencoded({ extended: true }));

// Middleware: Cookies analysieren
app.use(cookieParser());

// Session-Setup
app.use(
  session({
    secret: 'meinGeheimnis', // unbedingt geheim halten!
    resave: false,
    saveUninitialized: true,
  })
);

// Dummy-Datenbank (JSON-Datei)
const dbPath = './users.json';
if (!fs.existsSync(dbPath)) {
  fs.writeFileSync(dbPath, JSON.stringify([]));
}

// Benutzer laden
function getUsers() {
  return JSON.parse(fs.readFileSync(dbPath, 'utf8'));
}

// Benutzer speichern (hinzufügen)
function saveUser(user) {
  const users = getUsers();
  users.push(user);
  fs.writeFileSync(dbPath, JSON.stringify(users, null, 2));
}

// Middleware: Cookie "rememberMe" prüfen und Session setzen
app.use((req, res, next) => {
  if (!req.session.isLoggedIn && req.cookies.rememberMe) {
    const users = getUsers();
    const user = users.find(u => u.benutzername === req.cookies.rememberMe);
    if (user) {
      req.session.isLoggedIn = true;
      req.session.username = user.benutzername;
    }
  }
  next();
});

// Login Route (POST)
app.post('/login', (req, res) => {
  const { benutzername, passwort, rememberMe } = req.body;
  const users = getUsers();
  const user = users.find(u => u.benutzername === benutzername);

  if (user && bcrypt.compareSync(passwort, user.passwort)) {
    req.session.isLoggedIn = true;
    req.session.username = benutzername;

    // Login-Zeit speichern
    user.lastLogin = new Date().toISOString();
    fs.writeFileSync(dbPath, JSON.stringify(users, null, 2));

    // "Remember me" Cookie setzen
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
    // OP-Benutzer sieht eigene Seite
    return res.sendFile(path.resolve('Seiten/Login_OP.html'));
  } else {
    return res.sendFile(path.resolve('Seiten/Login.html'));
  }
});

// API: Login-Logs nur für OP (Piaa)
app.get('/api/logins', (req, res) => {
  if (!req.session.isLoggedIn || req.session.username !== 'Piaa') {
    return res.status(403).send('Nicht erlaubt');
  }
  const users = getUsers();
  const logins = users.map(u => ({
    benutzername: u.benutzername,
    lastLogin: u.lastLogin || 'Nie',
  }));
  res.json(logins);
});

// OP-Seite (nur für Piaa)
app.get('/OP.html', (req, res) => {
  if (!req.session.isLoggedIn || req.session.username !== 'Piaa') {
    return res.redirect('/');
  }
  res.sendFile(path.resolve('Seiten/OP.html'));
});

// Weitere Seiten (nur für eingeloggte Nutzer)
const protectedPages = ['Liste.html', 'Profil.html', 'uebermich.html'];
protectedPages.forEach((page) => {
  app.get(`/${page}`, (req, res) => {
    if (!req.session.isLoggedIn) {
      return res.redirect('/');
    }
    res.sendFile(path.resolve('Seiten', page));
  });
});

// Registrierung (POST)
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

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('rememberMe');
    res.redirect('/');
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

// Server starten
app.listen(port, () => {
  console.log(`Server läuft unter http://localhost:${port}`);
});
