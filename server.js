import express from 'express';
import path from 'path';
import session from 'express-session';
import fs from 'fs';
import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser'; // Für Cookies

const app = express();
const port = 3000;

// Middleware: Formulardaten parsen
app.use(express.urlencoded({ extended: true }));

// Middleware: Cookies analysieren
app.use(cookieParser());

// Session-Setup
app.use(
  session({
    secret: 'meinGeheimnis', // Verwende einen starken, geheimen Schlüssel
    resave: false,
    saveUninitialized: true,
  })
);

// Dummy-Datenbank (JSON-Datei)
const dbPath = './users.json';
if (!fs.existsSync(dbPath)) {
  fs.writeFileSync(dbPath, JSON.stringify([])); // Initialisiere leere Benutzerliste
}

// Dummy-Daten für Benutzer-Registrierung (optional zum Testen)
const defaultUsers = [
  {
    benutzername: 'Pia',
    passwort: bcrypt.hashSync('Pia.1', 10),
  },
];

// Registrierte Benutzer laden
function getUsers() {
  return JSON.parse(fs.readFileSync(dbPath, 'utf8'));
}

// Funktion um Benutzer zu speichern
function saveUser(user) {
  const users = getUsers();
  users.push(user);
  fs.writeFileSync(dbPath, JSON.stringify(users, null, 2)); // Benutzer speichern
}

// Route: Login (POST)
app.post('/login', (req, res) => {
  const { benutzername, passwort, rememberMe } = req.body;

  const users = getUsers();
  const user = users.find((u) => u.benutzername === benutzername);

  if (user && bcrypt.compareSync(passwort, user.passwort)) {
    req.session.isLoggedIn = true;
    req.session.username = benutzername;

    // Wenn "Angemeldet bleiben" aktiviert ist
    if (rememberMe) {
      // Setze ein langfristiges Cookie (30 Tage)
      res.cookie('rememberMe', benutzername, { maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true });
    }

    res.redirect('/Login.html'); // Erfolgreich eingeloggt
  } else {
    res.sendFile(path.resolve('Seiten/Falsch.html')); // Falsche Anmeldedaten
  }
});

// Beim Serverstart überprüfen, ob ein Cookie vorhanden ist
app.use((req, res, next) => {
  // Wenn der Benutzer bereits über das Cookie eingeloggt ist
  if (req.cookies.rememberMe) {
    const users = getUsers();
    const user = users.find((u) => u.benutzername === req.cookies.rememberMe);

    if (user) {
      req.session.isLoggedIn = true;
      req.session.username = user.benutzername;
    }
  }
  next();
});

// Route: Index Seite (GET)
app.get('/', (req, res) => {
  if (req.session.isLoggedIn) {
    res.sendFile(path.resolve('Seiten/Login.html'));
  } else {
    res.sendFile(path.resolve('Seiten/Startseite.html'));
  }
});

// Route: Login-Seite (GET)
app.get('/Login.html', (req, res) => {
  if (!req.session.isLoggedIn) {
    return res.redirect('/');
  }

  if (req.session.username === 'Piaa') {
    // OP sieht eine andere Seite
    res.sendFile(path.resolve('Seiten/Login_OP.html'));
  } else {
    res.sendFile(path.resolve('Seiten/Login.html'));
  }
});

// Route: Liste-Seite (GET)
app.get('/Liste.html', (req, res) => {
  if (req.session.isLoggedIn) {
    res.sendFile(path.resolve('Seiten/Liste.html')); // Nur eingeloggte Benutzer können auf diese Seite zugreifen
  } else {
    res.redirect('/'); // Benutzer wird zur Startseite weitergeleitet, wenn nicht eingeloggt
  }
});
app.get('/Profil.html', (req, res) => {
  if (req.session.isLoggedIn) {
    res.sendFile(path.resolve('Seiten/Profil.html')); // Nur eingeloggte Benutzer können auf diese Seite zugreifen
  } else {
    res.redirect('/'); // Benutzer wird zur Startseite weitergeleitet, wenn nicht eingeloggt
  }
});
app.get('/uebermich.html', (req, res) => {
  if (req.session.isLoggedIn) {
    res.sendFile(path.resolve('Seiten/uebermich.html')); // Nur eingeloggte Benutzer können auf diese Seite zugreifen
  } else {
    res.redirect('/'); // Benutzer wird zur Startseite weitergeleitet, wenn nicht eingeloggt
  }
});


app.post('/register', (req, res) => {
  const { benutzername, passwort, passwortBestätigen } = req.body;

  // Prüfen, ob alle Felder ausgefüllt sind
  if (!benutzername || !passwort || !passwortBestätigen) {
    return res.status(400).send('Alle Felder sind erforderlich.');
  }

  // Prüfen, ob die Passwörter übereinstimmen
  if (passwort !== passwortBestätigen) {
    return res.status(400).send('Die Passwörter stimmen nicht überein.');
  }

  const users = getUsers();
  
  // Prüfen, ob der Benutzername bereits existiert
  const userExists = users.some((u) => u.benutzername === benutzername);
  if (userExists) {
    return res.status(400).send('Benutzername bereits vergeben.');
  }

  // Passwort hashen
  const hashedPassword = bcrypt.hashSync(passwort, 10); // Sicherheit durch Hashing

  // Benutzer speichern
  const user = { benutzername, passwort: hashedPassword };
  saveUser(user);

  res.sendFile(path.resolve('Seiten/Login.html'));
});


// Logout-Route
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('rememberMe'); // Löscht das Cookie
    res.redirect('/'); // Zur Startseite zurückkehren
  });
});

// Weitere Routen für Index und Registrierung (siehe vorheriges Beispiel)

// Statische Dateien (CSS, Bilder, etc.) bereitstellen
app.use(express.static(path.resolve('Seiten')));

// Statische Datei-Route für den Download von Dateien im 'downloads'-Ordner
app.use('/downloads', express.static(path.resolve('downloads')));

// Route: Benutzerdefinierter Download
app.get('/download/:filename', (req, res) => {
  const { filename } = req.params;
  const filePath = path.resolve('downloads', filename);

  // Überprüfen, ob die Datei existiert
  if (fs.existsSync(filePath)) {
    // Datei zum Download bereitstellen
    res.download(filePath, filename, (err) => {
      if (err) {
        console.error('Fehler beim Herunterladen der Datei:', err);
        res.status(500).send('Fehler beim Download der Datei.');
      }
    });
  } else {
    // Datei existiert nicht
    res.status(404).send('Datei nicht gefunden.');
  }
});

// Server starten
app.listen(port, () => {
  console.log(`Server läuft unter http://localhost:${port}`);
});
