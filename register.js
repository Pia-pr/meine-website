const express = require('express');
const bcrypt = require('bcrypt'); // Zum sicheren Hashen der Passwörter
const connectDB = require('./db'); // Unsere DB-Verbindung

const app = express();
app.use(express.json()); // Um JSON-Daten zu verarbeiten

// Registrierung Route
app.post('/register', async (req, res) => {
  const { username, password, passwordConfirm } = req.body;

  // Alle Felder prüfen
  if (!username || !password || !passwordConfirm) {
    return res.status(400).send('Alle Felder sind erforderlich.');
  }

  // Passwörter vergleichen
  if (password !== passwordConfirm) {
    return res.status(400).send('Die Passwörter stimmen nicht überein.');
  }

  // Passwort hashen
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const db = await connectDB();
    const usersCollection = db.collection('users');

    // Benutzer prüfen
    const existingUser = await usersCollection.findOne({ username });
    if (existingUser) {
      return res.status(400).send('Benutzername bereits vergeben.');
    }

    // Benutzer speichern
    await usersCollection.insertOne({ username, password: hashedPassword });

    res.status(201).send('Benutzer erfolgreich registriert.');
  } catch (err) {
    console.error(err);
    res.status(500).send('Fehler beim Speichern des Benutzers.');
  }
});

// Server starten
const port = 3000;
app.listen(port, () => {
  console.log(`Server läuft auf Port ${port}`);
});
