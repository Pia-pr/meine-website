import pkg from 'pg';
import 'dotenv/config';

const { Pool } = pkg;

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// 🟢 Automatische Initialisierung der Datenbank
export async function initializeDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        benutzername TEXT PRIMARY KEY,
        passwort TEXT NOT NULL,
        login_history TEXT[]
      );
    `);
    console.log('✅ Datenbank initialisiert (Tabelle users vorhanden oder neu erstellt)');
  } catch (err) {
    console.error('❌ Fehler bei der Datenbank-Initialisierung:', err);
    throw err;
  }
}

export async function getUsers() {
  try {
    const res = await pool.query('SELECT * FROM users');
    return res.rows;
  } catch (err) {
    console.error('Fehler bei getUsers:', err);
    throw err;
  }
}

export async function getUserByUsername(username) {
  try {
    const res = await pool.query(
      'SELECT * FROM users WHERE benutzername = $1',
      [username]
    );
    return res.rows[0];
  } catch (err) {
    console.error('Fehler bei getUserByUsername:', err);
    throw err;
  }
}

export async function addUser(benutzername, passwort) {
  try {
    await pool.query(
      'INSERT INTO users (benutzername, passwort, login_history) VALUES ($1, $2, $3)',
      [benutzername, passwort, []]
    );
  } catch (err) {
    console.error('Fehler bei addUser:', err);
    throw err;
  }
}

export async function updateLastLogin(username, time) {
  try {
    await pool.query(
      `UPDATE users
       SET login_history = array_append(login_history, $2)
       WHERE benutzername = $1`,
      [username, time]
    );
  } catch (err) {
    console.error('Fehler bei updateLastLogin:', err);
    throw err;
  }
}

export async function deleteUserByUsername(benutzername) {
  try {
    await pool.query(
      'DELETE FROM users WHERE benutzername = $1',
      [benutzername]
    );
  } catch (err) {
    console.error('Fehler bei deleteUserByUsername:', err);
    throw err;
  }
}
