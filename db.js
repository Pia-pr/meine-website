import pkg from 'pg';
const { Pool } = pkg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // wichtig für Render
});

export async function getUsers() {
  const res = await pool.query('SELECT * FROM users');
  return res.rows;
}

export async function getUserByUsername(username) {
  const res = await pool.query('SELECT * FROM users WHERE benutzername = $1', [username]);
  return res.rows[0];
}

export async function addUser(benutzername, passwort) {
  await pool.query(
    'INSERT INTO users (benutzername, passwort, login_history) VALUES ($1, $2, $3)',
    [benutzername, passwort, []]
  );
}

export async function updateLastLogin(username, time) {
  await pool.query(
    `UPDATE users
     SET login_history = array_append(login_history, $2)
     WHERE benutzername = $1`,
    [username, time]
  );
}
