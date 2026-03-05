const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./database.db');

db.serialize(() => {
  // Crea la tabla de usuarios con la columna de saldo
  db.run(`CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE, 
    password TEXT NOT NULL, 
    role TEXT DEFAULT 'cliente',
    saldo REAL DEFAULT 0.0
  )`, (err) => {
    if (err) console.error("Error:", err.message);
    else console.log("Tabla 'usuarios' lista con columna de saldo.");
  });
});
db.close();