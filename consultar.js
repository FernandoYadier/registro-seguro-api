  const sqlite3 = require('sqlite3').verbose();
  const db = new sqlite3.Database('./database.db');

  db.all("SELECT id, email, password, role FROM usuarios", [], (err, rows) => {
  if (err) throw err;
  console.table(rows);
  db.close();
  });