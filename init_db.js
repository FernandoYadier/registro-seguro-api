  const sqlite3 = require('sqlite3').verbose();

  // base de datos
  const db = new sqlite3.Database('./database.db');

  db.serialize(() => {
  const sql = `CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE, 
    password TEXT NOT NULL, 
    role TEXT DEFAULT 'cliente'
  )`;

    db.run(sql, (err) => {
      if (err) {
        console.error("Error al crear la tabla:", err.message);
      } else {
        console.log(" Base de datos y tabla 'usuarios' creadas correctamente.");
      }
    });
  });

  db.close();