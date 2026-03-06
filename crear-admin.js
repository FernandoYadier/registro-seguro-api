// Script para crear el primer usuario ADMIN

require("dotenv").config();
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");

const db = new sqlite3.Database(process.env.DB_PATH || "./database.db");
const BCRYPT_SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 10;

// Datos del admin
const adminEmail = "admin@gmail.com";
const adminPassword = "admin12345";

async function crearAdmin() {
  try {
    db.get(
      "SELECT * FROM usuarios WHERE email = ?",
      [adminEmail],
      async (err, row) => {
        if (err) {
          console.error("Error al verificar usuario:", err);
          db.close();
          return;
        }

        if (row) {
          console.log("El usuario " + adminEmail + " ya existe.");
          console.log(
            "Si quieres cambiar su rol a admin, usa el siguiente comando:",
          );
          console.log("");
          console.log(
            'UPDATE usuarios SET role = "admin" WHERE email = "' +
              adminEmail +
              '";',
          );
          db.close();
          return;
        }

        const hashedPassword = await bcrypt.hash(
          adminPassword,
          BCRYPT_SALT_ROUNDS,
        );

        const sql =
          "INSERT INTO usuarios (email, password, role, saldo) VALUES (?, ?, ?, ?)";
        db.run(sql, [adminEmail, hashedPassword, "admin", 0.0], function (err) {
          if (err) {
            console.error("Error al crear admin:", err);
          } else {
            console.log("");
            console.log("¡Usuario ADMIN creado exitosamente!");
            console.log("");
            console.log("Email:    " + adminEmail);
            console.log("Password: " + adminPassword);
            console.log("Rol:      admin");
            console.log("");
            console.log("Ahora puedes hacer login con estas credenciales:");
            console.log("");
            console.log("POST http://localhost:3000/login");
            console.log(
              JSON.stringify(
                {
                  email: adminEmail,
                  password: adminPassword,
                },
                null,
                2,
              ),
            );
            console.log("");
          }
          db.close();
        });
      },
    );
  } catch (error) {
    console.error("Error:", error);
    db.close();
  }
}

// Ejecutar
console.log("");
console.log("CREANDO USUARIO ADMINISTRADOR...");
console.log("");
crearAdmin();
