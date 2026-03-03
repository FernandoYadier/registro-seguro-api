// Cargar variables de entorno desde .env
require("dotenv").config();

const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

// Variables de entorno desde .env
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || "./database.db";
const SECRET_KEY = process.env.SECRET_KEY;
const BCRYPT_SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 10;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "1h";
const NODE_ENV = process.env.NODE_ENV || "development";

// Validar que existe la SECRET_KEY
if (!SECRET_KEY) {
  console.error("ERROR: SECRET_KEY no está definida en el archivo .env");
  console.error("Crea un archivo .env con: SECRET_KEY=tu_clave_secreta");
  process.exit(1);
}

// Conexión a la base de datos
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error("Error al conectar con la base de datos:", err);
  } else {
    console.log("Conectado a la base de datos:", DB_PATH);
  }
});

// Endpoint POST - Registro de usuario
app.post("/registro", async (req, res) => {
  const { email, password } = req.body;

  // Valida la longitud
  if (!email || !password || password.length < 8 || password.length > 10) {
    return res.status(400).send("Credenciales Invalidas");
  }

  // Verifica si el usuario ya existe
  const sqlCheck = "SELECT * FROM usuarios WHERE email = ?";
  db.get(sqlCheck, [email], async (err, row) => {
    if (err) return res.status(500).send("Error de servidor");

    if (row) {
      return res.status(409).send("El usuario ya existe");
    }

    try {
      // Cifra la contraseña con bcrypt usando SALT_ROUNDS del .env
      const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

      const sqlInsert = "INSERT INTO usuarios (email, password) VALUES (?, ?)";
      db.run(sqlInsert, [email, hashedPassword], function (err) {
        if (err) return res.status(500).send("Error al registrar");

        console.log(`Usuario registrado: ${email}`);
        res.status(201).send("Usuario Registrado");
      });
    } catch (error) {
      console.error("Error en cifrado:", error);
      res.status(500).send("Error en el proceso de cifrado");
    }
  });
});

// Endpoint POST - Login con JWT
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).send("Credenciales Invalidas");
  }

  const sqlCheck = "SELECT * FROM usuarios WHERE email = ?";
  db.get(sqlCheck, [email], async (err, row) => {
    if (err) {
      console.error("Error en la BD:", err);
      return res.status(500).send("Error de servidor");
    }

    if (!row) {
      console.log(`Usuario no encontrado: ${email}`);
      return res.status(401).send("Email o contraseña incorrectos");
    }

    try {
      const passwordMatch = await bcrypt.compare(password, row.password);

      if (!passwordMatch) {
        console.log(` Contraseña incorrecta para: ${email}`);
        return res.status(401).send("Email o contraseña incorrectos");
      }

      console.log(`\n Credenciales válidas para: ${email}`);
      console.log("Datos del usuario:", {
        id: row.id,
        email: row.email,
        role: row.role,
      });

      const payload = {
        id: row.id,
        email: row.email,
        role: row.role,
      };

      console.log("PAYLOAD creado:", payload);

      const token = jwt.sign(payload, SECRET_KEY, {
        expiresIn: JWT_EXPIRES_IN,
      });

      console.log("TOKEN JWT generado:");
      console.log(token);
      console.log(`Expira en: ${JWT_EXPIRES_IN}\n`);

      res.status(200).json({
        message: "Login exitoso",
        token: token,
        user: {
          id: row.id,
          email: row.email,
          role: row.role,
        },
      });
    } catch (error) {
      console.error("Error en autenticación:", error);
      res.status(500).send("Error en el proceso de autenticación");
    }
  });
});

// Middleware para verificar JWT
function verificarToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).send("Token no proporcionado");
  }

  // Verificar token usando SECRET_KEY del .env
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      console.log("Token inválido o expirado");
      return res.status(403).send("Token invalido o expirado");
    }

    req.user = decoded;
    next();
  });
}

// Endpoint PUT - Actualizar contraseña
app.put("/actualizar-password", verificarToken, async (req, res) => {
  const { newPassword } = req.body;
  const email = req.user.email;

  if (!newPassword || newPassword.length < 8 || newPassword.length > 10) {
    return res.status(400).send("Credenciales Invalidas");
  }

  try {
    const hashedPassword = await bcrypt.hash(newPassword, BCRYPT_SALT_ROUNDS);

    const sqlUpdate = "UPDATE usuarios SET password = ? WHERE email = ?";
    db.run(sqlUpdate, [hashedPassword, email], function (err) {
      if (err) return res.status(500).send("Error al actualizar contraseña");

      console.log(`Contraseña actualizada para: ${email}`);
      res.status(200).send("Contraseña actualizada exitosamente");
    });
  } catch (error) {
    console.error("Error en cifrado:", error);
    res.status(500).send("Error en el proceso de cifrado");
  }
});

// Endpoint PUT - Cambiar rol
app.put("/cambiar-rol", verificarToken, (req, res) => {
  const { email, newRole } = req.body;

  if (req.user.role !== "admin") {
    return res.status(403).send("No tienes permisos para cambiar roles");
  }

  if (!email || !newRole) {
    return res.status(400).send("Datos invalidos");
  }

  const rolesPermitidos = ["cliente", "admin", "moderador"];
  if (!rolesPermitidos.includes(newRole)) {
    return res
      .status(400)
      .send("Rol invalido. Use: cliente, admin o moderador");
  }

  const sqlCheck = "SELECT * FROM usuarios WHERE email = ?";
  db.get(sqlCheck, [email], (err, row) => {
    if (err) return res.status(500).send("Error de servidor");

    if (!row) {
      return res.status(404).send("Usuario no encontrado");
    }

    const sqlUpdate = "UPDATE usuarios SET role = ? WHERE email = ?";
    db.run(sqlUpdate, [newRole, email], function (err) {
      if (err) return res.status(500).send("Error al cambiar rol");

      console.log(`Rol actualizado: ${email} → ${newRole}`);
      res.status(200).send(`Rol actualizado a '${newRole}' exitosamente`);
    });
  });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log("\n" + "=".repeat(60));
  console.log(`Servidor activo en http://localhost:${PORT}`);
  console.log(`Ambiente: ${NODE_ENV}`);
  console.log(`JWT expira en: ${JWT_EXPIRES_IN}`);
  console.log(`Bcrypt salt rounds: ${BCRYPT_SALT_ROUNDS}`);
  console.log("=".repeat(60));
  console.log("\nEndpoints disponibles:");
  console.log("   POST   /registro");
  console.log("   POST   /login       Genera JWT");
  console.log("   PUT    /actualizar-password   Requiere JWT");
  console.log("   PUT    /cambiar-rol           Requiere JWT (Admin)");
  console.log("=".repeat(60) + "\n");
});
