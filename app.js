// Cargar variables de entorno desde .env
require("dotenv").config();

const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const winston = require("winston");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(express.json());

// Variables de entorno
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || "./database.db";
const SECRET_KEY = process.env.SECRET_KEY;
const BCRYPT_SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 10;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "1h";
const NODE_ENV = process.env.NODE_ENV || "development";

// === CREAR CARPETA LOGS ===
const logDir = path.join(__dirname, "logs");
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir);
}

// === LOGGER ===
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(
      ({ level, message, timestamp }) =>
        `[${level.toUpperCase()}] ${timestamp} - ${message}`
    )
  ),
  transports: [
    new winston.transports.File({
      filename: path.join(logDir, "error.log"),
      level: "error",
    }),
    new winston.transports.File({
      filename: path.join(logDir, "combined.log"),
    }),
  ],
});

// Mostrar en consola también
if (NODE_ENV !== "production") {
  logger.add(new winston.transports.Console());
}

// Validar SECRET_KEY
if (!SECRET_KEY) {
  logger.error("SECRET_KEY no está definida");
  process.exit(1);
}

// Conexión a DB
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    logger.error(`Error DB: ${err.message}`);
  } else {
    logger.info(`Conectado a DB: ${DB_PATH}`);
  }
});

// === LOG AUTOMÁTICO DE TODAS LAS PETICIONES 🔥
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.url}`);
  next();
});

// --- MIDDLEWARE JWT ---
function verificarToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    logger.warn("Acceso sin token");
    return res.status(401).send("Token no proporcionado");
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      logger.warn("Token inválido");
      return res.status(403).send("Token invalido o expirado");
    }

    logger.info(`Token válido usuario ${decoded.id}`);
    req.user = decoded;
    next();
  });
}

// Validaciones
function esEmailValido(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function contieneHTML(texto) {
  return /<[^>]*>/.test(texto);
}

// --- REGISTRO ---
app.post("/registro", async (req, res) => {
  const { email, password } = req.body;

  if (
    !email ||
    !esEmailValido(email) ||
    !password ||
    password.length < 8 ||
    password.length > 10
  ) {
    logger.warn("Registro inválido");
    return res.status(400).send("Datos de registro inválidos");
  }

  if (contieneHTML(email) || contieneHTML(password)) {
    logger.warn("Registro con HTML");
    return res.status(400).send("Datos de registro inválidos");
  }

  db.get("SELECT * FROM usuarios WHERE email = ?", [email], async (err, row) => {
    if (err) {
      logger.error(`Error DB registro: ${err.message}`);
      return res.status(500).send("Error de servidor");
    }

    if (row) {
      logger.warn(`Usuario ya existe: ${email}`);
      return res.status(409).send("El usuario ya existe");
    }

    try {
      const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

      db.run(
        "INSERT INTO usuarios (email, password, saldo) VALUES (?, ?, 0.0)",
        [email, hashedPassword],
        (err) => {
          if (err) {
            logger.error(`Error insert usuario: ${err.message}`);
            return res.status(500).send("Error al registrar");
          }

          logger.info(`Usuario registrado: ${email}`);
          res.status(201).send("Usuario Registrado Correctamente");
        }
      );
    } catch (error) {
      logger.error(`Error hash password: ${error.message}`);
      res.status(500).send("Error en el proceso de cifrado");
    }
  });
});

// --- LOGIN ---
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    logger.warn("Login inválido");
    return res.status(400).send("Credenciales Invalidas");
  }

  db.get("SELECT * FROM usuarios WHERE email = ?", [email], async (err, row) => {
    if (err) {
      logger.error(`Error login: ${err.message}`);
      return res.status(500).send("Error de servidor");
    }

    if (!row) {
      logger.warn(`Usuario no encontrado: ${email}`);
      return res.status(401).send("Email o contraseña incorrectos");
    }

    const match = await bcrypt.compare(password, row.password);

    if (!match) {
      logger.warn(`Password incorrecta: ${email}`);
      return res.status(401).send("Email o contraseña incorrectos");
    }

    const payload = { id: row.id, email: row.email, role: row.role };
    const token = jwt.sign(payload, SECRET_KEY, {
      expiresIn: JWT_EXPIRES_IN,
    });

    logger.info(`Login exitoso: ${email}`);
    res.json({ message: "Login exitoso", token, user: payload });
  });
});

// --- SALDO ---
app.post("/mi-saldo", verificarToken, (req, res) => {
  db.get(
    "SELECT email, saldo FROM usuarios WHERE id = ?",
    [req.user.id],
    (err, row) => {
      if (err) {
        logger.error(`Error saldo: ${err.message}`);
        return res.status(500).send("Error al obtener saldo");
      }

      logger.info(`Consulta saldo usuario ${req.user.id}`);
      res.json(row);
    }
  );
});

// --- DEPOSITAR ---
app.post("/depositar", verificarToken, (req, res) => {
  const { monto } = req.body;

  if (typeof monto !== "number" || monto <= 0) {
    logger.warn(`Monto inválido: ${monto}`);
    return res.status(400).send("Monto inválido");
  }

  db.run(
    "UPDATE usuarios SET saldo = saldo + ? WHERE id = ?",
    [monto, req.user.id],
    (err) => {
      if (err) {
        logger.error(`Error depósito: ${err.message}`);
        return res.status(500).send("Error");
      }

      logger.info(`Depósito ${monto} usuario ${req.user.id}`);
      res.send("Depósito realizado");
    }
  );
});

// --- SERVER ---
app.listen(PORT, () => {
  logger.info(`Servidor corriendo en http://localhost:${PORT}`);
});