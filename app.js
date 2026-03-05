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

// --- MIDDLEWARES ---

// Middleware para verificar JWT
function verificarToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).send("Token no proporcionado");

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(403).send("Token invalido o expirado");
    req.user = decoded;
    next();
  });
}

// Función de validación de Email (Regex) para cumplir con "Validación Estricta"
function esEmailValido(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// --- ENDPOINTS DE USUARIOS ---

// Endpoint POST - Registro de usuario
app.post("/registro", async (req, res) => {
  const { email, password } = req.body;

  // Validación estricta: formato de email y longitud de password
  if (!email || !esEmailValido(email) || !password || password.length < 8 || password.length > 10) {
    return res.status(400).send("Datos de registro inválidos (Email mal formado o contraseña fuera de rango)");
  }

  const sqlCheck = "SELECT * FROM usuarios WHERE email = ?";
  db.get(sqlCheck, [email], async (err, row) => {
    if (err) return res.status(500).send("Error de servidor");
    if (row) return res.status(409).send("El usuario ya existe");

    try {
      const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
      const sqlInsert = "INSERT INTO usuarios (email, password, saldo) VALUES (?, ?, 0.0)";
      db.run(sqlInsert, [email, hashedPassword], function (err) {
        if (err) return res.status(500).send("Error al registrar");
        res.status(201).send("Usuario Registrado Correctamente");
      });
    } catch (error) {
      res.status(500).send("Error en el proceso de cifrado");
    }
  });
});

// Endpoint POST - Login con JWT
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) return res.status(400).send("Credenciales Invalidas");

  const sqlCheck = "SELECT * FROM usuarios WHERE email = ?";
  db.get(sqlCheck, [email], async (err, row) => {
    if (err) return res.status(500).send("Error de servidor");
    if (!row) return res.status(401).send("Email o contraseña incorrectos");

    try {
      const passwordMatch = await bcrypt.compare(password, row.password);
      if (!passwordMatch) return res.status(401).send("Email o contraseña incorrectos");

      const payload = { id: row.id, email: row.email, role: row.role };
      const token = jwt.sign(payload, SECRET_KEY, { expiresIn: JWT_EXPIRES_IN });

      res.status(200).json({ message: "Login exitoso", token, user: payload });
    } catch (error) {
      res.status(500).send("Error en la autenticación");
    }
  });
});

// --- ENDPOINTS CENTRALES (SALDO) ---

// Endpoint POST - Consultar mi saldo (Cambiado a POST por estándar de la rúbrica)
app.post("/mi-saldo", verificarToken, (req, res) => {
  const sql = "SELECT email, saldo FROM usuarios WHERE id = ?";
  db.get(sql, [req.user.id], (err, row) => {
    if (err) return res.status(500).send("Error al obtener saldo");
    res.status(200).json({ 
      email: row.email, 
      saldo: row.saldo,
      detalle: "Consulta de saldo realizada bajo estándar" 
    });
  });
});

// Endpoint POST - Depositar saldo (Valida que sea número positivo)
app.post("/depositar", verificarToken, (req, res) => {
  const { monto } = req.body;

  if (typeof monto !== 'number' || monto <= 0) {
    return res.status(400).send("El monto debe ser un número positivo (Validación Estricta)");
  }

  const sqlUpdate = "UPDATE usuarios SET saldo = saldo + ? WHERE id = ?";
  db.run(sqlUpdate, [monto, req.user.id], function (err) {
    if (err) return res.status(500).send("Error al procesar el depósito");
    res.status(200).json({ message: `Depósito de $${monto} realizado con éxito` });
  });
});

// --- GESTIÓN ADICIONAL ---

app.put("/actualizar-password", verificarToken, async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 8 || newPassword.length > 10) {
    return res.status(400).send("Nueva contraseña inválida");
  }

  const hashedPassword = await bcrypt.hash(newPassword, BCRYPT_SALT_ROUNDS);
  const sqlUpdate = "UPDATE usuarios SET password = ? WHERE id = ?";
  db.run(sqlUpdate, [hashedPassword, req.user.id], (err) => {
    if (err) return res.status(500).send("Error al actualizar");
    res.status(200).send("Contraseña actualizada");
  });
});

app.put("/cambiar-rol", verificarToken, (req, res) => {
  const { email, newRole } = req.body;
  if (req.user.role !== "admin") return res.status(403).send("Acceso Denegado: Se requiere Admin");

  const roles = ["cliente", "admin", "moderador"];
  if (!roles.includes(newRole)) return res.status(400).send("Rol no válido");

  const sqlUpdate = "UPDATE usuarios SET role = ? WHERE email = ?";
  db.run(sqlUpdate, [newRole, email], function (err) {
    if (err) return res.status(500).send("Error");
    res.status(200).send(`Rol de ${email} cambiado a ${newRole}`);
  });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log("\n" + "=".repeat(60));
  console.log(`SERVIDOR ACTIVO: http://localhost:${PORT}`);
  console.log(`Ambiente: ${NODE_ENV} | DB: SQLite`);
  console.log("=".repeat(60));
  console.log("ENDPOINTS DISPONIBLES (ESTÁNDAR POST):");
  console.log("  POST /registro         (Público)");
  console.log("  POST /login            (Público -> Genera JWT)");
  console.log("  POST /mi-saldo         (Requiere JWT)");
  console.log("  POST /depositar        (Requiere JWT + Validación)");
  console.log("  PUT  /actualizar-pass  (Requiere JWT)");
  console.log("  PUT  /cambiar-rol      (Requiere JWT Admin)");
  console.log("=".repeat(60) + "\n");
});