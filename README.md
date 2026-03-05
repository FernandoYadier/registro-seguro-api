Requisitos de Instalación

Clonar el repositorio:
git clone <enlace-del-repo>
cd registro-seguro-api

Instalar dependencias:
npm install

Configurar Variables de Entorno:
Crea un archivo .env en la raíz.

Inicializar la Base de Datos:

Ejecuta el script para crear las tablas con la estructura de saldos:
node init_db.js

Iniciar el Servidor:
node app.js


Guía de Pruebas (Postman)

1. Registro de Usuario

Método: POST

URL: /registro


Body (JSON): {"email": "usuario@test.com", "password": "password123"}

3. Login (Obtener Token)
   
Método: POST

URL: /login

Acción: Copiar el token recibido para las siguientes pruebas.

4. Depositar Saldo (Endpoint Central)

Método: POST

URL: /depositar

Auth: Seleccionar Bearer Token y pegar el JWT.

Body (JSON): {"monto": 100.50}

5. Consultar Saldo

Método: POST

URL: /mi-saldo

Auth: Bearer Token.

Body (JSON): {} (Obligatorio enviar llaves vacías).
