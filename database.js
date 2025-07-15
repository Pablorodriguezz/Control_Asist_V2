// database.js (VERSIÓN PARA RAILWAY)
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

// Railway nos dará la ruta en una variable de entorno. Si no existe, usamos la carpeta local.
const dataDir = process.env.RAILWAY_VOLUME_MOUNT_PATH || __dirname;
const dbPath = path.join(dataDir, 'asistencia.db');

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error("Error al abrir la base de datos:", err.message);
    } else {
        console.log(`Conectado a la base de datos en: ${dbPath}`);
    }
});

// El resto de tu código original se queda exactamente igual
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        usuario TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        rol TEXT NOT NULL CHECK(rol IN ('empleado', 'admin'))
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS registros (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER,
    fecha_hora DATETIME NOT NULL,
    tipo TEXT NOT NULL CHECK(tipo IN ('entrada', 'salida')),
    foto_path TEXT,
    
    -- Nuevos campos para la auditoría --
    es_modificado BOOLEAN DEFAULT 0,
    fecha_hora_original DATETIME,
    modificado_por_admin_id INTEGER,
    fecha_modificacion DATETIME,
    motivo_modificacion TEXT,

    FOREIGN KEY (usuario_id) REFERENCES usuarios (id) ON DELETE CASCADE,
    FOREIGN KEY (modificado_por_admin_id) REFERENCES usuarios (id)
)`);

    const adminUser = 'admin';
    const adminPass = 'admin123';
    db.get('SELECT * FROM usuarios WHERE usuario = ?', [adminUser], (err, row) => {
        if (!row) {
            bcrypt.hash(adminPass, 10, (err, hash) => {
                db.run('INSERT INTO usuarios (nombre, usuario, password, rol) VALUES (?, ?, ?, ?)',
                    ['Administrador', adminUser, hash, 'admin']
                );
            });
        }
    });
});

module.exports = db;