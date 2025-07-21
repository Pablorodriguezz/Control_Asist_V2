// database.js (VERSIÓN PARA POSTGRESQL EN RAILWAY)
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

// Railway proporciona automáticamente la URL de conexión en esta variable de entorno
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false // Requerido para conexiones a bases de datos en la nube como la de Railway
    }
});

console.log('Conectando a la base de datos PostgreSQL...');

const initializeDatabase = async () => {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS usuarios (
                id SERIAL PRIMARY KEY,
                nombre TEXT NOT NULL,
                usuario TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                rol TEXT NOT NULL CHECK(rol IN ('empleado', 'admin'))
            );
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS registros (
                id SERIAL PRIMARY KEY,
                usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
                fecha_hora TIMESTAMPTZ NOT NULL,
                tipo TEXT NOT NULL CHECK(tipo IN ('entrada', 'salida')),
                foto_path TEXT,
                es_modificado BOOLEAN DEFAULT FALSE,
                fecha_hora_original TIMESTAMPTZ,
                modificado_por_admin_id INTEGER REFERENCES usuarios(id),
                fecha_modificacion TIMESTAMPTZ,
                motivo_modificacion TEXT
            );
        `);
        
        console.log('Tablas "usuarios" y "registros" verificadas/creadas.');

        // Crear usuario admin si no existe
        const adminUser = 'admin';
        const adminPass = 'admin123';
        const res = await pool.query('SELECT * FROM usuarios WHERE usuario = $1', [adminUser]);

        if (res.rowCount === 0) {
            const hash = await bcrypt.hash(adminPass, 10);
            await pool.query(
                'INSERT INTO usuarios (nombre, usuario, password, rol) VALUES ($1, $2, $3, $4)',
                ['Administrador', adminUser, hash, 'admin']
            );
            console.log('Usuario administrador creado.');
        }

    } catch (err) {
        console.error('Error al inicializar la base de datos:', err.stack);
    }
};

// Ejecutar la inicialización
initializeDatabase();

// Exportamos el pool para poder hacer consultas desde server.js
module.exports = {
    query: (text, params) => pool.query(text, params),
};