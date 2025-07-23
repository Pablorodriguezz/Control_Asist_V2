// database.js (VERSIÓN CON ACTUALIZACIÓN DE REGLAS)
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

if (!process.env.DATABASE_URL) {
    console.error("Error Crítico: La variable de entorno DATABASE_URL no está definida.");
    process.exit(1);
}

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

const init = async () => {
    try {
        console.log('Iniciando conexión y configuración de la base de datos...');
        
        await pool.query(`
            CREATE TABLE IF NOT EXISTS usuarios (
                id SERIAL PRIMARY KEY,
                nombre TEXT NOT NULL,
                usuario TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                rol TEXT NOT NULL, -- Eliminamos el CHECK de aquí para manejarlo dinámicamente
                dias_vacaciones_anuales INTEGER DEFAULT 28
            );
        `);

        // ==========================================================
        // NUEVO: Bloque para actualizar la restricción (constraint) del rol
        // Esto asegura que en cada despliegue, la regla esté actualizada.
        // ==========================================================
        try {
            // 1. Intentamos eliminar la restricción antigua si existe.
            await pool.query(`ALTER TABLE usuarios DROP CONSTRAINT IF EXISTS usuarios_rol_check;`);
            
            // 2. Añadimos la nueva restricción con todos los roles permitidos.
            await pool.query(`
                ALTER TABLE usuarios 
                ADD CONSTRAINT usuarios_rol_check 
                CHECK(rol IN ('empleado', 'admin', 'gestor_vacaciones'));
            `);
            console.log('Restricción de roles actualizada correctamente.');
        } catch (err) {
            console.warn('Advertencia: No se pudo actualizar la restricción de roles. Puede que ya estuviera correcta.', err.message);
        }
        // ==========================================================


        const resColumna = await pool.query(`
            SELECT column_name FROM information_schema.columns 
            WHERE table_name='usuarios' AND column_name='dias_vacaciones_anuales'
        `);
        if (resColumna.rowCount === 0) {
            await pool.query('ALTER TABLE usuarios ADD COLUMN dias_vacaciones_anuales INTEGER DEFAULT 30');
            console.log('Columna "dias_vacaciones_anuales" añadida a la tabla "usuarios" con valor por defecto 30.');
        }

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

                // --- CAMBIO IMPORTANTE: ACTUALIZACIÓN DE LA TABLA VACACIONES ---
        await pool.query(`
            CREATE TABLE IF NOT EXISTS vacaciones (
                id SERIAL PRIMARY KEY,
                usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
                fecha_inicio DATE NOT NULL,
                fecha_fin DATE NOT NULL,
                estado TEXT NOT NULL DEFAULT 'pendiente', -- Ahora el estado por defecto es 'pendiente'
                comentarios TEXT
            );
        `);
        
        // Script para asegurar que la columna 'estado' y la restricción existan y estén actualizadas
        const resColEstado = await pool.query("SELECT 1 FROM information_schema.columns WHERE table_name='vacaciones' AND column_name='estado'");
        if (resColEstado.rowCount === 0) {
            await pool.query("ALTER TABLE vacaciones ADD COLUMN estado TEXT NOT NULL DEFAULT 'pendiente'");
        }
        
        await pool.query("ALTER TABLE vacaciones DROP CONSTRAINT IF EXISTS vacaciones_estado_check;");
        await pool.query("ALTER TABLE vacaciones ADD CONSTRAINT vacaciones_estado_check CHECK(estado IN ('aprobada', 'pendiente', 'rechazada'));");
        console.log('Tabla "vacaciones" actualizada con estados.');

        
        console.log('Tablas (usuarios, registros, vacaciones) verificadas/creadas correctamente.');

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

        console.log('¡Base de datos lista!');

    } catch (err) {
        console.error('Error fatal durante la inicialización de la base de datos:', err.stack);
        process.exit(1); 
    }
};

module.exports = {
    query: (text, params) => pool.query(text, params),
    init: init,
};