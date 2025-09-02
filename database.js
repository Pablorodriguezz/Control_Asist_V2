const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

if (!process.env.DATABASE_URL) {
    console.error("Error Crítico: La variable de entorno DATABASE_URL no está definida.");
    process.exit(1);
}

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

const init = async () => {
    try {
        console.log('Iniciando conexión y configuración de la base de datos...');
        
        // --- CREACIÓN/ACTUALIZACIÓN DE LA TABLA usuarios ---
        await pool.query(`
            CREATE TABLE IF NOT EXISTS usuarios (
                id SERIAL PRIMARY KEY,
                nombre TEXT NOT NULL,
                usuario TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                rol TEXT NOT NULL,
                dias_vacaciones_anuales INTEGER DEFAULT 20,
                dias_compensatorios INTEGER DEFAULT 0 NOT NULL,
                fecha_contratacion DATE
            );
        `);

        // --- SCRIPT PARA AÑADIR dias_compensatorios SI NO EXISTE ---
        const resColComp = await pool.query("SELECT 1 FROM information_schema.columns WHERE table_name='usuarios' AND column_name='dias_compensatorios'");
        if (resColComp.rowCount === 0) {
            await pool.query("ALTER TABLE usuarios ADD COLUMN dias_compensatorios INTEGER DEFAULT 0 NOT NULL");
            console.log('Columna "dias_compensatorios" añadida a la tabla usuarios.');
        }
        
        // --- SCRIPT PARA AÑADIR fecha_contratacion SI NO EXISTE ---
        const resColContratacion = await pool.query("SELECT 1 FROM information_schema.columns WHERE table_name='usuarios' AND column_name='fecha_contratacion'");
        if (resColContratacion.rowCount === 0) {
            await pool.query("ALTER TABLE usuarios ADD COLUMN fecha_contratacion DATE");
            console.log('Columna "fecha_contratacion" añadida a la tabla usuarios.');
        }

        await pool.query(`ALTER TABLE usuarios ALTER COLUMN dias_vacaciones_anuales SET DEFAULT 20;`);
        console.log('Valor por defecto de "dias_vacaciones_anuales" asegurado en 20.');

        try {
            await pool.query(`ALTER TABLE usuarios DROP CONSTRAINT IF EXISTS usuarios_rol_check;`);
            await pool.query(`ALTER TABLE usuarios ADD CONSTRAINT usuarios_rol_check CHECK(rol IN ('empleado', 'admin', 'gestor_vacaciones'));`);
            console.log('Restricción de roles actualizada correctamente.');
        } catch (err) {
            console.warn('Advertencia al actualizar restricción de roles:', err.message);
        }

        // --- CREACIÓN DE OTRAS TABLAS ---
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

        await pool.query(`
            CREATE TABLE IF NOT EXISTS vacaciones (
                id SERIAL PRIMARY KEY,
                usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
                fecha_inicio DATE NOT NULL,
                fecha_fin DATE NOT NULL,
                estado TEXT NOT NULL DEFAULT 'pendiente',
                comentarios TEXT
            );
        `);
        
        const resColEstado = await pool.query("SELECT 1 FROM information_schema.columns WHERE table_name='vacaciones' AND column_name='estado'");
        if (resColEstado.rowCount === 0) {
            await pool.query("ALTER TABLE vacaciones ADD COLUMN estado TEXT NOT NULL DEFAULT 'pendiente'");
        }
        
        await pool.query("ALTER TABLE vacaciones DROP CONSTRAINT IF EXISTS vacaciones_estado_check;");
        await pool.query("ALTER TABLE vacaciones ADD CONSTRAINT vacaciones_estado_check CHECK(estado IN ('aprobada', 'pendiente', 'rechazada'));");
        console.log('Tabla "vacaciones" actualizada con estados.');

        // --- NUEVO: CREACIÓN DE LA TABLA DE JUSTIFICANTES ---
        await pool.query(`
            CREATE TABLE IF NOT EXISTS justificantes (
                id SERIAL PRIMARY KEY,
                usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
                fecha_inicio DATE NOT NULL,
                fecha_fin DATE NOT NULL,
                motivo TEXT,
                archivo_path VARCHAR(255) NOT NULL,
                fecha_subida TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('Tabla "justificantes" asegurada.');

        await pool.query(`
            CREATE TABLE IF NOT EXISTS nominas (
                id SERIAL PRIMARY KEY,
                usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
                mes INTEGER NOT NULL CHECK (mes >= 1 AND mes <= 12),
                anio INTEGER NOT NULL,
                nombre_archivo VARCHAR(255) NOT NULL,
                archivo_path VARCHAR(512) NOT NULL,
                fecha_subida TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(usuario_id, mes, anio) -- Un empleado solo puede tener una nómina por mes/año
            );
        `);
        console.log("Tabla 'nominas' asegurada y lista.");

        
        
        // --- CREACIÓN DEL USUARIO ADMIN POR DEFECTO ---
        const adminUser = 'admin';
        const adminPass = 'admin123';
        const res = await pool.query('SELECT * FROM usuarios WHERE usuario = $1', [adminUser]);
        if (res.rowCount === 0) {
            const hash = await bcrypt.hash(adminPass, 10);
            await pool.query(
                'INSERT INTO usuarios (nombre, usuario, password, rol, fecha_contratacion) VALUES ($1, $2, $3, $4, $5)',
                ['Administrador', adminUser, hash, 'admin', new Date().toISOString().split('T')[0]]
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