// server.js (COMPLETO CON LÓGICA DE DÍAS LABORABLES)
const express = require('express');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const db = require('./database.js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Parser } = require('json2csv');
const { DateTime } = require('luxon');
const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");
const crypto = require('crypto');

// En server.js, pégalo después de la línea de 'crypto'

const calcularBalance = async (usuarioId, anioActual) => {
    const resUsuario = await db.query('SELECT dias_vacaciones_anuales, dias_compensatorios, fecha_contratacion FROM usuarios WHERE id = $1', [usuarioId]);
    if (resUsuario.rowCount === 0) throw new Error('Usuario no encontrado');
    
    const usuario = resUsuario.rows[0];
    let diasAnualesBase = usuario.dias_vacaciones_anuales || 20;

    // Prorrateo de días si el usuario fue contratado este año
    if (usuario.fecha_contratacion && new Date(usuario.fecha_contratacion).getFullYear() === anioActual) {
        const fechaInicio = DateTime.fromJSDate(new Date(usuario.fecha_contratacion));
        const finDeAnio = DateTime.fromObject({ year: anioActual, month: 12, day: 31 });
        const diasTrabajados = finDeAnio.diff(fechaInicio, 'days').toObject().days + 1;
        const diasDelAnio = DateTime.fromObject({ year: anioActual }).isInLeapYear ? 366 : 365;
        const diasProrrateados = (diasTrabajados / diasDelAnio) * (usuario.dias_vacaciones_anuales || 20);
        // Redondear al medio día más cercano (e.g., 10.3 -> 10.5, 10.1 -> 10.0)
        diasAnualesBase = Math.round(diasProrrateados * 2) / 2;
    }

    const compensatorios = usuario.dias_compensatorios || 0;
    const diasTotales = diasAnualesBase + compensatorios;
    return diasTotales;
};

// --- NUEVA FUNCIÓN ---
// Calcula solo días de Lunes a Viernes
const calcularDiasLaborables = (fechaInicio, fechaFin) => {
    let start = DateTime.fromISO(fechaInicio);
    const end = DateTime.fromISO(fechaFin);
    let count = 0;
    while (start <= end) {
        // weekday: 1 es Lunes, 7 es Domingo
        if (start.weekday >= 1 && start.weekday <= 5) {
            count++;
        }
        start = start.plus({ days: 1 });
    }
    return count;
};

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'tu_secreto_super_secreto_y_largo_y_dificil_de_adivinar_987654';

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

app.get('/', (req, res) => {
    res.status(200).send('OK: Health check passed');
});

const s3Client = new S3Client({
    region: 'auto',
    endpoint: process.env.AWS_ENDPOINT,
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    },
});

const storage = multer.memoryStorage();
const upload = multer({ storage });

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// =================================================================
// RUTAS DE USUARIOS Y FICHAR (sin cambios)
// =================================================================
app.post('/api/login', async (req, res) => {
    const { usuario, password } = req.body;
    if (!usuario || !password) return res.status(400).json({ message: 'Usuario y contraseña requeridos.' });
    try {
        const result = await db.query('SELECT * FROM usuarios WHERE usuario = $1', [usuario]);
        if (result.rows.length === 0) return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
        const user = result.rows[0];
        const match = await bcrypt.compare(password, user.password);
        if (match) {
            const token = jwt.sign({ id: user.id, rol: user.rol, nombre: user.nombre }, JWT_SECRET, { expiresIn: '8h' });
            res.json({ token, rol: user.rol, nombre: user.nombre });
        } else {
            res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
        }
    } catch (err) { res.status(500).json({ message: 'Error del servidor' }); }
});

// En server.js

// ... (después de la ruta /api/login)

// --- NUEVA RUTA PÚBLICA PARA OBTENER EMPLEADOS ---
// No necesita autenticación porque es para la pantalla de inicio.
app.get('/api/empleados-para-fichaje', async (req, res) => {
    try {
        // Obtenemos solo los empleados activos para el fichaje
        const result = await db.query("SELECT id, nombre FROM usuarios WHERE rol = 'empleado' ORDER BY nombre ASC");
        res.json(result.rows);
    } catch (err) {
        console.error("Error al obtener la lista de empleados para fichaje:", err);
        res.status(500).json({ message: "Error del servidor." });
    }
});

// --- NUEVA RUTA PARA PROCESAR EL FICHAJE RÁPIDO ---
// Usa el mismo middleware de 'upload' que la ruta '/api/fichar'
app.post('/api/fichar-rapido', upload.single('foto'), async (req, res) => {
    // Obtenemos el ID del usuario desde el cuerpo de la petición, no del token
    const { tipo, usuarioId } = req.body;
    const fecha_hora = new Date();

    if (!usuarioId) return res.status(400).json({ message: 'Falta el ID del empleado.' });
    if (!req.file) return res.status(400).json({ message: 'La foto es obligatoria para el fichaje.' });
    if (!tipo || (tipo !== 'entrada' && tipo !== 'salida')) return res.status(400).json({ message: 'Tipo de fichaje inválido.' });

    try {
        const fileName = `${crypto.randomBytes(16).toString('hex')}.jpeg`;
        const putCommand = new PutObjectCommand({
            Bucket: process.env.R2_BUCKET_NAME,
            Key: fileName,
            Body: req.file.buffer,
            ContentType: req.file.mimetype
        });
        await s3Client.send(putCommand);
        
        const foto_path = `${process.env.R2_PUBLIC_URL}/${fileName}`;
        const sql = 'INSERT INTO registros (usuario_id, fecha_hora, tipo, foto_path) VALUES ($1, $2, $3, $4)';
        await db.query(sql, [usuarioId, fecha_hora, tipo, foto_path]);

        res.json({ message: `Fichaje de ${tipo} registrado correctamente.` });
    } catch (err) {
        console.error("Error al procesar el fichaje rápido:", err);
        res.status(500).json({ message: 'Error al procesar el fichaje.' });
    }
});

app.post('/api/fichar', authenticateToken, upload.single('foto'), async (req, res) => {
    const { tipo } = req.body;
    const usuario_id = req.user.id;
    const fecha_hora = new Date();
    if (!req.file) return res.status(400).json({ message: 'Falta foto.' });
    if (!tipo || (tipo !== 'entrada' && tipo !== 'salida')) return res.status(400).json({ message: 'Tipo inválido.' });
    try {
        const fileName = `${crypto.randomBytes(16).toString('hex')}.jpeg`;
        const putCommand = new PutObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, Key: fileName, Body: req.file.buffer, ContentType: req.file.mimetype });
        await s3Client.send(putCommand);
        const foto_path = `${process.env.R2_PUBLIC_URL}/${fileName}`;
        const sql = 'INSERT INTO registros (usuario_id, fecha_hora, tipo, foto_path) VALUES ($1, $2, $3, $4)';
        await db.query(sql, [usuario_id, fecha_hora, tipo, foto_path]);
        res.json({ message: `Fichaje de ${tipo} registrado.` });
    } catch (err) {
        console.error("Error al subir a R2 o guardar en DB:", err);
        res.status(500).json({ message: 'Error al procesar el fichaje.' });
    }
});

app.get('/api/estado', authenticateToken, async (req, res) => {
    const usuario_id = req.user.id;
    const sql = `SELECT tipo FROM registros WHERE usuario_id = $1 AND fecha_hora::date = CURRENT_DATE ORDER BY fecha_hora DESC LIMIT 1`;
    try {
        const result = await db.query(sql, [usuario_id]);
        const ultimoEstado = result.rows.length > 0 ? result.rows[0].tipo : 'salida';
        res.json({ estado: ultimoEstado });
    } catch (err) { res.status(500).json({ message: 'Error al consultar el estado.' }); }
});

// ... (El resto de rutas de admin, usuarios, informes, etc. que no están relacionadas con vacaciones se mantienen igual. Las incluyo por completitud)
app.get('/api/mis-registros', authenticateToken, async (req, res) => {
    const usuarioId = req.user.id;
    const { anio, mes } = req.query;
    if (!anio || !mes) return res.status(400).json({ message: 'Año y mes requeridos.' });
    try {
        const sql = `SELECT fecha_hora, tipo, es_modificado, motivo_modificacion, fecha_hora_original FROM registros WHERE usuario_id = $1 AND date_trunc('month', fecha_hora) = make_date($2, $3, 1) ORDER BY fecha_hora ASC`;
        const result = await db.query(sql, [usuarioId, anio, mes]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ message: "Error del servidor." }); }
});
app.get('/api/informe', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    const { fecha } = req.query;
    if (!fecha) return res.status(400).json({ message: 'Fecha requerida.' });
    const sql = `SELECT r.id, u.nombre, r.fecha_hora, r.tipo, r.foto_path, r.es_modificado, r.fecha_hora_original, r.motivo_modificacion FROM registros r JOIN usuarios u ON r.usuario_id = u.id WHERE r.fecha_hora::date = $1 ORDER BY u.nombre, r.fecha_hora`;
    try {
        const result = await db.query(sql, [fecha]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ message: 'Error al obtener informe.' }); }
});
// En server.js
app.get('/api/usuarios', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin' && req.user.rol !== 'gestor_vacaciones') return res.sendStatus(403);
    try {
        const result = await db.query("SELECT id, nombre, usuario, rol, dias_vacaciones_anuales, dias_compensatorios, fecha_contratacion FROM usuarios ORDER BY nombre");
        res.json(result.rows);
    } catch(err) { res.status(500).json({ message: "Error al obtener usuarios." }); }
});

// En server.js (NUEVA RUTA)
app.put('/api/usuarios/:id/dias-compensatorios', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin' && req.user.rol !== 'gestor_vacaciones') return res.sendStatus(403);
    const { id } = req.params;
    const { dias, motivo } = req.body;
    if (typeof dias !== 'number' || !Number.isInteger(dias) || dias < 0) return res.status(400).json({ message: 'El número de días debe ser un entero no negativo.' });
    try {
        const result = await db.query('UPDATE usuarios SET dias_compensatorios = $1 WHERE id = $2', [dias, id]);
        if (result.rowCount === 0) return res.status(404).json({ message: 'Usuario no encontrado.' });
        res.json({ message: `Días compensatorios actualizados a ${dias}. Motivo: ${motivo || 'No especificado'}` });
    } catch (err) { res.status(500).json({ message: 'Error al actualizar los días.' }); }
});

app.post('/api/usuarios', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    const { nombre, usuario, password, rol, fechaContratacion } = req.body;
    if (!nombre || !usuario || !password || !rol || !fechaContratacion) return res.status(400).json({ message: 'Faltan datos.' });
    try {
        const hash = await bcrypt.hash(password, 10);
        const result = await db.query(
            'INSERT INTO usuarios (nombre, usuario, password, rol, fecha_contratacion) VALUES ($1, $2, $3, $4, $5) RETURNING id', 
            [nombre, usuario, hash, rol, fechaContratacion]
        );
        res.status(201).json({ message: `Usuario '${nombre}' creado.`, id: result.rows[0].id });
    } catch (err) {
        if (err.code === '23505') return res.status(409).json({ message: 'El usuario ya existe.' });
        res.status(500).json({ message: 'Error al crear el usuario.' });
    }
});
app.put('/api/usuarios/:id/password', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    const { password } = req.body;
    if (!password) return res.status(400).json({ message: 'Falta la contraseña.' });
    try {
        const hash = await bcrypt.hash(password, 10);
        const result = await db.query('UPDATE usuarios SET password = $1 WHERE id = $2', [hash, req.params.id]);
        if (result.rowCount === 0) return res.status(404).json({ message: 'Usuario no encontrado.' });
        res.json({ message: 'Contraseña actualizada.' });
    } catch(err) { res.status(500).json({ message: 'Error al actualizar.' }); }
});
app.delete('/api/usuarios/:id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    if (parseInt(req.params.id, 10) === req.user.id) return res.status(400).json({ message: 'No puedes eliminarte a ti mismo.' });
    try {
        const result = await db.query('DELETE FROM usuarios WHERE id = $1', [req.params.id]);
        if (result.rowCount === 0) return res.status(404).json({ message: 'Usuario no encontrado.' });
        res.json({ message: 'Usuario eliminado.' });
    } catch(err) { res.status(500).json({ message: 'Error al eliminar.' }); }
});
app.put('/api/registros/:id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    const { nuevaFechaHora, motivo } = req.body;
    try {
        const registroOriginal = await db.query('SELECT fecha_hora FROM registros WHERE id = $1', [req.params.id]);
        if (registroOriginal.rows.length === 0) return res.status(404).json({ message: 'Registro no encontrado.' });
        const sql = `UPDATE registros SET fecha_hora = $1, es_modificado = TRUE, fecha_hora_original = $2, modificado_por_admin_id = $3, fecha_modificacion = $4, motivo_modificacion = $5 WHERE id = $6`;
        await db.query(sql, [new Date(nuevaFechaHora), registroOriginal.rows[0].fecha_hora, req.user.id, new Date(), motivo, req.params.id]);
        res.json({ message: 'Registro actualizado.' });
    } catch(err) { res.status(500).json({ message: 'Error al actualizar registro.' }); }
});
app.delete('/api/registros/:id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    try {
        const result = await db.query('DELETE FROM registros WHERE id = $1', [req.params.id]);
        if (result.rowCount === 0) return res.status(404).json({ message: 'Registro no encontrado.' });
        res.json({ message: 'Registro eliminado.' });
    } catch(err) { res.status(500).json({ message: 'Error al eliminar registro.' }); }
});
app.post('/api/fichaje-manual', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    const { usuarioId, fechaHora, tipo, motivo } = req.body;
    const sql = `INSERT INTO registros (usuario_id, fecha_hora, tipo, foto_path, es_modificado, fecha_hora_original, modificado_por_admin_id, fecha_modificacion, motivo_modificacion) VALUES ($1, $2, $3, $4, TRUE, NULL, $5, $6, $7)`;
    try {
        await db.query(sql, [usuarioId, new Date(fechaHora), tipo, null, req.user.id, new Date(), `Creación manual: ${motivo}`]);
        res.status(201).json({ message: 'Fichaje manual creado.' });
    } catch(err) { res.status(500).json({ message: 'Error al crear fichaje manual.' }); }
});
app.get('/api/informe-mensual', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    const { anio, mes, usuarioId } = req.query;
    const sql = `SELECT fecha_hora, tipo FROM registros WHERE usuario_id = $1 AND date_trunc('month', fecha_hora) = make_date($2, $3, 1) ORDER BY fecha_hora ASC`;
    try {
        const { rows: registros } = await db.query(sql, [usuarioId, anio, mes]);
        const registrosPorDia = registros.reduce((acc, registro) => {
            const dia = DateTime.fromJSDate(registro.fecha_hora).toISODate();
            if (!acc[dia]) acc[dia] = []; acc[dia].push(registro);
            return acc;
        }, {});
        const informe = { resumenSemanas: {}, totalHorasMesSegundos: 0, totalHorasExtraMesSegundos: 0 };
        for (const dia in registrosPorDia) {
            let totalSegundosDia = 0, entradaActual = null;
            for (const registro of registrosPorDia[dia]) {
                const fechaRegistro = DateTime.fromJSDate(registro.fecha_hora);
                if (registro.tipo === 'entrada' && !entradaActual) entradaActual = fechaRegistro;
                else if (registro.tipo === 'salida' && entradaActual) {
                    const duracion = fechaRegistro.diff(entradaActual, 'seconds').seconds;
                    if (duracion > 0) totalSegundosDia += duracion;
                    entradaActual = null;
                }
            }
            const numSemana = DateTime.fromISO(dia).weekNumber;
            if (!informe.resumenSemanas[numSemana]) informe.resumenSemanas[numSemana] = { totalSegundos: 0, horasExtraSegundos: 0 };
            informe.resumenSemanas[numSemana].totalSegundos += totalSegundosDia;
            informe.totalHorasMesSegundos += totalSegundosDia;
        }
        const umbralSemanalSegundos = 40 * 3600;
        for(const semana in informe.resumenSemanas) {
            const totalSemana = informe.resumenSemanas[semana].totalSegundos;
            if(totalSemana > umbralSemanalSegundos) {
                const extra = totalSemana - umbralSemanalSegundos;
                informe.resumenSemanas[semana].horasExtraSegundos = extra;
                informe.totalHorasExtraMesSegundos += extra;
            }
        }
        res.json(informe);
    } catch(err) { res.status(500).json({ message: 'Error en informe mensual.' }); }
});
app.get('/api/exportar-csv', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    const { anio, mes, usuarioId } = req.query;
    const sql = `SELECT u.nombre, r.fecha_hora, r.tipo FROM registros r JOIN usuarios u ON r.usuario_id = u.id WHERE r.usuario_id = $1 AND date_trunc('month', r.fecha_hora) = make_date($2, $3, 1) ORDER BY r.fecha_hora ASC`;
    const timeZone = 'Europe/Madrid';
    try {
        const { rows: data } = await db.query(sql, [usuarioId, anio, mes]);
        let totalHorasMesSegundos = 0, totalHorasExtraMesSegundos = 0;
        const registrosPorDia = data.reduce((acc, registro) => {
            const dia = DateTime.fromJSDate(registro.fecha_hora).toISODate();
            if (!acc[dia]) acc[dia] = []; acc[dia].push(registro);
            return acc;
        }, {});
        const resumenSemanas = {};
        for (const dia in registrosPorDia) {
            let totalSegundosDia = 0, entradaActual = null;
            for (const registro of registrosPorDia[dia]) {
                const fechaRegistro = DateTime.fromJSDate(registro.fecha_hora);
                if (registro.tipo === 'entrada' && !entradaActual) entradaActual = fechaRegistro;
                else if (registro.tipo === 'salida' && entradaActual) {
                    const duracion = fechaRegistro.diff(entradaActual, 'seconds').seconds;
                    if (duracion > 0) totalSegundosDia += duracion;
                    entradaActual = null;
                }
            }
            const numSemana = DateTime.fromISO(dia).weekNumber;
            if (!resumenSemanas[numSemana]) resumenSemanas[numSemana] = { totalSegundos: 0 };
            resumenSemanas[numSemana].totalSegundos += totalSegundosDia;
            totalHorasMesSegundos += totalSegundosDia;
        }
        const umbralSemanalSegundos = 40 * 3600;
        for(const semana in resumenSemanas) {
            if(resumenSemanas[semana].totalSegundos > umbralSemanalSegundos) totalHorasExtraMesSegundos += resumenSemanas[semana].totalSegundos - umbralSemanalSegundos;
        }
        const datosProcesados = data.map(registro => {
            const fechaLocal = DateTime.fromJSDate(registro.fecha_hora, { zone: 'utc' }).setZone(timeZone);
            return { "Nombre": registro.nombre, "Fecha y Hora (Local)": fechaLocal.toFormat('dd/MM/yyyy HH:mm:ss'), "Tipo": registro.tipo };
        });
        const segundosAFormatoHora = (s) => DateTime.fromSeconds(s, {zone: 'utc'}).toFormat('HH:mm:ss');
        datosProcesados.push({}, { "Nombre": "Total Horas Mes", "Fecha y Hora (Local)": segundosAFormatoHora(totalHorasMesSegundos) }, { "Nombre": "Total Horas Extra", "Fecha y Hora (Local)": segundosAFormatoHora(totalHorasExtraMesSegundos) });
        const fields = ["Nombre", "Fecha y Hora (Local)", "Tipo"];
        const json2csvParser = new Parser({ fields });
        const csv = json2csvParser.parse(datosProcesados);
        res.header('Content-Type', 'text/csv');
        res.attachment(`informe-${anio}-${mes}-usuario-${usuarioId}.csv`);
        res.send(csv);
    } catch(err) { res.status(500).json({ message: 'Error al exportar.' }); }
});
app.get('/api/dashboard', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado.' });
    }
    try {
        const hoy = DateTime.local().toISODate();
        const { rows: todosLosEmpleados } = await db.query("SELECT id, nombre FROM usuarios WHERE rol = 'empleado' ORDER BY nombre");
        const { rows: ultimosFichajes } = await db.query(`SELECT DISTINCT ON (usuario_id) usuario_id, tipo FROM registros WHERE fecha_hora::date = $1 ORDER BY usuario_id, fecha_hora DESC`, [hoy]);
        const { rows: ausenciasHoy } = await db.query(`SELECT u.nombre FROM vacaciones v JOIN usuarios u ON v.usuario_id = u.id WHERE $1 BETWEEN v.fecha_inicio AND v.fecha_fin AND v.estado = 'aprobada' AND u.rol = 'empleado'`, [hoy]);
        const { rows: resumenFichajes } = await db.query(`SELECT COUNT(*) AS total_fichajes, COUNT(*) FILTER (WHERE es_modificado = TRUE) AS fichajes_manuales FROM registros WHERE fecha_hora::date = $1`, [hoy]);
        const empleadosFichadosMap = new Map();
        ultimosFichajes.forEach(fichaje => { if (fichaje.tipo === 'entrada') { empleadosFichadosMap.set(fichaje.usuario_id, true); } });
        const empleadosDentro = [];
        const empleadosFuera = [];
        todosLosEmpleados.forEach(empleado => { (empleadosFichadosMap.has(empleado.id)) ? empleadosDentro.push(empleado.nombre) : empleadosFuera.push(empleado.nombre); });
        res.json({ empleadosDentro, empleadosFuera, ausenciasHoy: ausenciasHoy.map(a => a.nombre), resumen: { totalFichajes: resumenFichajes[0]?.total_fichajes || 0, fichajesManuales: resumenFichajes[0]?.fichajes_manuales || 0 } });
    } catch (err) {
        console.error("Error al obtener datos del dashboard:", err);
        res.status(500).json({ message: 'Error del servidor al cargar el dashboard.' });
    }
});


// =================================================================
// RUTAS PARA GESTIÓN DE VACACIONES (MODIFICADAS)
// =================================================================

// En server.js

app.get('/api/vacaciones', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin' && req.user.rol !== 'gestor_vacaciones') return res.sendStatus(403);
    try {
        const sql = `SELECT v.id, v.fecha_inicio, v.fecha_fin, u.nombre FROM vacaciones v JOIN usuarios u ON v.usuario_id = u.id WHERE v.estado = 'aprobada'`;
        const { rows } = await db.query(sql);
        res.json(rows);
    } catch (err) { res.status(500).json({ message: 'Error al obtener vacaciones.' }); }
});

// MODIFICADO: (ADMIN/GESTOR) Asigna vacaciones y valida saldo
// MODIFICADO: (ADMIN/GESTOR) Asigna vacaciones y valida saldo
app.post('/api/vacaciones', authenticateToken, async (req, res) => {
    // Solo admin y gestor pueden asignar vacaciones directamente
    if (req.user.rol !== 'admin' && req.user.rol !== 'gestor_vacaciones') {
        return res.status(403).json({ message: 'Acceso denegado.' });
    }

    const { usuarioId, fechaInicio, fechaFin } = req.body;

    // Validación de datos
    if (!usuarioId || !fechaInicio || !fechaFin) {
        return res.status(400).json({ message: 'Faltan datos para asignar las vacaciones.' });
    }
    if (new Date(fechaFin) < new Date(fechaInicio)) {
        return res.status(400).json({ message: 'La fecha de fin no puede ser anterior a la fecha de inicio.' });
    }

    try {
        const sql = `
            INSERT INTO vacaciones (usuario_id, fecha_inicio, fecha_fin, estado) 
            VALUES ($1, $2, $3, 'aprobada')
        `;
        // Como un admin las asigna, se aprueban directamente.
        await db.query(sql, [usuarioId, fechaInicio, fechaFin]);
        
        res.status(201).json({ message: 'Vacaciones asignadas correctamente.' });
    } catch (err) {
        console.error("Error al asignar vacaciones:", err);
        res.status(500).json({ message: 'Error del servidor al intentar asignar las vacaciones.' });
    }
});


// MODIFICADO: Calcula el balance de vacaciones de un usuario usando días laborables
app.get('/api/usuarios/:id/vacaciones-restantes', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin' && req.user.rol !== 'gestor_vacaciones') return res.sendStatus(403);
    const { id } = req.params;
    const anioActual = new Date().getFullYear();
    try {
        const diasTotales = await calcularBalance(id, anioActual);
        const sqlVacaciones = `SELECT fecha_inicio, fecha_fin FROM vacaciones WHERE usuario_id = $1 AND estado = 'aprobada' AND EXTRACT(YEAR FROM fecha_inicio) = $2`;
        const resVacaciones = await db.query(sqlVacaciones, [id, anioActual]);
        let diasGastados = 0;
        resVacaciones.rows.forEach(vac => {
            diasGastados += calcularDiasLaborables(vac.fecha_inicio.toISOString().split('T')[0], vac.fecha_fin.toISOString().split('T')[0]);
        });
        const diasRestantes = diasTotales - diasGastados;
        res.json({ diasTotales: parseFloat(diasTotales.toFixed(2)), diasGastados, diasRestantes: parseFloat(diasRestantes.toFixed(2)) });
    } catch (err) { res.status(500).json({ message: 'Error al calcular días restantes: ' + err.message }); }
});

// MODIFICADO: (EMPLEADO) El empleado solicita vacaciones con nuevas reglas
app.post('/api/solicitar-vacaciones', authenticateToken, async (req, res) => {
    const { fechaInicio, fechaFin } = req.body;
    const usuarioId = req.user.id;
    const anioActual = new Date().getFullYear();
    if (!fechaInicio || !fechaFin || new Date(fechaFin) < new Date(fechaInicio)) return res.status(400).json({ message: 'Fechas inválidas.' });

    try {
        const diasLaborablesSolicitados = calcularDiasLaborables(fechaInicio, fechaFin);
        if (diasLaborablesSolicitados < 5) return res.status(400).json({ message: `Debes solicitar un mínimo de 5 días laborables. Has solicitado ${diasLaborablesSolicitados}.` });
        if (diasLaborablesSolicitados > 10) return res.status(400).json({ message: `Puedes solicitar un máximo de 10 días laborables. Has solicitado ${diasLaborablesSolicitados}.` });
        
        const diasTotales = await calcularBalance(usuarioId, anioActual);
        const resVacaciones = await db.query("SELECT fecha_inicio, fecha_fin FROM vacaciones WHERE usuario_id = $1 AND estado IN ('aprobada', 'pendiente') AND EXTRACT(YEAR FROM fecha_inicio) = $2", [usuarioId, anioActual]);
        const diasComprometidos = resVacaciones.rows.reduce((total, vac) => total + calcularDiasLaborables(vac.fecha_inicio.toISOString().split('T')[0], vac.fecha_fin.toISOString().split('T')[0]), 0);
        const diasRestantes = diasTotales - diasComprometidos;

        if (diasLaborablesSolicitados > diasRestantes) return res.status(400).json({ message: `Días insuficientes. Solicitas ${diasLaborablesSolicitados} y solo te quedan ${diasRestantes.toFixed(2)} disponibles.` });
        
        await db.query('INSERT INTO vacaciones (usuario_id, fecha_inicio, fecha_fin, estado) VALUES ($1, $2, $3, $4)', [usuarioId, fechaInicio, fechaFin, 'pendiente']);
        res.status(201).json({ message: 'Solicitud de vacaciones enviada correctamente.' });
    } catch (err) { res.status(500).json({ message: 'Error al procesar la solicitud: ' + err.message }); }
});

// MODIFICADO: (EMPLEADO) Calcula su propio balance usando días laborables
app.get('/api/mis-vacaciones-restantes', authenticateToken, async (req, res) => {
    const usuarioId = req.user.id;
    const anioActual = new Date().getFullYear();
    try {
        const diasTotales = await calcularBalance(usuarioId, anioActual);
        
        const sqlVacaciones = `SELECT fecha_inicio, fecha_fin FROM vacaciones WHERE usuario_id = $1 AND estado = 'aprobada' AND EXTRACT(YEAR FROM fecha_inicio) = $2`;
        const resVacaciones = await db.query(sqlVacaciones, [usuarioId, anioActual]);
        
        let diasGastados = 0;
        resVacaciones.rows.forEach(vac => {
            diasGastados += calcularDiasLaborables(vac.fecha_inicio.toISOString().split('T')[0], vac.fecha_fin.toISOString().split('T')[0]);
        });
        
        const diasRestantes = diasTotales - diasGastados;
        
        const { rows } = await db.query('SELECT fecha_contratacion FROM usuarios WHERE id = $1', [usuarioId]);
        const fechaContratacion = rows.length > 0 ? rows[0].fecha_contratacion : null;

        res.json({ 
            diasTotales: parseFloat(diasTotales.toFixed(2)), 
            diasGastados, 
            diasRestantes: parseFloat(diasRestantes.toFixed(2)),
            fechaContratacion // Se envía la fecha al frontend
        });
    } catch(err) { 
        res.status(500).json({ message: 'Error al calcular días restantes: ' + err.message }); 
    }
});


// --- RUTAS SIN CAMBIOS NECESARIOS ---
app.put('/api/vacaciones/:id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin' && req.user.rol !== 'gestor_vacaciones') return res.sendStatus(403);
    const { id } = req.params;
    const { fechaInicio, fechaFin } = req.body;
    if (!fechaInicio || !fechaFin) return res.status(400).json({ message: 'Faltan las fechas de inicio y fin.' });
    try {
        const sql = 'UPDATE vacaciones SET fecha_inicio = $1, fecha_fin = $2 WHERE id = $3';
        const result = await db.query(sql, [fechaInicio, fechaFin, id]);
        if (result.rowCount === 0) return res.status(404).json({ message: 'Periodo de vacaciones no encontrado.' });
        res.json({ message: 'Vacaciones actualizadas correctamente.' });
    } catch (err) {
        res.status(500).json({ message: 'Error al actualizar las vacaciones.' });
    }
});

app.delete('/api/vacaciones/:id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin' && req.user.rol !== 'gestor_vacaciones') return res.sendStatus(403);
    const { id } = req.params;
    try {
        const sql = 'DELETE FROM vacaciones WHERE id = $1';
        const result = await db.query(sql, [id]);
        if (result.rowCount === 0) return res.status(404).json({ message: 'Periodo de vacaciones no encontrado.' });
        res.json({ message: 'Vacaciones eliminadas correctamente.' });
    } catch (err) {
        res.status(500).json({ message: 'Error al eliminar las vacaciones.' });
    }
});

// --- RUTA AÑADIDA: Obtiene las solicitudes pendientes para el admin/gestor ---
app.get('/api/vacaciones-pendientes', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin' && req.user.rol !== 'gestor_vacaciones') return res.sendStatus(403);
    try {
        const { rows } = await db.query("SELECT v.id, u.nombre, v.fecha_inicio, v.fecha_fin FROM vacaciones v JOIN usuarios u ON v.usuario_id = u.id WHERE v.estado = 'pendiente' ORDER BY v.id ASC");
        res.json(rows);
    } catch(err) { res.status(500).json({ message: 'Error al obtener solicitudes.' }); }
});

// --- RUTA AÑADIDA: Permite al admin/gestor aprobar o rechazar solicitudes ---
app.put('/api/vacaciones/:id/gestionar', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin' && req.user.rol !== 'gestor_vacaciones') return res.sendStatus(403);
    const { nuevoEstado } = req.body;
    if (!['aprobada', 'rechazada'].includes(nuevoEstado)) return res.status(400).json({ message: 'Estado no válido.' });
    try {
        const result = await db.query("UPDATE vacaciones SET estado = $1 WHERE id = $2 AND estado = 'pendiente'", [nuevoEstado, req.params.id]);
        if (result.rowCount === 0) return res.status(404).json({ message: 'Solicitud no encontrada o ya gestionada.' });
        res.json({ message: `Solicitud ${nuevoEstado}.` });
    } catch(err) { res.status(500).json({ message: 'Error al gestionar.' }); }
});

app.get('/api/fix-vacation-days', authenticateToken, async(req, res) => {
    if (req.user.rol !== 'admin') return res.sendStatus(403);
    try {
        // MODIFICADO: Actualiza a 20 días
        await db.query("UPDATE usuarios SET dias_vacaciones_anuales = 20 WHERE rol = 'empleado' AND (dias_vacaciones_anuales IS NULL OR dias_vacaciones_anuales != 20)");
        res.send('Datos de vacaciones de usuarios existentes actualizados a 20 días laborables.');
    } catch (e) {
        res.status(500).send('Error al actualizar: ' + e.message);
    }
});

// En server.js
// --- LÓGICA RESTAURADA A LA VERSIÓN CORRECTA ---
app.get('/api/mis-vacaciones', authenticateToken, async (req, res) => {
    const usuarioId = req.user.id;
    try {
        const sql = `
            SELECT id, 'Mis Vacaciones' as title, fecha_inicio as start, fecha_fin as end 
            FROM vacaciones 
            WHERE usuario_id = $1 AND estado = 'aprobada'
        `;
        const { rows } = await db.query(sql, [usuarioId]);
        res.json(rows); // Ahora devuelve un array de eventos
    } catch(err) {
        res.status(500).json({ message: 'Error al obtener mis vacaciones.' });
    }
});

app.put('/api/vacaciones/:id/gestionar', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin' && req.user.rol !== 'gestor_vacaciones') return res.sendStatus(403);
    const { nuevoEstado } = req.body;
    if (!['aprobada', 'rechazada'].includes(nuevoEstado)) return res.status(400).json({ message: 'Estado no válido.' });
    try {
        const result = await db.query("UPDATE vacaciones SET estado = $1 WHERE id = $2 AND estado = 'pendiente'", [nuevoEstado, req.params.id]);
        if (result.rowCount === 0) return res.status(404).json({ message: 'Solicitud no encontrada o ya gestionada.' });
        res.json({ message: `Solicitud ${nuevoEstado}.` });
    } catch(err) { res.status(500).json({ message: 'Error al gestionar.' }); }
});

app.get('/api/mis-solicitudes', authenticateToken, async (req, res) => {
    try {
        const { rows } = await db.query("SELECT fecha_inicio, fecha_fin, estado FROM vacaciones WHERE usuario_id = $1 ORDER BY fecha_inicio DESC", [req.user.id]);
        res.json(rows);
    } catch(err) { res.status(500).json({ message: 'Error al obtener tus solicitudes.' }); }
});

// =================================================================
// INICIO DEL SERVIDOR
// =================================================================
const startServer = async () => {
    try {
        await db.init();
        app.listen(PORT, '0.0.0.0', () => {
            console.log(`Servidor corriendo y accesible en la red en el puerto ${PORT}`);
        });
    } catch (error) {
        console.error("No se pudo iniciar el servidor:", error);
        process.exit(1);
    }
};

startServer();