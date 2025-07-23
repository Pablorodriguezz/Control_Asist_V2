// server.js (COMPLETO CON EDICIÓN Y ELIMINACIÓN DE VACACIONES)
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
// RUTAS PRINCIPALES
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

app.get('/api/usuarios', authenticateToken, async (req, res) => {
    // CAMBIO: Permitimos acceso a 'admin' Y 'gestor_vacaciones'
if (req.user.rol !== 'admin' && req.user.rol !== 'gestor_vacaciones') return res.status(403);
    try {
        const result = await db.query("SELECT id, nombre, usuario, rol FROM usuarios ORDER BY nombre");
        res.json(result.rows);
    } catch(err) { res.status(500).json({ message: "Error al obtener usuarios." }); }
});

app.post('/api/usuarios', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    const { nombre, usuario, password, rol } = req.body;
    if (!nombre || !usuario || !password || !rol) return res.status(400).json({ message: 'Faltan datos.' });
    try {
        const hash = await bcrypt.hash(password, 10);
        const result = await db.query('INSERT INTO usuarios (nombre, usuario, password, rol) VALUES ($1, $2, $3, $4) RETURNING id', [nombre, usuario, hash, rol]);
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


// =================================================================
// RUTAS PARA GESTIÓN DE VACACIONES
// =================================================================

function calcularDiasNaturales(fechaInicio, fechaFin) {
    const inicio = DateTime.fromJSDate(new Date(fechaInicio));
    const fin = DateTime.fromJSDate(new Date(fechaFin));
    const diff = fin.diff(inicio, 'days').toObject();
    return diff.days + 1;
}

app.get('/api/vacaciones', authenticateToken, async (req, res) => {
    // CAMBIO: Permitimos acceso a 'admin' Y 'gestor_vacaciones'
if (req.user.rol !== 'admin' && req.user.rol !== 'gestor_vacaciones') return res.sendStatus(403);
    const { start, end } = req.query;
    try {
        let sql = `SELECT v.id, v.fecha_inicio, v.fecha_fin, u.nombre FROM vacaciones v JOIN usuarios u ON v.usuario_id = u.id WHERE v.estado = 'aprobada'`;
        const params = [];
        if (start && end) {
            sql += ` AND v.fecha_fin >= $1 AND v.fecha_inicio <= $2`;
            params.push(start.split('T')[0]); 
            params.push(end.split('T')[0]);
        }
        const { rows } = await db.query(sql, params);
        res.json(rows);
    } catch(err) {
        console.error("Error en GET /api/vacaciones:", err); 
        res.status(500).json({ message: 'Error al obtener vacaciones.' });
    }
});

app.post('/api/vacaciones', authenticateToken, async (req, res) => {
// CAMBIO: Permitimos acceso a 'admin' Y 'gestor_vacaciones'
if (req.user.rol !== 'admin' && req.user.rol !== 'gestor_vacaciones') return res.sendStatus(403);
    const { usuarioId, fechaInicio, fechaFin } = req.body;
    if (!usuarioId || !fechaInicio || !fechaFin) return res.status(400).json({ message: 'Faltan datos.' });
    try {
        const sql = 'INSERT INTO vacaciones (usuario_id, fecha_inicio, fecha_fin) VALUES ($1, $2, $3)';
        await db.query(sql, [usuarioId, fechaInicio, fechaFin]);
        res.status(201).json({ message: 'Vacaciones registradas correctamente.' });
    } catch(err) { res.status(500).json({ message: 'Error al registrar las vacaciones.' }); }
});

app.get('/api/usuarios/:id/vacaciones-restantes', authenticateToken, async (req, res) => {
    // CAMBIO: Permitimos acceso a 'admin' Y 'gestor_vacaciones'
if (req.user.rol !== 'admin' && req.user.rol !== 'gestor_vacaciones') return res.sendStatus(403);
    const { id } = req.params;
    const anioActual = new Date().getFullYear();
    try {
        const resUsuario = await db.query('SELECT dias_vacaciones_anuales FROM usuarios WHERE id = $1', [id]);
        if (resUsuario.rowCount === 0) return res.status(404).json({ message: 'Usuario no encontrado.' });
        const diasTotales = resUsuario.rows[0].dias_vacaciones_anuales === null ? 30 : resUsuario.rows[0].dias_vacaciones_anuales;
        const sqlVacaciones = `SELECT fecha_inicio, fecha_fin FROM vacaciones WHERE usuario_id = $1 AND estado = 'aprobada' AND EXTRACT(YEAR FROM fecha_inicio) = $2`;
        const resVacaciones = await db.query(sqlVacaciones, [id, anioActual]);
        let diasGastados = 0;
        resVacaciones.rows.forEach(vac => {
            diasGastados += calcularDiasNaturales(vac.fecha_inicio, vac.fecha_fin);
        });
        const diasRestantes = diasTotales - diasGastados;
        res.json({ diasTotales, diasGastados, diasRestantes });
    } catch(err) {
        console.error("Error al calcular días restantes:", err);
        res.status(500).json({ message: 'Error al calcular días restantes.' });
    }
});

app.put('/api/vacaciones/:id', authenticateToken, async (req, res) => {
    // CAMBIO: Permitimos acceso a 'admin' Y 'gestor_vacaciones'
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
        console.error("Error en PUT /api/vacaciones/:id", err);
        res.status(500).json({ message: 'Error al actualizar las vacaciones.' });
    }
});

app.delete('/api/vacaciones/:id', authenticateToken, async (req, res) => {
    // CAMBIO: Permitimos acceso a 'admin' Y 'gestor_vacaciones'
if (req.user.rol !== 'admin' && req.user.rol !== 'gestor_vacaciones') return res.sendStatus(403);
    const { id } = req.params;
    try {
        const sql = 'DELETE FROM vacaciones WHERE id = $1';
        const result = await db.query(sql, [id]);
        if (result.rowCount === 0) return res.status(404).json({ message: 'Periodo de vacaciones no encontrado.' });
        res.json({ message: 'Vacaciones eliminadas correctamente.' });
    } catch (err) {
        console.error("Error en DELETE /api/vacaciones/:id", err);
        res.status(500).json({ message: 'Error al eliminar las vacaciones.' });
    }
});

app.get('/api/fix-vacation-days', authenticateToken, async(req, res) => {
    if (req.user.rol !== 'admin') return res.sendStatus(403);
    try {
        await db.query("UPDATE usuarios SET dias_vacaciones_anuales = 30 WHERE rol = 'empleado' AND dias_vacaciones_anuales IS NULL");
        res.send('Datos de vacaciones de usuarios existentes actualizados a 30.');
    } catch (e) {
        res.status(500).send('Error al actualizar: ' + e.message);
    }
});



// =================================================================
// RUTA PARA EL DASHBOARD
// =================================================================
app.get('/api/dashboard', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado.' });
    }

    try {
        const hoy = DateTime.local().toISODate(); // Formato 'YYYY-MM-DD'

        // 1. Obtener todos los empleados
        const { rows: todosLosEmpleados } = await db.query(
            "SELECT id, nombre FROM usuarios WHERE rol = 'empleado' ORDER BY nombre"
        );

        // 2. Obtener los últimos fichajes de hoy para cada empleado
        const { rows: ultimosFichajes } = await db.query(`
            SELECT DISTINCT ON (usuario_id) usuario_id, tipo
            FROM registros
            WHERE fecha_hora::date = $1
            ORDER BY usuario_id, fecha_hora DESC
        `, [hoy]);

        // 3. Obtener ausencias (vacaciones) de hoy
        const { rows: ausenciasHoy } = await db.query(`
            SELECT u.nombre
            FROM vacaciones v
            JOIN usuarios u ON v.usuario_id = u.id
            WHERE $1 BETWEEN v.fecha_inicio AND v.fecha_fin
              AND v.estado = 'aprobada'
              AND u.rol = 'empleado'
        `, [hoy]);

        // 4. Obtener widgets de resumen del día
        const { rows: resumenFichajes } = await db.query(`
            SELECT 
                COUNT(*) AS total_fichajes,
                COUNT(*) FILTER (WHERE es_modificado = TRUE) AS fichajes_manuales
            FROM registros
            WHERE fecha_hora::date = $1
        `, [hoy]);
        
        // --- Procesamiento de datos ---

        const empleadosFichadosMap = new Map();
        ultimosFichajes.forEach(fichaje => {
            if (fichaje.tipo === 'entrada') {
                empleadosFichadosMap.set(fichaje.usuario_id, true);
            }
        });

        const empleadosDentro = [];
        const empleadosFuera = [];

        todosLosEmpleados.forEach(empleado => {
            if (empleadosFichadosMap.has(empleado.id)) {
                empleadosDentro.push(empleado.nombre);
            } else {
                empleadosFuera.push(empleado.nombre);
            }
        });

        res.json({
            empleadosDentro,
            empleadosFuera,
            ausenciasHoy: ausenciasHoy.map(a => a.nombre),
            resumen: {
                totalFichajes: resumenFichajes[0]?.total_fichajes || 0,
                fichajesManuales: resumenFichajes[0]?.fichajes_manuales || 0
            }
        });

    } catch (err) {
        console.error("Error al obtener datos del dashboard:", err);
        res.status(500).json({ message: 'Error del servidor al cargar el dashboard.' });
    }
});

app.get('/api/mis-vacaciones-restantes', authenticateToken, async (req, res) => {
    const usuarioId = req.user.id; // Obtenemos el ID del token
    const anioActual = new Date().getFullYear();

    try {
        const resUsuario = await db.query('SELECT dias_vacaciones_anuales FROM usuarios WHERE id = $1', [usuarioId]);
        if (resUsuario.rowCount === 0) {
            return res.status(404).json({ message: 'Usuario no encontrado.' });
        }
        
        const diasTotales = resUsuario.rows[0].dias_vacaciones_anuales ?? 30;
        
        const sqlVacaciones = `SELECT fecha_inicio, fecha_fin FROM vacaciones WHERE usuario_id = $1 AND estado = 'aprobada' AND EXTRACT(YEAR FROM fecha_inicio) = $2`;
        const resVacaciones = await db.query(sqlVacaciones, [usuarioId, anioActual]);
        
        let diasGastados = 0;
        resVacaciones.rows.forEach(vac => {
            // Reutilizamos la función de cálculo que ya tenías
            const inicio = DateTime.fromJSDate(new Date(vac.fecha_inicio));
            const fin = DateTime.fromJSDate(new Date(vac.fecha_fin));
            diasGastados += fin.diff(inicio, 'days').toObject().days + 1;
        });
        
        const diasRestantes = diasTotales - diasGastados;
        res.json({ diasTotales, diasGastados, diasRestantes });

    } catch(err) {
        console.error("Error al calcular mis días restantes:", err);
        res.status(500).json({ message: 'Error al calcular días restantes.' });
    }
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