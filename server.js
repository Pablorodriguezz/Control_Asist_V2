// server.js (VERSIÓN FINAL CON CLOUDFLARE R2)
const express = require('express');
const cors = require('cors');
const path = require('path');
// const fs = require('fs'); // ELIMINADO: Ya no necesitamos manejar el sistema de archivos para las fotos.
const multer = require('multer');
const db = require('./database.js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Parser } = require('json2csv');
const { DateTime } = require('luxon');

// NUEVO: Importamos el cliente S3 de AWS y el módulo crypto
const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'tu_secreto_super_secreto_y_largo_y_dificil_de_adivinar_987654';

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// NUEVO: Configuración del cliente S3 para apuntar a Cloudflare R2
// Leemos las variables de entorno que configuraste en Railway
const s3Client = new S3Client({
    region: 'auto', // Requerido por Cloudflare
    endpoint: process.env.AWS_ENDPOINT, // La URL del endpoint de tu cuenta
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    },
});

// CAMBIADO: Configuración de Multer
// En lugar de guardar en disco (diskStorage), guardamos la foto en la memoria (memoryStorage)
// Esto nos da un "buffer" con los datos del archivo, listo para ser enviado a R2.
const storage = multer.memoryStorage();
const upload = multer({ storage });

// ELIMINADO: Ya no necesitamos servir la carpeta /uploads estáticamente
// app.use('/uploads', express.static(uploadDir));

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
// RUTA DE FICHAJE - ¡AQUÍ ESTÁ LA MAGIA!
// =================================================================
app.post('/api/fichar', authenticateToken, upload.single('foto'), async (req, res) => {
    const { tipo } = req.body;
    const usuario_id = req.user.id;
    const fecha_hora = new Date();

    if (!req.file) {
        return res.status(400).json({ message: 'Falta foto.' });
    }
    if (!tipo || (tipo !== 'entrada' && tipo !== 'salida')) {
        return res.status(400).json({ message: 'Tipo inválido.' });
    }

    try {
        // NUEVO: Generamos un nombre de archivo único y seguro
        const fileName = `${crypto.randomBytes(16).toString('hex')}.jpeg`;

        // NUEVO: Creamos el comando para subir el archivo a R2
        const putCommand = new PutObjectCommand({
            Bucket: process.env.R2_BUCKET_NAME, // El nombre de tu bucket
            Key: fileName,                       // El nombre único del archivo
            Body: req.file.buffer,               // Los datos de la imagen desde la memoria
            ContentType: req.file.mimetype,      // El tipo de contenido (ej: 'image/jpeg')
        });

        // NUEVO: Enviamos el comando a R2
        await s3Client.send(putCommand);

        // CAMBIADO: Construimos la URL pública completa de la foto
        const foto_path = `${process.env.R2_PUBLIC_URL}/${fileName}`;

        // El resto es igual: insertamos la nueva URL en la base de datos
        const sql = 'INSERT INTO registros (usuario_id, fecha_hora, tipo, foto_path) VALUES ($1, $2, $3, $4)';
        await db.query(sql, [usuario_id, fecha_hora, tipo, foto_path]);

        res.json({ message: `Fichaje de ${tipo} registrado.` });
        
    } catch (err) {
        console.error("Error al subir a R2 o guardar en DB:", err);
        res.status(500).json({ message: 'Error al procesar el fichaje.' });
    }
});


// =================================================================
// EL RESTO DE RUTAS NO CAMBIAN
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
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
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
//prueba