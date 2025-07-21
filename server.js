// =================================================================
// SERVIDOR PARA LA APLICACIÓN DE CONTROL DE ASISTENCIA
// =================================================================

// 1. IMPORTACIÓN DE MÓDULOS
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const db = require('./database.js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Parser } = require('json2csv');

// NUEVA LIBRERÍA DE FECHAS: LUXON
const { DateTime } = require('luxon');


// 2. INICIALIZACIÓN Y CONFIGURACIÓN
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'tu_secreto_super_secreto_y_largo_y_dificil_de_adivinar_987654';

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// --- CONFIGURACIÓN DE MULTER ---
const uploadDir = path.join(__dirname, 'public/uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
        const userId = req.user ? req.user.id : 'unknown';
        cb(null, `${Date.now()}-${userId}.jpeg`);
    }
});
const upload = multer({ storage });
app.use('/uploads', express.static(uploadDir));

// --- MIDDLEWARE DE AUTENTICACIÓN ---
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
// RUTAS DE LA API
// =================================================================

// --- RUTA PÚBLICA: LOGIN ---
app.post('/api/login', (req, res) => {
    const { usuario, password } = req.body;
    if (!usuario || !password) return res.status(400).json({ message: 'Usuario y contraseña son requeridos.' });
    db.get('SELECT * FROM usuarios WHERE usuario = ?', [usuario], (err, user) => {
        if (err || !user) return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
        bcrypt.compare(password, user.password, (err, result) => {
            if (result) {
                const token = jwt.sign({ id: user.id, rol: user.rol, nombre: user.nombre }, JWT_SECRET, { expiresIn: '8h' });
                res.json({ token, rol: user.rol, nombre: user.nombre });
            } else {
                res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
            }
        });
    });
});

// --- RUTA EMPLEADO: OBTENER ESTADO ---
app.get('/api/estado', authenticateToken, (req, res) => {
    const usuario_id = req.user.id;
    const hoy = new Date().toISOString().split('T')[0];
    const sql = `
        SELECT tipo 
        FROM registros 
        WHERE usuario_id = ? AND date(fecha_hora) = ? 
        ORDER BY fecha_hora DESC 
        LIMIT 1
    `;
    db.get(sql, [usuario_id, hoy], (err, row) => {
        if (err) return res.status(500).json({ message: 'Error al consultar el estado.' });
        const ultimoEstado = row ? row.tipo : 'salida';
        res.json({ estado: ultimoEstado });
    });
});


// --- RUTA EMPLEADO: FICHAJE CON FOTO ---
app.post('/api/fichar', authenticateToken, upload.single('foto'), (req, res) => {
    const { tipo } = req.body;
    const usuario_id = req.user.id;
    const fecha_hora = new Date().toISOString();
    const foto_path = req.file ? `/uploads/${req.file.filename}` : null;
    if (!tipo || (tipo !== 'entrada' && tipo !== 'salida')) return res.status(400).json({ message: 'Tipo de fichaje inválido.' });
    if (!foto_path) return res.status(400).json({ message: 'No se ha proporcionado la foto de verificación.' });
    
    const sql = 'INSERT INTO registros (usuario_id, fecha_hora, tipo, foto_path) VALUES (?, ?, ?, ?)';
    db.run(sql, [usuario_id, fecha_hora, tipo, foto_path], function(err) {
        if (err) {
            console.error("Error en DB al fichar:", err.message);
            return res.status(500).json({ message: 'Error al guardar el registro en la base de datos.' });
        }
        res.json({ message: `Fichaje de ${tipo} registrado con foto.` });
    });
});

// --- RUTA EMPLEADO: OBTENER SU PROPIO HISTORIAL DE FICHAJES ---
app.get('/api/mis-registros', authenticateToken, (req, res) => {
    const usuarioId = req.user.id;
    const { anio, mes } = req.query;

    if (!anio || !mes) {
        return res.status(400).json({ message: 'Se requieren el año y el mes.' });
    }

    try {
        const fechaInicio = DateTime.fromObject({ year: anio, month: mes, day: 1 }).startOf('month');
        const fechaFin = fechaInicio.endOf('month');
        
        const sql = `
            SELECT 
                fecha_hora, 
                tipo, 
                es_modificado, 
                motivo_modificacion, 
                fecha_hora_original 
            FROM registros 
            WHERE usuario_id = ? AND fecha_hora BETWEEN ? AND ? 
            ORDER BY fecha_hora DESC
        `;

        db.all(sql, [usuarioId, fechaInicio.toUTC().toISO(), fechaFin.toUTC().toISO()], (err, rows) => {
            if (err) {
                console.error("Error en /api/mis-registros:", err.message);
                return res.status(500).json({ message: 'Error al obtener tus registros.' });
            }
            res.json(rows);
        });
    } catch (e) {
        console.error("Error procesando la fecha en /mis-registros:", e.message);
        res.status(500).json({ message: "Error interno del servidor." });
    }
});


// --- RUTA ADMIN: INFORME DIARIO ---
app.get('/api/informe', authenticateToken, (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    const { fecha } = req.query;
    if (!fecha) return res.status(400).json({ message: 'Se requiere una fecha.' });
    
    const sql = `
        SELECT 
            r.id, u.nombre, r.fecha_hora, r.tipo, r.foto_path, 
            r.es_modificado, r.fecha_hora_original, r.motivo_modificacion 
        FROM registros r 
        JOIN usuarios u ON r.usuario_id = u.id 
        WHERE date(r.fecha_hora) = ? 
        ORDER BY u.nombre, r.fecha_hora
    `;

    db.all(sql, [fecha], (err, rows) => {
        if (err) return res.status(500).json({ message: 'Error al obtener el informe.' });
        res.json(rows);
    });
});

// --- RUTAS DE GESTIÓN DE USUARIOS (ADMIN) ---
// (Estas rutas no usan fechas, por lo que no cambian)
app.get('/api/usuarios', authenticateToken, (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    db.all("SELECT id, nombre, usuario, rol FROM usuarios ORDER BY nombre", [], (err, rows) => {
        if (err) return res.status(500).json({ message: "Error al obtener la lista de usuarios." });
        res.json(rows);
    });
});
app.post('/api/usuarios', authenticateToken, (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    const { nombre, usuario, password, rol } = req.body;
    if (!nombre || !usuario || !password || !rol) return res.status(400).json({ message: 'Faltan datos.' });
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ message: 'Error al encriptar.' });
        db.run('INSERT INTO usuarios (nombre, usuario, password, rol) VALUES (?, ?, ?, ?)', [nombre, usuario, hash, rol], function(err) {
            if (err) {
                if (err.code === 'SQLITE_CONSTRAINT') return res.status(409).json({ message: 'El usuario ya existe.' });
                return res.status(500).json({ message: 'Error al crear el usuario.' });
            }
            res.status(201).json({ message: `Usuario '${nombre}' creado.`, id: this.lastID });
        });
    });
});
app.put('/api/usuarios/:id/password', authenticateToken, (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    const { password } = req.body;
    if (!password) return res.status(400).json({ message: 'Falta la nueva contraseña.' });
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ message: 'Error al encriptar.' });
        db.run('UPDATE usuarios SET password = ? WHERE id = ?', [hash, req.params.id], function(err) {
            if (err) return res.status(500).json({ message: 'Error al actualizar.' });
            if (this.changes === 0) return res.status(404).json({ message: 'Usuario no encontrado.' });
            res.json({ message: 'Contraseña actualizada.' });
        });
    });
});
app.delete('/api/usuarios/:id', authenticateToken, (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    if (parseInt(req.params.id, 10) === req.user.id) return res.status(400).json({ message: 'No puedes eliminar tu propia cuenta.' });
    db.run('DELETE FROM usuarios WHERE id = ?', req.params.id, function(err) {
        if (err) return res.status(500).json({ message: 'Error al eliminar.' });
        if (this.changes === 0) return res.status(404).json({ message: 'Usuario no encontrado.' });
        res.json({ message: 'Usuario eliminado.' });
    });
});
app.put('/api/registros/:id', authenticateToken, (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    const registroId = req.params.id;
    const { nuevaFechaHora, motivo } = req.body;
    const adminId = req.user.id;
    if (!nuevaFechaHora || !motivo || motivo.trim() === '') return res.status(400).json({ message: 'Se requiere la nueva fecha/hora y un motivo.' });
    db.get('SELECT fecha_hora FROM registros WHERE id = ?', [registroId], (err, registroOriginal) => {
        if (err) return res.status(500).json({ message: 'Error en base de datos.' });
        if (!registroOriginal) return res.status(404).json({ message: 'Registro no encontrado.' });
        const sql = `UPDATE registros SET fecha_hora = ?, es_modificado = 1, fecha_hora_original = ?, modificado_por_admin_id = ?, fecha_modificacion = ?, motivo_modificacion = ? WHERE id = ?`;
        const params = [ new Date(nuevaFechaHora).toISOString(), registroOriginal.fecha_hora, adminId, new Date().toISOString(), motivo, registroId ];
        db.run(sql, params, function(err) {
            if (err) {
                console.error("Error al actualizar el registro:", err.message);
                return res.status(500).json({ message: 'Error al actualizar el registro.' });
            }
            res.json({ message: 'Registro actualizado correctamente.' });
        });
    });
});
app.delete('/api/registros/:id', authenticateToken, (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    const registroId = req.params.id;
    const sql = 'DELETE FROM registros WHERE id = ?';
    db.run(sql, [registroId], function(err) {
        if (err) {
            console.error("Error al eliminar el registro:", err.message);
            return res.status(500).json({ message: 'Error interno del servidor.' });
        }
        if (this.changes === 0) return res.status(404).json({ message: 'Registro no encontrado.' });
        res.json({ message: 'El registro de fichaje ha sido eliminado.' });
    });
});
app.post('/api/fichaje-manual', authenticateToken, (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    const { usuarioId, fechaHora, tipo, motivo } = req.body;
    const adminId = req.user.id;
    if (!usuarioId || !fechaHora || !tipo || !motivo || motivo.trim() === '') return res.status(400).json({ message: 'Todos los campos son obligatorios.' });
    const sql = `INSERT INTO registros (usuario_id, fecha_hora, tipo, foto_path, es_modificado, fecha_hora_original, modificado_por_admin_id, fecha_modificacion, motivo_modificacion) VALUES (?, ?, ?, ?, 1, NULL, ?, ?, ?)`;
    const params = [ usuarioId, new Date(fechaHora).toISOString(), tipo, null, adminId, new Date().toISOString(), `Creación manual: ${motivo}` ];
    db.run(sql, params, function(err) {
        if (err) {
            console.error("Error al crear fichaje manual:", err.message);
            return res.status(500).json({ message: 'Error al guardar el fichaje.' });
        }
        res.status(201).json({ message: 'Fichaje manual creado con éxito.' });
    });
});

// --- RUTAS DE INFORMES (ADMIN) ---
app.get('/api/informe-mensual', authenticateToken, (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    const { anio, mes, usuarioId } = req.query;
    if (!anio || !mes || !usuarioId) return res.status(400).json({ message: 'Parámetros incompletos.' });

    try {
        const fechaInicio = DateTime.fromObject({ year: anio, month: mes, day: 1 }).startOf('month');
        const fechaFin = fechaInicio.endOf('month');
        const sql = `SELECT fecha_hora, tipo FROM registros WHERE usuario_id = ? AND fecha_hora BETWEEN ? AND ? ORDER BY fecha_hora ASC`;

        db.all(sql, [usuarioId, fechaInicio.toUTC().toISO(), fechaFin.toUTC().toISO()], (err, registros) => {
            if (err) return res.status(500).json({ message: 'Error en la base de datos.' });

            const registrosPorDia = registros.reduce((acc, registro) => {
                const dia = DateTime.fromISO(registro.fecha_hora).toISODate();
                if (!acc[dia]) acc[dia] = [];
                acc[dia].push(registro);
                return acc;
            }, {});

            const informe = { resumenSemanas: {}, totalHorasMesSegundos: 0, totalHorasExtraMesSegundos: 0 };
            
            for (const dia in registrosPorDia) {
                const registrosDelDia = registrosPorDia[dia];
                let totalSegundosDia = 0;
                let entradaActual = null;
                for (const registro of registrosDelDia) {
                    const fechaRegistro = DateTime.fromISO(registro.fecha_hora);
                    if (registro.tipo === 'entrada' && !entradaActual) {
                        entradaActual = fechaRegistro;
                    } else if (registro.tipo === 'salida' && entradaActual) {
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
        });
    } catch (e) {
        console.error("Error crítico en /informe-mensual:", e.message);
        res.status(500).json({ message: "Error interno del servidor." });
    }
});


// =========================================================================
// == RUTA DE EXPORTACIÓN A CSV CON TOTALES AL FINAL ==
// =========================================================================
app.get('/api/exportar-csv', authenticateToken, (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    const { anio, mes, usuarioId } = req.query;
    if (!anio || !mes || !usuarioId) return res.status(400).json({ message: 'Faltan parámetros.' });

    const fechaInicio = DateTime.fromObject({ year: anio, month: mes, day: 1 }).startOf('month');
    const fechaFin = fechaInicio.endOf('month');
    const sql = `SELECT u.nombre, r.fecha_hora, r.tipo FROM registros r JOIN usuarios u ON r.usuario_id = u.id WHERE r.usuario_id = ? AND r.fecha_hora BETWEEN ? AND ? ORDER BY r.fecha_hora ASC`;
    const timeZone = 'Europe/Madrid';

    db.all(sql, [usuarioId, fechaInicio.toUTC().toISO(), fechaFin.toUTC().toISO()], (err, data) => {
        if (err) return res.status(500).json({ message: 'Error al obtener datos.' });
        
        // 1. Procesar los fichajes individuales para el CSV
        const datosProcesados = data.map(registro => {
            const fechaLocal = DateTime.fromISO(registro.fecha_hora, { zone: 'utc' }).setZone(timeZone);
            return {
                "Nombre": registro.nombre,
                "Fecha y Hora (Local)": fechaLocal.toFormat('dd/MM/yyyy HH:mm:ss'),
                "Tipo": registro.tipo
            };
        });

        // 2. Calcular los totales (reutilizando la lógica de la otra ruta)
        const registrosPorDia = data.reduce((acc, registro) => {
            const dia = DateTime.fromISO(registro.fecha_hora).toISODate();
            if (!acc[dia]) acc[dia] = [];
            acc[dia].push(registro);
            return acc;
        }, {});
        
        let totalHorasMesSegundos = 0;
        let totalHorasExtraMesSegundos = 0;
        const resumenSemanas = {};

        for (const dia in registrosPorDia) {
            let totalSegundosDia = 0;
            let entradaActual = null;
            for (const registro of registrosPorDia[dia]) {
                const fechaRegistro = DateTime.fromISO(registro.fecha_hora);
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
            if(resumenSemanas[semana].totalSegundos > umbralSemanalSegundos) {
                totalHorasExtraMesSegundos += resumenSemanas[semana].totalSegundos - umbralSemanalSegundos;
            }
        }

        // 3. Formatear los totales a un formato de hora HH:MM:SS
        const segundosAFormatoHora = (s) => DateTime.fromSeconds(s, {zone: 'utc'}).toFormat('HH:mm:ss');
        const totalHorasFormato = segundosAFormatoHora(totalHorasMesSegundos);
        const totalExtrasFormato = segundosAFormatoHora(totalHorasExtraMesSegundos);

        // 4. Añadir las filas de resumen al final de los datos
        datosProcesados.push({}); // Fila vacía para separar
        datosProcesados.push({ "Nombre": "Total Horas Mes", "Fecha y Hora (Local)": totalHorasFormato });
        datosProcesados.push({ "Nombre": "Total Horas Extra", "Fecha y Hora (Local)": totalExtrasFormato });
        
        // 5. Generar el CSV
        const fields = ["Nombre", "Fecha y Hora (Local)", "Tipo"];
        const json2csvParser = new Parser({ fields });
        const csv = json2csvParser.parse(datosProcesados);

        res.header('Content-Type', 'text/csv');
        res.attachment(`informe-${anio}-${mes}-usuario-${usuarioId}.csv`);
        res.send(csv);
    });
});


// =================================================================
// INICIO DEL SERVIDOR
// =================================================================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor corriendo y accesible en la red en el puerto ${PORT}`);
});