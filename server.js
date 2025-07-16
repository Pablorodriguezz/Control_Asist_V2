// =================================================================
// SERVIDOR PARA LA APLICACIÓN DE CONTROL DE ASISTENCIA (VERSIÓN CON EDICIÓN Y ELIMINACIÓN DE FICHAJES)
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
const { parseISO, differenceInSeconds, startOfMonth, endOfMonth } = require('date-fns');
const { Parser } = require('json2csv');

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
    db.get('SELECT tipo FROM registros WHERE usuario_id = ? ORDER BY fecha_hora DESC LIMIT 1', [usuario_id], (err, row) => {
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
                if (err.errno === 19) return res.status(409).json({ message: 'El usuario ya existe.' });
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

// --- RUTA ADMIN: EDITAR REGISTRO DE FICHAJE ---
app.put('/api/registros/:id', authenticateToken, (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado.' });
    }

    const registroId = req.params.id;
    const { nuevaFechaHora, motivo } = req.body;
    const adminId = req.user.id;

    if (!nuevaFechaHora || !motivo || motivo.trim() === '') {
        return res.status(400).json({ message: 'Se requiere la nueva fecha/hora y un motivo.' });
    }

    db.get('SELECT fecha_hora FROM registros WHERE id = ?', [registroId], (err, registroOriginal) => {
        if (err) return res.status(500).json({ message: 'Error en base de datos.' });
        if (!registroOriginal) return res.status(404).json({ message: 'Registro no encontrado.' });

        const sql = `
            UPDATE registros 
            SET 
                fecha_hora = ?, 
                es_modificado = 1,
                fecha_hora_original = ?,
                modificado_por_admin_id = ?,
                fecha_modificacion = ?,
                motivo_modificacion = ?
            WHERE id = ?`;
        
        const params = [
            new Date(nuevaFechaHora).toISOString(),
            registroOriginal.fecha_hora,
            adminId,
            new Date().toISOString(),
            motivo,
            registroId
        ];

        db.run(sql, params, function(err) {
            if (err) {
                console.error("Error al actualizar el registro:", err.message);
                return res.status(500).json({ message: 'Error al actualizar el registro.' });
            }
            res.json({ message: 'Registro actualizado correctamente.' });
        });
    });
});

// --- **NUEVA RUTA** ADMIN: ELIMINAR REGISTRO DE FICHAJE ---
app.delete('/api/registros/:id', authenticateToken, (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }

    const registroId = req.params.id;
    const sql = 'DELETE FROM registros WHERE id = ?';

    db.run(sql, [registroId], function(err) {
        if (err) {
            console.error("Error al eliminar el registro:", err.message);
            return res.status(500).json({ message: 'Error interno del servidor al intentar eliminar.' });
        }
        
        if (this.changes === 0) {
            return res.status(404).json({ message: 'Registro no encontrado. No se pudo eliminar.' });
        }
        res.json({ message: 'El registro de fichaje ha sido eliminado correctamente.' });
    });
});

// --- RUTAS DE INFORMES (ADMIN) ---
app.get('/api/informe-mensual', authenticateToken, (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    const { anio, mes, usuarioId } = req.query;
    if (!anio || !mes || !usuarioId) return res.status(400).json({ message: 'Parámetros incompletos.' });

    try {
        const fechaInicio = startOfMonth(new Date(anio, mes - 1, 1));
        const fechaFin = endOfMonth(fechaInicio);
        const sql = `SELECT fecha_hora, tipo FROM registros WHERE usuario_id = ? AND fecha_hora BETWEEN ? AND ? ORDER BY fecha_hora ASC`;
        
        db.all(sql, [usuarioId, fechaInicio.toISOString(), fechaFin.toISOString()], (err, registros) => {
            if (err) {
                console.error("DB Error en /informe-mensual:", err.message);
                return res.status(500).json({ message: 'Error en la base de datos.' });
            }

            const periodosTrabajados = [];
            let entradaActual = null;
            for (const registro of registros) {
                if (registro.tipo === 'entrada' && !entradaActual) {
                    entradaActual = registro.fecha_hora;
                } else if (registro.tipo === 'salida' && entradaActual) {
                    const fechaEntrada = parseISO(entradaActual);
                    const fechaSalida = parseISO(registro.fecha_hora);
                    const duracionSegundos = differenceInSeconds(fechaSalida, fechaEntrada);

                    if (duracionSegundos >= 0) {
                        periodosTrabajados.push({
                            fecha: entradaActual.split('T')[0],
                            entrada: entradaActual,
                            salida: registro.fecha_hora,
                            duracionSegundos: duracionSegundos
                        });
                    }
                    entradaActual = null;
                }
            }
            res.json(periodosTrabajados);
        });
    } catch (e) {
        console.error("Error crítico en /informe-mensual:", e.message);
        res.status(500).json({ message: "Error interno del servidor." });
    }
});

app.get('/api/exportar-csv', authenticateToken, (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    const { anio, mes, usuarioId } = req.query;
    if (!anio || !mes || !usuarioId) return res.status(400).json({ message: 'Faltan parámetros.' });

    const fechaInicio = startOfMonth(new Date(anio, mes - 1, 1));
    const fechaFin = endOfMonth(fechaInicio);
    const sql = `SELECT u.nombre, r.fecha_hora, r.tipo FROM registros r JOIN usuarios u ON r.usuario_id = u.id WHERE r.usuario_id = ? AND r.fecha_hora BETWEEN ? AND ? ORDER BY r.fecha_hora ASC`;

    db.all(sql, [usuarioId, fechaInicio.toISOString(), fechaFin.toISOString()], (err, data) => {
        if (err) return res.status(500).json({ message: 'Error al obtener datos.' });
        const fields = ['nombre', 'fecha_hora', 'tipo'];
        const json2csvParser = new Parser({ fields });
        const csv = json2csvParser.parse(data);
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