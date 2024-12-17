const express = require('express');
const mysql = require('mysql2');
const multer = require('multer');
const xlsx = require('xlsx');
const bcrypt = require('bcrypt');
const path = require('path');
const app = express();
require('dotenv').config();
const session = require('express-session');
const bodyParser = require('body-parser');
const pdf = require('pdf-parse');
const fs = require('fs');
const PDFDocument = require('pdfkit');


// Configuración de MySQL
const db = mysql.createConnection({
  host: process.env.DB_HOST,       // Host desde .env
  user: process.env.DB_USER,       // Usuario desde .env
  password: process.env.DB_PASSWORD,   // Contraseña desde .env
  database: process.env.DB_NAME,    // Nombre de la base de datos desde .env
});

db.connect(err => {
  if (err) {
    console.error('Error al conectar con la base de datos:', err);
    return;
  }
  console.log('Conexión exitosa a la base de datos');
});

// Configuración de la sesión
app.use(session({
    secret: 'secretKey',
    resave: false,
    saveUninitialized: false,
  }));

  // Configuración de Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

  
app.use(bodyParser.urlencoded({ extended: true }));

// Ruta para la página principal
app.get('/', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
  
  function requireLogin(req, res, next) {
    if (!req.session.user) {
      return res.redirect('/login.html');
    }
    next();
  }
  
  function requireRole(role) {
    return (req, res, next) => {
        if (req.session.user && role.includes(req.session.user.tipo_usuario)) {
            next();
        } else {
            res.status(403).send('Acceso denegado');
        }
    };
  }

  // Función para convertir fechas seriales de Excel a formato 'YYYY-MM-DD HH:MM:SS'
function excelSerialToDate(serial) {
  const MS_PER_DAY = 86400000; // Milisegundos en un día
  const EXCEL_EPOCH = new Date(Date.UTC(1899, 11, 30)); // Fecha base de Excel

  // Convertir el número serial en milisegundos y agregar la fecha base
  const date = new Date(EXCEL_EPOCH.getTime() + serial * MS_PER_DAY);

  // Formatear la fecha al formato compatible con MySQL
  const formattedDate = date.toISOString().slice(0, 19).replace('T', ' ');
  return formattedDate;
}

// Registro de usuario
app.post('/registrar', (req, res) => {
  const { nombre_usuario, password, codigo_acceso } = req.body;

  const query = 'SELECT tipo_usuario FROM codigos_acceso WHERE codigo = ?';
  db.query(query, [codigo_acceso], (err, results) => {
      if (err || results.length === 0) {
          return res.send('Código de acceso inválido');
      }

      const tipo_usuario = results[0].tipo_usuario;
      const hashedPassword = bcrypt.hashSync(password, 10);

      const insertUser = 'INSERT INTO usuarios (nombre_usuario, password_hash, tipo_usuario) VALUES (?, ?, ?)';
      db.query(insertUser, [nombre_usuario, hashedPassword, tipo_usuario], (err) => {
          if (err) return res.send('Error al registrar usuario');
          res.redirect('/login.html');
      });
  });
});

// Iniciar sesión
app.post('/login', (req, res) => {
  const { nombre_usuario, password } = req.body;

  // Consulta para obtener el usuario y su tipo
  const query = 'SELECT * FROM usuarios WHERE nombre_usuario = ?';
  db.query(query, [nombre_usuario], (err, results) => {
      if (err) {
          return res.send('Error al obtener el usuario');
      }

      if (results.length === 0) {
          return res.send('Usuario no encontrado');
      }

      const user = results[0];

      // Verificar la contraseña
      const isPasswordValid = bcrypt.compareSync(password, user.password_hash);
      if (!isPasswordValid) {
          return res.send('Contraseña incorrecta');
      }

      // Almacenar la información del usuario en la sesión
      req.session.user = {
        id: user.id,
        username: user.nombre_usuario,
        tipo_usuario: user.tipo_usuario.trim().toLowerCase()
    };

      // Redirigir al usuario a la página principal
      res.redirect('/');
  });
});

// Cerrar sesión
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login.html');
});

  // Ruta para registrar citas
  app.post('/registrar-citas', requireLogin, requireRole(['admin', 'medico']), (req, res) => {
    const { paciente, edad_paciente, fecha_hora, doctor, especialidad, id_doctor } = req.body;
  console.log(req.body);
    const query = 'INSERT INTO citas (paciente, edad_paciente, fecha_hora, doctor, especialidad, id_doctor) VALUES (?, ?, ?, ?, ?, ?)';
    db.query(query, [paciente, edad_paciente, fecha_hora, doctor, especialidad, id_doctor], (err, result) => {
      if (err) {
        return res.send('Error al guardar los datos en la base de datos.');
      }
      res.send(`Cita de ${paciente} guardada en la base de datos.`);
    });
  });

  // Ruta para mostrar todas las citas registradas
app.get('/citas', requireLogin, requireRole(['admin']), (req, res) => {
    db.query('SELECT * FROM citas', (err, results) => {
      if (err) {
        return res.send('Error al obtener los datos.');
      }
  
      let html = `
        <html>
        <head>
          <link rel="stylesheet" href="/styles.css">
          <title>Citas</title>
        </head>
        <body>
          <h1>Citas Registrados</h1>
          <table>
            <thead>
              <tr>
                <th>Número de cita</th>
                <th>Paciente</th>
                <th>Edad del paciente</th>
                <th>Fecha y hora</th>
                <th>Doctor</th>
                <th>Especialidad del doctor</th>
                <th>ID del doctor</th>
              </tr>
            </thead>
            <tbody>
      `;
  
      results.forEach(cita => {
        html += `
          <tr>
            <td>${cita.num_cita}</td>
            <td>${cita.paciente}</td>
            <td>${cita.edad_paciente}</td>
            <td>${cita.fecha_hora}</td>
            <td>${cita.doctor}</td>
            <td>${cita.especialidad}</td>
            <td>${cita.id_doctor}</td>
          </tr>
        `;
      });
  
      html += `
            </tbody>
          </table>
          <button onclick="window.location.href='/'">Volver</button>
        </body>
        </html>
      `;
  
      res.send(html);
    });
  });

  const upload = multer({ dest: 'uploads/' });

  app.post('/upload-citas', requireLogin, requireRole(['admin']), upload.single('excelFile'), (req, res) => {
    const filePath = req.file.path;
    const workbook = xlsx.readFile(filePath);
    const sheetName = workbook.SheetNames[0];
    const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);
  
    data.forEach(row => {
      const { paciente, edad_paciente, fecha_hora, doctor, especialidad, id_doctor } = row;
      const FechaHora = excelSerialToDate(fecha_hora);

      const sql = 'INSERT INTO citas (paciente, edad_paciente, fecha_hora, doctor, especialidad, id_doctor) VALUES (?, ?, ?, ?, ?, ?)';
      db.query(sql, [paciente, edad_paciente, FechaHora, doctor, especialidad, id_doctor], err => {
          if (err) {
              console.error('Error al insertar en la base de datos:', err);
          }
      });
  });

  res.send('<h1>Archivo cargado y datos guardados</h1><a href="/registrar-citas-excel.html">Volver</a>');
});

// Ruta para subir y procesar el archivo PDF
app.post('/subir-citas-pdf', upload.single('archivoPDF'), (req, res) => {
  const filePath = req.file.path; 

  const dataBuffer = fs.readFileSync(filePath);

  pdf(dataBuffer).then(data => {
    const textoPDF = data.text; 

    const lineas = textoPDF.split('\n'); 

    lineas.forEach(linea => {

      const campos = linea.split(',').map(campo => campo.trim());

      let [paciente, edad_paciente, fecha_hora, doctor, especialidad, id_doctor] = campos;

      if (paciente && edad_paciente && fecha_hora && doctor && especialidad && id_doctor) {

        fecha_hora = fecha_hora.replace(/(\d{4}-\d{2}-\d{2})(\d{2}:\d{2}:\d{2})/, '$1 $2');

        const query = `
          INSERT INTO citas (paciente, edad_paciente, fecha_hora, doctor, especialidad, id_doctor)
          VALUES (?, ?, ?, ?, ?, ?)
        `;

        db.query(query, [paciente, parseInt(edad_paciente), fecha_hora, doctor, especialidad, parseInt(id_doctor)], err => {
          if (err) {
            console.error('Error al guardar registro:', err);
          }
        });
      }
    });

    res.send('Citas guardadas correctamente desde el archivo PDF.');
    fs.unlinkSync(filePath); 
  }).catch(err => {
    res.status(500).send('Error al procesar el archivo PDF.');
    console.error('Error al procesar PDF:', err);
  });
});


  app.get('/download-citas', requireLogin, requireRole(['admin']), (req, res) => {
    const sql = `SELECT * FROM citas`;
    db.query(sql, (err, results) => {
      if (err) throw err;
    
      const worksheet = xlsx.utils.json_to_sheet(results);
      const workbook = xlsx.utils.book_new();
      xlsx.utils.book_append_sheet(workbook, worksheet, 'Citas');
    
      const filePath = path.join(__dirname, 'uploads', 'citas.xlsx');
      xlsx.writeFile(workbook, filePath);
      res.download(filePath, 'citas.xlsx');
    });
  });

// Ruta para descargar un PDF con los registros de la tabla
app.get('/descargar-citas-pdf', requireLogin, requireRole(['admin']), (req, res) => {
  // Crear un nuevo documento PDF
  const doc = new PDFDocument();
  
  // Configurar la cabecera de respuesta
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', 'attachment; filename=citas.pdf');

  // Pipe del documento al cliente
  doc.pipe(res);

  // Título del PDF
  doc.fontSize(18).text('Registros de Citas Médicas', { align: 'center' });
  doc.moveDown();

  // Query para obtener los registros de la tabla
  const query = 'SELECT * FROM citas';
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error al obtener los registros:', err);
      res.status(500).send('Error al generar el PDF');
      return;
    }

    // Agregar registros al PDF
    results.forEach(cita => {
      doc
        .fontSize(12)
        .text(`Paciente: ${cita.paciente}`, { continued: true })
        .text(` | Edad: ${cita.edad_paciente}`, { continued: true })
        .text(` | Fecha: ${cita.fecha_hora}`)
        .text(`Doctor: ${cita.doctor} | Especialidad: ${cita.especialidad} | ID Doctor: ${cita.id_doctor}`)
        .moveDown();
    });

    // Finalizar el documento
    doc.end();
  });
});

    // Ruta para obtener el tipo de usuario actual
app.get('/tipo-usuario', requireLogin, (req, res) => {
    res.json({ tipo_usuario: req.session.user.tipo_usuario });
  });
  
  // Ruta para que los médicos editen citas asignadas
  app.post('/editar-mis-citas', requireLogin, requireRole(['medico']), (req, res) => {
    const medicoId = req.session.user.id; 
    const { num_cita, paciente, edad_paciente, fecha_hora } = req.body; 
  
    const query = 'SELECT * FROM citas WHERE num_cita = ? AND id_doctor = ?';
    db.query(query, [num_cita, medicoId], (err, results) => {
        if (err || results.length === 0) {
            return res.status(403).send('No tienes permiso para modificar esta cita.');
        }
  
        const query = 'UPDATE citas SET paciente = ?, edad_paciente = ?, fecha_hora = ? WHERE num_cita = ? AND id_doctor = ?';
        db.query(query, [paciente, edad_paciente, fecha_hora, num_cita, medicoId], (err) => {
            if (err) {
                return res.status(500).send('Error al actualizar cita.');
            }
            res.send(`Cita de ${paciente} actualizada con éxito.`);
        });
    });
  });
  
  // Ruta para que los médicos editen citas asignadas
  app.post('/eliminar-mis-citas', requireLogin, requireRole(['medico']), (req, res) => {
    const medicoId = req.session.user.id; 
    const { num_cita } = req.body; 
    const query = 'DELETE FROM citas WHERE num_cita = ? AND id_doctor = ?';
    db.query(query, [num_cita, medicoId], (err, results) => {
        if (err || results.length === 0) {
            return res.status(403).send('No tienes permiso para eliminar esta cita.');
        }
            res.send(`Cita eliminada con éxito.`);
        });
    });

  // Ruta para que los doctores vean las citas asignadas
  app.get('/ver-mis-citas', requireLogin, requireRole(['medico']), (req, res) => {
    const medicoId = req.session.user.id; // ID del técnico desde la sesión
  
    // Filtrar equipos por usuario_id (relación lógica)
    const query = 'SELECT * FROM citas WHERE id_doctor = ?';
    db.query(query, [medicoId], (err, results) => {
        if (err) {
            return res.status(500).send('Error al obtener las citas asignadas.');
        }
        
        let html = `
        <html>
        <head>
          <link rel="stylesheet" href="/styles.css">
          <title>Citas</title>
        </head>
        <body>
          <h1>Citas Registradas</h1>
          <table>
            <thead>
              <tr>
                <th>Número de cita</th>
                <th>Paciente</th>
                <th>Edad del paciente</th>
                <th>Fecha y hora</th>
                <th>Doctor</th>
                <th>Especialidad del doctor</th>
                <th>ID del doctor</th>
              </tr>
            </thead>
            <tbody>
      `;
  
      results.forEach(cita => {
        html += `
          <tr>
            <td>${cita.num_cita}</td>
            <td>${cita.paciente}</td>
            <td>${cita.edad_paciente}</td>
            <td>${cita.fecha_hora}</td>
            <td>${cita.doctor}</td>
            <td>${cita.especialidad}</td>
            <td>${cita.id_doctor}</td>
          </tr>
        `;
      });
  
      html += `
            </tbody>
          </table>
          <button onclick="window.location.href='/'">Volver</button>
        </body>
        </html>
      `;
  
      res.send(html);
    });
  });

  // Ruta para que los doctores vean las citas asignadas
  app.get('/ver-mi-cita-proxima', requireLogin, requireRole(['medico']), (req, res) => {
    const medicoId = req.session.user.id; // ID del técnico desde la sesión
  
    // Filtrar equipos por usuario_id (relación lógica)
    const query = 'SELECT * FROM citas WHERE id_doctor = ? AND fecha_hora = (SELECT MIN(fecha_hora) FROM citas WHERE id_doctor = ? AND fecha_hora > NOW())';
    db.query(query, [medicoId, medicoId], (err, results) => {
        if (err) {
            return res.status(500).send('Error al obtener las cita próxima.');
        }
        
        let html = `
        <html>
        <head>
          <link rel="stylesheet" href="/styles.css">
          <title>Citas</title>
        </head>
        <body>
          <h1>Próxima Cita</h1>
          <table>
            <thead>
              <tr>
                <th>Número de cita</th>
                <th>Paciente</th>
                <th>Edad del paciente</th>
                <th>Fecha y hora</th>
                <th>Doctor</th>
                <th>Especialidad del doctor</th>
                <th>ID del doctor</th>
              </tr>
            </thead>
            <tbody>
      `;
  
      results.forEach(cita => {
        html += `
          <tr>
            <td>${cita.num_cita}</td>
            <td>${cita.paciente}</td>
            <td>${cita.edad_paciente}</td>
            <td>${cita.fecha_hora}</td>
            <td>${cita.doctor}</td>
            <td>${cita.especialidad}</td>
            <td>${cita.id_doctor}</td>
          </tr>
        `;
      });
  
      html += `
            </tbody>
          </table>
          <button onclick="window.location.href='/'">Volver</button>
        </body>
        </html>
      `;
  
      res.send(html);
    });
  });

// Ruta para mostrar edad promedio de los pacientes
app.get('/edadpromedio-mis-pacientes', requireLogin, requireRole(['medico']), (req, res) => {
  const medicoId = req.session.user.id; // ID del técnico desde la sesión

  // Filtrar equipos por usuario_id (relación lógica)
  const query = 'SELECT AVG(edad_paciente) AS edad_promedio FROM citas WHERE id_doctor = ?';
  db.query(query, [medicoId], (err, results) => {
      if (err) {
          return res.status(500).send('Error al obtener las citas asignadas.');
      }

      let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Edad Promedio mis Pacientes</title>
      </head>
      <body>
        <h1>Edad Promedio de mis Pacientes</h1>
        <table>
          <thead>
            <tr>
              <th>Edad Promedio de mis Pacientes</th>
            </tr>
          </thead>
          <tbody>
    `;

    results.forEach(paciente => {
      html += `
        <tr>
          <td>${paciente.edad_promedio}</td>
      `;
    });

    html += `
          </tbody>
        </table>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;

    res.send(html);
});
});


  // Ruta para que solo admin pueda ver todos los usuarios
  app.get('/ver-usuarios', requireLogin, requireRole(['admin']), (req, res) => {
    const query = 'SELECT * FROM usuarios';
  
    db.query(query, (err, results) => {
        if (err) {
          return res.send('Error al obtener usuarios');
          }
  
          let html = `
          <html>
          <head>
            <link rel="stylesheet" href="/styles.css">
            <title>Usuarios</title>
          </head>
          <body>
            <h1>Usuarios Registrados</h1>
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Nombre de Usuario</th>
                  <th>Tipo de Usuario</th>
                </tr>
              </thead>
              <tbody>
        `;
    
        results.forEach(usuario => {
          html += `
            <tr>
              <td>${usuario.id}</td>
              <td>${usuario.nombre_usuario}</td>
              <td>${usuario.tipo_usuario}</td>
          `;
        });
    
        html += `
              </tbody>
            </table>
            <button onclick="window.location.href='/'">Volver</button>
          </body>
          </html>
        `;
    
        res.send(html);
    });
  });

    // Ruta para que solo admin pueda ver todos los usuarios
    app.get('/ver-medicos', requireLogin, requireRole(['admin']), (req, res) => {
      const query = 'SELECT * FROM doctores';
    
      db.query(query, (err, results) => {
          if (err) {
            return res.send('Error al obtener usuarios');
            }
    
            let html = `
            <html>
            <head>
              <link rel="stylesheet" href="/styles.css">
              <title>Usuarios</title>
            </head>
            <body>
              <h1>Usuarios Registrados</h1>
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Doctor</th>
                    <th>Especialidad</th>
                    <th>Nombre de Usuario</th>
                  </tr>
                </thead>
                <tbody>
          `;
      
          results.forEach(doctor => {
            html += `
              <tr>
                <td>${doctor.id}</td>
                <td>${doctor.doctor}</td>
                <td>${doctor.especialidad}</td>
                <td>${doctor.nombre_usuario}</td>
            `;
          });
      
          html += `
                </tbody>
              </table>
              <button onclick="window.location.href='/'">Volver</button>
            </body>
            </html>
          `;
      
          res.send(html);
      });
    });

// Configuración de puerto
const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Servidor corriendo en el puerto ${port}`);
  });
