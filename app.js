import express from "express"
import { promises as fs } from "fs"
import { hashPass, comparePass, generarToken, jwtAuth } from "./utils.js"
import {v4 as uuidv4} from "uuid"
import Database from 'better-sqlite3'
import cors from "cors"
const app = express();
const port = 9000;

const db = new Database('./ecommerce.sqlite')

db.exec(`
  CREATE TABLE IF NOT EXISTS usuarios (
    id TEXT PRIMARY KEY,
    user_name TEXT,
    mail TEXT,
    tel TEXT,
    user_password TEXT
  );
`);

const leerBase = async () => {
    const users = await db.prepare("SELECT * FROM usuarios").all();
    return users
}

const mostrarUno = async (id) => {
    const user = await db.prepare("SELECT * FROM usuarios WHERE id = ?").get(id);
    return user
}
console.log("mostrar uno:", await mostrarUno("3257a02a-2bb5-4089-a936-2fdf173234e9"))
console.log(await leerBase())


app.use(express.json());
app.use(cors({
  origin: "*",
  methods: "GET,POST,PUT,DELETE,PATCH,OPTIONS",
   allowedHeaders: "Content-Type, Authorization"
}))

app.get("/products/:id", jwtAuth,async (req, res) => {
    const id = parseInt(req.params.id);
    if(!id) {
        res.status(400).json({message: "no etá acá el id bro"});
    }
    try {
        const data = await fs.readFile(`jsons/products/${id}.json`, 'utf8')
        const parseData = JSON.parse(data);
        res.status(200).json(parseData);
    }
    catch (err) {
        res.status(404).json({message: "No encontrado"});
    }
})

// Asumo que ya tenés express, db, mostrarUno y hashPass definidos/importados
app.put('/usuarios/:id',jwtAuth, async (req, res) => {
  const id = req.params.id;
  if (!id) {
    return res.status(400).json({ message: "Falta el id en la ruta" });
  }

  const { user_name, mail, tel, user_password } = req.body;

  try {
    const user = await mostrarUno(id);
    if (!user) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    user.user_name = typeof user_name === "string" && user_name.trim() !== "" ? user_name.trim() : user.user_name;
    user.mail = typeof mail === "string" && mail.trim() !== "" ? mail.trim() : user.mail;
    user.tel = typeof tel === "string" && tel.trim() !== "" ? tel.trim() : user.tel;

    if (typeof user_password === "string" && user_password.trim() !== "") {
      user.user_password = await hashPass(user_password);
    } else {
      user.user_password = user.user_password;
    }

    await db.prepare(
      "UPDATE usuarios SET user_name = ?, mail = ?, tel = ?, user_password = ? WHERE id = ?"
    ).run(user.user_name, user.mail, user.tel, user.user_password, id);

    const userToReturn = { ...user };
    delete userToReturn.user_password;

    return res.status(200).json(userToReturn);
  } catch (err) {
    console.error("Error actualizando usuario:", err);
    return res.status(500).json({ message: "Error interno del servidor" });
  }
});


app.get('/usuarios/:id', jwtAuth, async (req, res) => {
    const id = req.params.id;
    if(!id){
        res.status(400).json({message: "no etá acá el id bro"});
    }
    try{
        const user = await mostrarUno(id);
        res.status(200).json(user);
    }
    catch (err){
        res.status(404).json({message: "No encontrado"});
    }
})


app.get("/categories", jwtAuth, async (req, res) => {
    try {
        const data = await fs.readFile('jsons/cats/cat.json', 'utf8');
        const jsonData = JSON.parse(data);
        res.status(200).json(jsonData);

    } catch (err) {
        res.status(404).json({message: "no se encontró xd"});
    }
})


app.get("/categories/:id", jwtAuth, async (req, res) => {
    const id = parseInt(req.params.id);
    if(!id){
        res.status(400).json({message: "no etá acá el id bro"});
    }
    try{
        const data = await fs.readFile(`jsons/cats_products/${id}.json`, 'utf8')
        const parseData = JSON.parse(data);
        res.status(200).json(parseData);
    }
    catch (err){
        res.status(404).json({message: "No encontrado"});
    }
})



app.get("/comments/:id", jwtAuth, async (req, res) => {
    const id = parseInt(req.params.id);
    if(!id){
        res.status(400).json({message: "no es esté id bro"});
    }
    try{
        const data = await fs.readFile(`jsons/products_comments/${id}.json`, 'utf8')
        const parseData = JSON.parse(data);
        res.status(200).json(parseData);
}
    catch (err){
        res.status(404).json({message: "No encontrado xd"});
    }
})

app.post("/login", async (req, res) => {
  try {
    let { user_name, user_password } = req.body;
    if (!user_name || !user_password) {
      return res.status(400).json({ status: "error", message: "Faltan campos" });
    }

    user_name = String(user_name).trim().normalize('NFC');

   
    const user = db.prepare("SELECT id, user_name, mail, user_password FROM usuarios WHERE user_name = ? COLLATE NOCASE").get(user_name);

    if (!user) {
      return res.status(401).json({ message: "El usuario no existe" });
    }

    // comparar password (bcrypt)
    const match = await comparePass(user_password, user.user_password);
    if (!match) {
      return res.status(401).json({ message: "La contraseña no coincide" });
    }

    
    const token = generarToken(user);
    
    
    return res.status(200).json({ status: "ok", message: "Login successful", token });
  } catch (error) {
    console.error("Error en /login:", error.stack || error);
    return res.status(500).json({ status: "error", message: "Error interno del servidor" });
  }
});

app.post("/sign-up", async (req, res) => {
  try {
    let { user_name, mail, tel, user_password } = req.body;

    // validación mínima
    if (!user_name || !mail || !user_password) {
      return res.status(400).json({ status: "error", message: "Faltan campos obligatorios" });
    }

    // normalizar
    user_name = String(user_name).trim().toLowerCase();
    mail = String(mail).trim().toLowerCase();
    tel = tel ? String(tel).trim() : null;

    // comprobar existentes (opcional para feedback)
    const existingByMail = db.prepare("SELECT id FROM usuarios WHERE mail = ?").get(mail);
    if (existingByMail) {
      return res.status(409).json({ status: "mail-existe", message: "El mail ya existe" });
    }

    const existingByName = db.prepare("SELECT id FROM usuarios WHERE user_name = ? COLLATE BINARY").get(user_name);
    if (existingByName) {
      return res.status(409).json({ status: "username-existe", message: "El username ya existe" });
    }

    // hashear contraseña
    const hashed = await hashPass(user_password);

    // insertar
    const id = uuidv4();
    const insert = db.prepare(
      "INSERT INTO usuarios (id, user_name, mail, tel, user_password) VALUES (?, ?, ?, ?, ?)"
    );

    try {
      const result = insert.run(id, user_name, mail, tel, hashed);

      return res.status(201).json({
        status: "ok",
        insertedId: id,
        changes: result.changes,
        lastInsertRowid: result.lastInsertRowid
      });
    } catch (err) {
      // manejar constraint si hay UNIQUE en DB y hubo race-condition
      if (err && err.code === "SQLITE_CONSTRAINT") {
        return res.status(409).json({ status: "error", message: "Usuario o email ya existe (constraint)" });
      }
      throw err;
    }
  } catch (error) {
    console.error("Error en /sign-up:", error.stack || error);
    return res.status(500).json({ status: "error", message: "Error interno del servidor" });
  }
});

//TODO  
app.post('/cart', jwtAuth, async (req, res) => {
  
})

app.listen(port, () => {
    console.log(`Escuchando en el puerto http://localhost:${port}`)
})



