// api.js
import express from "express"
import { promises as fs } from "fs"
import { hashPass, comparePass, generarToken, jwtAuth } from "./utils.js"
import { v4 as uuidv4 } from "uuid"
import Database from 'better-sqlite3'
import cors from "cors"
import dotenv from 'dotenv'

dotenv.config() // asegurarse de que .env se cargue

const app = express();
const port = process.env.PORT || 9000;

const db = new Database('./ecommerce.sqlite')

// esquema mínimo
db.exec(`
  CREATE TABLE IF NOT EXISTS usuarios (
    id TEXT PRIMARY KEY,
    user_name TEXT,
    mail TEXT,
    tel TEXT,
    user_password TEXT
  );

  CREATE TABLE IF NOT EXISTS carrito (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    productos TEXT,
    FOREIGN KEY(user_id) REFERENCES usuarios(id) ON DELETE CASCADE
  );
`);

// helpers DB
const leerBase = async () => {
  const users = await db.prepare("SELECT * FROM usuarios").all();
  return users
}

const mostrarUno = async (id) => {
  const user = await db.prepare("SELECT * FROM usuarios WHERE id = ?").get(id);
  return user
}

app.use(express.json());
app.use(cors({
  origin: "*",
  methods: "GET,POST,PUT,DELETE,PATCH,OPTIONS",
  allowedHeaders: "Content-Type, Authorization"
}))

// GET product by id (usa jwtAuth)
app.get("/products/:id", jwtAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  if (!id && id !== 0) {
    return res.status(400).json({ message: "no etá acá el id bro" });
  }
  try {
    const data = await fs.readFile(`jsons/products/${id}.json`, 'utf8')
    const parseData = JSON.parse(data);
    return res.status(200).json(parseData);
  } catch (err) {
    return res.status(404).json({ message: "No encontrado" });
  }
})

// GET multiple products by ids query ?ids=1,2,3
app.get('/products', async (req, res) => {
  try {
    const ids = req.query.ids;
    if (!ids) {
      return res.status(400).json({ message: 'Faltan ids en la query' });
    }
    const idsParaUsar = String(ids).split(',').map(s => parseInt(s)).filter(n => !Number.isNaN(n));

    const products = await Promise.all(
      idsParaUsar.map(async id => {
        try {
          const data = await fs.readFile(`jsons/products/${id}.json`, 'utf8');
          return JSON.parse(data);
        } catch (err) {
          // si falta un producto, devolvemos null y luego filtramos
          return null;
        }
      })
    );

    const filtered = products.filter(Boolean);
    return res.status(200).json(filtered);

  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Error al obtener productos' });
  }
});

app.put('/usuarios/:id', jwtAuth, async (req, res) => {
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
    } // si no, se mantiene la password actual

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
  if (!id) {
    return res.status(400).json({ message: "no etá acá el id bro" });
  }
  try {
    const user = await mostrarUno(id);
    return res.status(200).json(user);
  } catch (err) {
    return res.status(404).json({ message: "No encontrado" });
  }
})

app.get("/categories", jwtAuth, async (req, res) => {
  try {
    const data = await fs.readFile('jsons/cats/cat.json', 'utf8');
    const jsonData = JSON.parse(data);
    return res.status(200).json(jsonData);
  } catch (err) {
    return res.status(404).json({ message: "no se encontró xd" });
  }
})

app.get("/categories/:id", jwtAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  if (!id && id !== 0) {
    return res.status(400).json({ message: "no etá acá el id bro" });
  }
  try {
    const data = await fs.readFile(`jsons/cats_products/${id}.json`, 'utf8')
    const parseData = JSON.parse(data);
    return res.status(200).json(parseData);
  } catch (err) {
    return res.status(404).json({ message: "No encontrado" });
  }
})

app.get("/comments/:id", jwtAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  if (!id && id !== 0) {
    return res.status(400).json({ message: "no es esté id bro" });
  }
  try {
    const data = await fs.readFile(`jsons/products_comments/${id}.json`, 'utf8')
    const parseData = JSON.parse(data);
    return res.status(200).json(parseData);
  } catch (err) {
    return res.status(404).json({ message: "No encontrado xd" });
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

    if (!user_name || !mail || !user_password) {
      return res.status(400).json({ status: "error", message: "Faltan campos obligatorios" });
    }

    user_name = String(user_name).trim().toLowerCase();
    mail = String(mail).trim().toLowerCase();
    tel = tel ? String(tel).trim() : null;

    const existingByMail = db.prepare("SELECT id FROM usuarios WHERE mail = ?").get(mail);
    if (existingByMail) {
      return res.status(409).json({ status: "mail-existe", message: "El mail ya existe" });
    }

    const existingByName = db.prepare("SELECT id FROM usuarios WHERE user_name = ? COLLATE BINARY").get(user_name);
    if (existingByName) {
      return res.status(409).json({ status: "username-existe", message: "El username ya existe" });
    }

    const hashed = await hashPass(user_password);
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

// GET carrito -> /cart?id=USER_ID
app.get('/cart', async (req, res) => {
  const idUsuario = req.query.id;
  if (!idUsuario) return res.status(400).json({ status: 'error', message: 'Falta id en query' });
  try {
    const dbIds = await db.prepare('SELECT productos FROM carrito WHERE user_id = ?').get(idUsuario)
    if (!dbIds || !dbIds.productos) return res.status(404).json({ status: 'error', message: 'Carrito no encontrado' })
    const ids = String(dbIds.productos).split(',').filter(Boolean)
    return res.status(200).json({ status: 'ok', message: 'ok', products: ids })
  } catch (err) {
    console.error('Error GET /cart', err);
    return res.status(500).json({ status: 'error', message: 'Error interno' });
  }
})

// PUT carrito -> /cart?ids=55,48,65&id=USER_ID
app.put('/cart', async (req, res) => {
  const ids = req.query.ids // string "55,48,65"
  const idUsuario = req.query.id

  if (!ids || !idUsuario) {
    return res.status(400).json({ status: 'error', message: 'Faltan parametros ids o id' });
  }

  try {
    let cart = await db.prepare(`SELECT * FROM carrito WHERE user_id = ?`).get(idUsuario);

    if (cart) {
      db.prepare(`UPDATE carrito SET productos = ? WHERE user_id = ?`).run(ids, idUsuario);
      cart = await db.prepare(`SELECT * FROM carrito WHERE user_id = ?`).get(idUsuario);
    } else {
      const cartID = uuidv4();
      db.prepare(`INSERT INTO carrito (id, user_id, productos) VALUES (?, ?, ?)`)
        .run(cartID, idUsuario, ids);
      cart = await db.prepare(`SELECT * FROM carrito WHERE id = ?`).get(cartID);
    }

    return res.status(200).json({ status: 'ok', message: 'ok', cart });
  } catch (err) {
    console.error('Error en PUT /cart', err);
    return res.status(500).json({ status: 'error', message: 'Error interno del servidor' });
  }
})

app.listen(port, () => {
  console.log(`Escuchando en el puerto http://localhost:${port}`)
})
