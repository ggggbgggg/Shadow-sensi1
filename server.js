require("dotenv").config();

const express = require("express");
const fs = require("fs");
const crypto = require("crypto");
const path = require("path");

const app = express();
app.use(express.json());
app.use(express.static("public"));

const DB = "keys.json";

if (!process.env.ADMIN_PASSWORD || !process.env.SECRET_KEY) {
  throw new Error("Configure ADMIN_PASSWORD e SECRET_KEY.");
}

if (!fs.existsSync(DB)) {
  fs.writeFileSync(DB, "[]");
}

function readKeys() {
  return JSON.parse(fs.readFileSync(DB, "utf8"));
}

function saveKeys(keys) {
  fs.writeFileSync(DB, JSON.stringify(keys, null, 2));
}

function hash(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function sign(value) {
  return crypto.createHmac("sha256", process.env.SECRET_KEY)
    .update(value).digest("hex");
}

function adminAuth(req, res, next) {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  const parts = token.split(".");

  if (parts.length !== 2) {
    return res.status(401).json({error:"Acesso negado"});
  }

  const expected = sign(parts[0]);

  if (!/^[a-f0-9]{64}$/.test(parts[1]) ||
      !crypto.timingSafeEqual(
        Buffer.from(parts[1]),
        Buffer.from(expected)
      )) {
    return res.status(401).json({error:"Token inválido"});
  }

  const timestamp = Number(parts[0].split(":")[0]);

  if (!Number.isFinite(timestamp) ||
      Date.now() - timestamp > 8 * 60 * 60 * 1000 ||
      timestamp > Date.now()) {
    return res.status(401).json({error:"Sessão expirada"});
  }

  next();
}

function token() {
  const data = Date.now() + ":" + crypto.randomBytes(20).toString("hex");
  return data + "." + sign(data);
}

// LOGIN ADMINISTRADOR
app.post("/api/admin/login", (req, res) => {
  if (req.body.password !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({error:"Senha incorreta"});
  }

  res.json({token:token()});
});

// LISTAR KEYS SEM REVELAR OS CÓDIGOS
app.get("/api/admin/keys", adminAuth, (req, res) => {
  const keys = readKeys().map(k => ({
    id:k.id,
    duration:k.duration,
    activatedAt:k.activatedAt,
    blocked:k.blocked,
    createdAt:k.createdAt
  }));

  res.json(keys);
});

// CRIAR KEY
app.post("/api/admin/keys", adminAuth, (req, res) => {
  const hours = Number(req.body.hours);

  if (![1,24,168,720].includes(hours)) {
    return res.status(400).json({error:"Validade inválida"});
  }

  const keys = readKeys();

  const code = "SHADOW-" +
    crypto.randomBytes(4).toString("hex").toUpperCase();

  keys.push({
    id:crypto.randomUUID(),
    codeHash:hash(code),
    duration:hours,
    activatedAt:null,
    blocked:false,
    createdAt:Date.now()
  });

  saveKeys(keys);

  res.json({code});
});

// BLOQUEAR KEY
app.post("/api/admin/keys/:id/block", adminAuth, (req, res) => {
  const keys = readKeys();
  const key = keys.find(k => k.id === req.params.id);

  if (!key) return res.status(404).json({error:"Key não encontrada"});

  key.blocked = !key.blocked;
  saveKeys(keys);

  res.json({blocked:key.blocked});
});

// EXCLUIR KEY
app.delete("/api/admin/keys/:id", adminAuth, (req, res) => {
  const keys = readKeys();
  const updated = keys.filter(k => k.id !== req.params.id);

  if (keys.length === updated.length) {
    return res.status(404).json({error:"Key não encontrada"});
  }

  saveKeys(updated);
  res.json({success:true});
});

// VALIDAR KEY
app.post("/api/login-key", (req, res) => {
  const code = String(req.body.key || "").trim();

  if (!code || code.length > 100) {
    return res.status(400).json({error:"Key inválida"});
  }

  const keys = readKeys();
  const key = keys.find(k => k.codeHash === hash(code));

  if (!key || key.blocked) {
    return res.status(403).json({error:"Key inválida ou bloqueada"});
  }

  if (!key.activatedAt) {
    key.activatedAt = Date.now();
    saveKeys(keys);
  }

  const expiresAt = key.activatedAt + key.duration * 3600000;
  const remaining = expiresAt - Date.now();

  if (remaining <= 0) {
    return res.status(403).json({error:"Key expirada"});
  }

  res.json({success:true, expiresAt, remaining});
});

// CONFERIR VALIDADE
app.post("/api/check-key", (req, res) => {
  const code = String(req.body.key || "").trim();
  const key = readKeys().find(k => k.codeHash === hash(code));

  if (!key || key.blocked) {
    return res.status(403).json({active:false});
  }

  const expiresAt = key.activatedAt
    ? key.activatedAt + key.duration * 3600000
    : null;

  const remaining = expiresAt ? expiresAt - Date.now() : null;

  res.json({
    active:remaining === null || remaining > 0,
    expiresAt,
    remaining
  });
});

app.get("/{*splat}", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(process.env.PORT || 3000, () => {
  console.log("SHADOW SENSI ONLINE!");
});
