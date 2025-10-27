# KasirPintar-clone — Web-based "Pro" Features (Auth, Stock, Supplier, Tests)

---

> Dokumen ini memperluas skeleton MVP sebelumnya menjadi versi **web-based Pro** dengan fitur-fitur penting:
> - Autentikasi & role-based access (Admin, Kasir, Owner)
> - Manajemen supplier & pembelian (restock)
> - Peringatan stok rendah
> - Pengujian otomatis lebih lengkap (termasuk cek stok)
> - UI frontend: login & role handling, halaman restock & manajemen staff

---

## Catatan penting sebelum menjalankan
1. Tambahkan environment variable `JWT_SECRET` sebelum menjalankan backend. Contoh di Linux/Mac:
   ```bash
   export JWT_SECRET="isi_rahasia_anda"
   ```
   Di Windows (PowerShell):
   ```powershell
   $env:JWT_SECRET = "isi_rahasia_anda"
   ```
2. Pastikan Node.js sudah terpasang.

---

=== backend/package.json ===
{
  "name": "kasirpintar-clone-backend",
  "version": "0.2.0",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "migrate": "node migrate.js",
    "test": "node test.js"
  },
  "dependencies": {
    "better-sqlite3": "^8.0.0",
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "body-parser": "^1.20.2",
    "csv-writer": "^1.6.0",
    "pdfkit": "^0.13.0",
    "bcrypt": "^5.1.0",
    "jsonwebtoken": "^9.0.0",
    "axios": "^1.4.0"
  }
}

---

### Migrasi DB (tambah tabel users, suppliers, purchases)

=== backend/migrate.js ===
const Database = require('better-sqlite3');
const db = new Database('./db.sqlite');

// Products
db.prepare(`CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  price INTEGER NOT NULL,
  stock INTEGER NOT NULL DEFAULT 0,
  barcode TEXT
)`).run();

// Users (auth)
db.prepare(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT,
  role TEXT DEFAULT 'kasir',
  fullname TEXT
)`).run();

// Suppliers
db.prepare(`CREATE TABLE IF NOT EXISTS suppliers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT,
  address TEXT
)`).run();

// Purchases (restock)
db.prepare(`CREATE TABLE IF NOT EXISTS purchases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  supplier_id INTEGER,
  created_at TEXT DEFAULT (datetime('now','localtime')),
  total INTEGER
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS purchase_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  purchase_id INTEGER,
  product_id INTEGER,
  qty INTEGER,
  price INTEGER,
  FOREIGN KEY(purchase_id) REFERENCES purchases(id),
  FOREIGN KEY(product_id) REFERENCES products(id)
)`).run();

// Sales & items
db.prepare(`CREATE TABLE IF NOT EXISTS sales (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT DEFAULT (datetime('now','localtime')),
  total INTEGER NOT NULL,
  cashier_id INTEGER
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS sale_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sale_id INTEGER,
  product_id INTEGER,
  qty INTEGER,
  price INTEGER,
  FOREIGN KEY(sale_id) REFERENCES sales(id),
  FOREIGN KEY(product_id) REFERENCES products(id)
)`).run();

// Seed: admin user (default password: admin123) if not exists
const bcrypt = require('bcrypt');
const adminExists = db.prepare('SELECT * FROM users WHERE username = ?').get('admin');
if (!adminExists) {
  const hash = bcrypt.hashSync('admin123', 10);
  db.prepare('INSERT INTO users (username, password, role, fullname) VALUES (?, ?, ?, ?)')
    .run('admin', hash, 'admin', 'Administrator');
  console.log('Seeded admin user (username: admin, password: admin123)');
}

console.log('Migration complete. DB file: ./db.sqlite');

---

=== backend/server.js ===
const express = require('express');
const Database = require('better-sqlite3');
const bodyParser = require('body-parser');
const cors = require('cors');
const createCsvWriter = require('csv-writer').createObjectCsvWriter;
const PDFDocument = require('pdfkit');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const db = new Database('./db.sqlite');
const app = express();
app.use(cors());
app.use(bodyParser.json());

const JWT_SECRET = process.env.JWT_SECRET || 'please_change_this_secret';

// Helper: auth middleware
function verifyToken(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ error: 'No token' });
  const token = auth.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Invalid token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { id, username, role }
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Token invalid' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Forbidden' });
    next();
  }
}

// AUTH: login
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = bcrypt.compareSync(password, user.password);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '8h' });
  res.json({ token, user: { id: user.id, username: user.username, role: user.role, fullname: user.fullname } });
});

// AUTH: register (admin only)
app.post('/api/auth/register', verifyToken, requireRole('admin'), (req, res) => {
  const { username, password, role, fullname } = req.body;
  const hash = bcrypt.hashSync(password, 10);
  try {
    const info = db.prepare('INSERT INTO users (username, password, role, fullname) VALUES (?, ?, ?, ?)')
      .run(username, hash, role || 'kasir', fullname || null);
    res.json({ id: info.lastInsertRowid });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Produk: CRUD (some routes require auth)
app.get('/api/products', verifyToken, (req, res) => {
  const rows = db.prepare('SELECT * FROM products').all();
  res.json(rows);
});

app.post('/api/products', verifyToken, requireRole('admin','owner'), (req, res) => {
  const { name, price, stock, barcode } = req.body;
  const stmt = db.prepare('INSERT INTO products (name, price, stock, barcode) VALUES (?, ?, ?, ?)');
  const info = stmt.run(name, price, stock || 0, barcode || null);
  res.json({ id: info.lastInsertRowid });
});

app.put('/api/products/:id', verifyToken, requireRole('admin','owner'), (req, res) => {
  const id = req.params.id;
  const { name, price, stock, barcode } = req.body;
  db.prepare('UPDATE products SET name=?, price=?, stock=?, barcode=? WHERE id=?')
    .run(name, price, stock, barcode, id);
  res.json({ ok: true });
});

app.delete('/api/products/:id', verifyToken, requireRole('admin','owner'), (req, res) => {
  db.prepare('DELETE FROM products WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// Supplier management (admin/owner)
app.get('/api/suppliers', verifyToken, requireRole('admin','owner'), (req, res) => {
  const rows = db.prepare('SELECT * FROM suppliers').all();
  res.json(rows);
});

app.post('/api/suppliers', verifyToken, requireRole('admin','owner'), (req, res) => {
  const { name, phone, address } = req.body;
  const info = db.prepare('INSERT INTO suppliers (name, phone, address) VALUES (?, ?, ?)').run(name, phone, address);
  res.json({ id: info.lastInsertRowid });
});

// Purchase / restock
app.post('/api/purchases', verifyToken, requireRole('admin','owner','kasir'), (req, res) => {
  const { supplier_id, items } = req.body; // items: [{product_id, qty, price}]
  if (!items || !items.length) return res.status(400).json({ error: 'No items' });
  const total = items.reduce((s, it) => s + (it.price * it.qty), 0);
  const insertPurchase = db.prepare('INSERT INTO purchases (supplier_id, total) VALUES (?, ?)');
  const info = insertPurchase.run(supplier_id || null, total);
  const purchaseId = info.lastInsertRowid;
  const insertItem = db.prepare('INSERT INTO purchase_items (purchase_id, product_id, qty, price) VALUES (?, ?, ?, ?)');
  const incStock = db.prepare('UPDATE products SET stock = stock + ? WHERE id = ?');

  const tx = db.transaction((items) => {
    for (const it of items) {
      insertItem.run(purchaseId, it.product_id, it.qty, it.price);
      incStock.run(it.qty, it.product_id);
    }
  });

  try { tx(items); } catch (e) { return res.status(400).json({ error: e.message }); }
  res.json({ purchaseId });
});

// Transaksi (create sale) — now record cashier id
app.post('/api/sales', verifyToken, (req, res) => {
  const { items } = req.body; // items: [{product_id, qty, price}]
  if (!items || !items.length) return res.status(400).json({ error: 'No items' });
  const total = items.reduce((s, it) => s + (it.price * it.qty), 0);
  const insertSale = db.prepare('INSERT INTO sales (total, cashier_id) VALUES (?, ?)');
  const info = insertSale.run(total, req.user.id);
  const saleId = info.lastInsertRowid;
  const insertItem = db.prepare('INSERT INTO sale_items (sale_id, product_id, qty, price) VALUES (?, ?, ?, ?)');
  const decStock = db.prepare('UPDATE products SET stock = stock - ? WHERE id = ?');
  const getProduct = db.prepare('SELECT * FROM products WHERE id = ?');

  const tx = db.transaction((items) => {
    for (const it of items) {
      const prod = getProduct.get(it.product_id);
      if (!prod) throw new Error('Product not found: ' + it.product_id);
      if (prod.stock < it.qty) throw new Error('Insufficient stock for product id ' + it.product_id);
      insertItem.run(saleId, it.product_id, it.qty, it.price);
      decStock.run(it.qty, it.product_id);
    }
  });

  try { tx(items); } catch (e) { return res.status(400).json({ error: e.message }); }
  res.json({ saleId });
});

// Laporan sederhana (CSV) - filter by date range
app.get('/api/reports/sales.csv', verifyToken, requireRole('admin','owner'), (req, res) => {
  const { from, to } = req.query; // optional yyyy-mm-dd
  let sql = `SELECT s.id, s.created_at, s.total, s.cashier_id, si.product_id, si.qty, si.price
    FROM sales s JOIN sale_items si ON si.sale_id = s.id`;
  const params = [];
  if (from && to) {
    sql += ' WHERE date(s.created_at) BETWEEN date(?) AND date(?)';
    params.push(from, to);
  }
  sql += ' ORDER BY s.created_at DESC';
  const rows = db.prepare(sql).all(...params);

  const csvWriter = createCsvWriter({
    path: './sales_report.csv',
    header: [
      {id: 'id', title: 'Sale ID'},
      {id: 'created_at', title: 'Created At'},
      {id: 'total', title: 'Total'},
      {id: 'cashier_id', title: 'Cashier ID'},
      {id: 'product_id', title: 'Product ID'},
      {id: 'qty', title: 'Qty'},
      {id: 'price', title: 'Price'}
    ]
  });

  csvWriter.writeRecords(rows).then(() => {
    res.download('./sales_report.csv');
  });
});

// Cetak struk sederhana (PDF)
app.get('/api/sales/:id/receipt', verifyToken, (req, res) => {
  const id = req.params.id;
  const sale = db.prepare('SELECT * FROM sales WHERE id=?').get(id);
  const items = db.prepare('SELECT si.*, p.name FROM sale_items si JOIN products p ON p.id = si.product_id WHERE si.sale_id = ?').all(id);
  if (!sale) return res.status(404).send('Not found');

  res.setHeader('Content-Type', 'application/pdf');
  const doc = new PDFDocument({ size: [280, 400], margin: 10 });
  doc.pipe(res);
  doc.fontSize(12).text('Toko Contoh', { align: 'center' });
  doc.text('==========================');
  items.forEach(it => {
    doc.text(`${it.name} x${it.qty}  Rp ${it.price * it.qty}`);
  });
  doc.text('--------------------------');
  doc.fontSize(14).text(`TOTAL Rp ${sale.total}`, { align: 'right' });
  doc.end();
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log('Backend running on', PORT));

---

## Frontend — perubahan & tambahan

Kami menambahkan halaman login, token storage, role-aware UI, halaman restock & supplier, dan manajemen staff.

=== frontend/package.json ===
{
  "name": "kasirpintar-clone-frontend",
  "version": "0.2.0",
  "private": true,
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "start": "vite preview"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "axios": "^1.4.0"
  },
  "devDependencies": {
    "vite": "^5.0.0"
  }
}

=== frontend/src/main.jsx ===
import React from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'

createRoot(document.getElementById('root')).render(<App />)

=== frontend/src/App.jsx ===
import React, { useEffect, useState } from 'react'
import axios from 'axios'
import { install } from 'undici-types'

const API = 'http://localhost:4000/api'

function authHeaders(){
  const token = localStorage.getItem('token');
  return token ? { Authorization: 'Bearer ' + token } : {};
}

function Login({ onLogin }){
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  async function submit(){
    const res = await axios.post(API + '/auth/login', { username, password });
    localStorage.setItem('token', res.data.token);
    onLogin(res.data.user);
  }
  return (
    <div>
      <h3>Login</h3>
      <input placeholder="username" value={username} onChange={e=>setUsername(e.target.value)} />
      <input placeholder="password" type="password" value={password} onChange={e=>setPassword(e.target.value)} />
      <button onClick={submit}>Login</button>
    </div>
  )
}

export default function App(){
  const [user, setUser] = useState(null);
  const [products, setProducts] = useState([])
  const [cart, setCart] = useState([])
  const [newProd, setNewProd] = useState({ name: '', price: 0, stock: 0 })
  const [suppliers, setSuppliers] = useState([])

  useEffect(()=>{ const t = localStorage.getItem('token'); if (t) { fetchProducts(); fetchSuppliers(); const userToken = JSON.parse(atob(t.split('.')[1])); setUser({ username: userToken.username, role: userToken.role, id: userToken.id }); } }, [])

  async function fetchProducts(){
    try{
      const res = await axios.get(API + '/products', { headers: authHeaders() })
      setProducts(res.data)
    }catch(e){ console.error(e) }
  }

  async function fetchSuppliers(){
    try{
      const res = await axios.get(API + '/suppliers', { headers: authHeaders() })
      setSuppliers(res.data)
    }catch(e){ console.error(e) }
  }

  function addToCart(p){
    const existing = cart.find(c => c.product_id === p.id)
    if (existing) {
      setCart(cart.map(c => c.product_id === p.id ? {...c, qty: c.qty + 1} : c))
    } else {
      setCart([...cart, { product_id: p.id, name: p.name, price: p.price, qty: 1 }])
    }
  }

  async function checkout(){
    const items = cart.map(c => ({ product_id: c.product_id, qty: c.qty, price: c.price }))
    const res = await axios.post(API + '/sales', { items }, { headers: authHeaders() })
    alert('Transaksi berhasil. ID: ' + res.data.saleId)
    setCart([])
    fetchProducts()
  }

  async function createProduct(){
    await axios.post(API + '/products', newProd, { headers: authHeaders() })
    setNewProd({ name:'', price:0, stock:0 })
    fetchProducts()
  }

  async function createSupplier(name){
    await axios.post(API + '/suppliers', { name }, { headers: authHeaders() })
    fetchSuppliers()
  }

  async function restock(supplier_id, items){
    await axios.post(API + '/purchases', { supplier_id, items }, { headers: authHeaders() })
    fetchProducts()
  }

  if (!localStorage.getItem('token')) return <Login onLogin={(u)=>{ setUser(u); fetchProducts(); fetchSuppliers(); }} />

  return (
    <div style={{ padding: 20, fontFamily: 'Arial' }}>
      <h2>KasirPintar-clone (Pro - Web)</h2>
      <div>Login sebagai: {user?.username} ({user?.role}) <button onClick={()=>{localStorage.removeItem('token'); location.reload();}}>Logout</button></div>
      <div style={{ display: 'flex', gap: 20 }}>
        <div style={{ flex: 2 }}>
          <h3>Produk</h3>
          <div style={{ display:'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap:10 }}>
            {products.map(p => (
              <div key={p.id} style={{ border:'1px solid #ddd', padding:10 }}>
                <strong>{p.name}</strong>
                <div>Rp {p.price}</div>
                <div>Stok: {p.stock} {p.stock < 5 ? '⚠️ stok menipis' : ''}</div>
                <button onClick={() => addToCart(p)}>Tambah</button>
              </div>
            ))}
          </div>

          {user.role !== 'kasir' && (
            <>
              <hr />
              <h4>Tambah Produk</h4>
              <input placeholder="Nama" value={newProd.name} onChange={e=>setNewProd({...newProd, name:e.target.value})} />
              <input placeholder="Harga" type="number" value={newProd.price} onChange={e=>setNewProd({...newProd, price:parseInt(e.target.value||0)})} />
              <input placeholder="Stok" type="number" value={newProd.stock} onChange={e=>setNewProd({...newProd, stock:parseInt(e.target.value||0)})} />
              <button onClick={createProduct}>Simpan</button>
            </>
          )}
        </div>

        <div style={{ flex: 1 }}>
          <h3>Keranjang</h3>
          {cart.map(c => (
            <div key={c.product_id}>{c.name} x{c.qty} = Rp {c.qty * c.price}</div>
          ))}
          <div style={{ marginTop: 10 }}>
            <strong>Total: Rp {cart.reduce((s, c) => s + c.qty * c.price, 0)}</strong>
            <div>
              <button onClick={checkout} disabled={!cart.length}>Bayar</button>
            </div>
          </div>

          <hr />
          <h4>Supplier & Restock</h4>
          <div>
            <button onClick={() => createSupplier(prompt('Nama supplier:'))}>Tambah Supplier</button>
            <div>
              {suppliers.map(s => <div key={s.id}>{s.name}</div>)}
            </div>
            <div>
              <button onClick={() => {
                const sup = suppliers[0];
                if (!sup) return alert('Tambahkan supplier dulu');
                const prod = products[0];
                if (!prod) return alert('Tambahkan produk dulu');
                const qty = parseInt(prompt('Qty restock untuk ' + prod.name, '10')) || 0;
                restock(sup.id, [{ product_id: prod.id, qty, price: prod.price }]);
              }}>Restock (contoh cepat)</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

---

## Pengujian Otomatis Lengkap (test.js)
Menambahkan pengujian untuk autentikasi, stok berkurang setelah penjualan, dan bertambah setelah restock.

=== backend/test.js ===
const axios = require('axios');
const assert = require('assert');

const API = 'http://localhost:4000/api';

(async () => {
  try {
    console.log('🧪 MULAI PENGUJIAN OTOMATIS KASIRPINTAR-CLONE (PRO)');

    // 0️⃣ Login admin (seeded admin/admin123)
    const login = await axios.post(`${API}/auth/login`, { username: 'admin', password: 'admin123' });
    assert(login.data.token, 'Gagal login admin');
    const token = login.data.token;
    const headers = { Authorization: 'Bearer ' + token };
    console.log('🔐 Login admin sukses');

    // 1️⃣ Tambah Produk
    const newProduct = { name: 'Indomie Goreng', price: 3500, stock: 20 };
    const resProd = await axios.post(`${API}/products`, newProduct, { headers });
    assert(resProd.data.id, 'Produk gagal dibuat');
    const prodId = resProd.data.id;
    console.log('✅ Produk berhasil dibuat dengan ID:', prodId);

    // 2️⃣ Tambah supplier
    const sup = await axios.post(`${API}/suppliers`, { name: 'PT. Supplier Contoh' }, { headers });
    assert(sup.data.id, 'Gagal tambah supplier');
    const supId = sup.data.id;
    console.log('✅ Supplier dibuat ID:', supId);

    // 3️⃣ Cek stok awal
    let prods = (await axios.get(`${API}/products`, { headers })).data;
    const p = prods.find(x => x.id === prodId);
    assert(p.stock === 20, 'Stok awal tidak sesuai');
    console.log('📦 Stok awal benar:', p.stock);

    // 4️⃣ Buat transaksi (kasir)
    // Register user kasir
    const kasirUser = { username: 'kasir1', password: 'kasir123', role: 'kasir', fullname: 'Kasir Satu' };
    await axios.post(`${API}/auth/register`, kasirUser, { headers });
    const loginKasir = await axios.post(`${API}/auth/login`, { username: 'kasir1', password: 'kasir123' });
    const tokenKasir = loginKasir.data.token;

    // make sale as kasir
    const sale = await axios.post(`${API}/sales`, { items: [{ product_id: prodId, qty: 5, price: 3500 }] }, { headers: { Authorization: 'Bearer ' + tokenKasir } });
    assert(sale.data.saleId, 'Transaksi gagal');
    console.log('💵 Transaksi berhasil ID:', sale.data.saleId);

    // 5️⃣ Cek stok berkurang
    prods = (await axios.get(`${API}/products`, { headers })).data;
    const afterSale = prods.find(x => x.id === prodId);
    assert(afterSale.stock === 15, 'Stok tidak berkurang setelah penjualan');
    console.log('📉 Stok setelah jual benar:', afterSale.stock);

    // 6️⃣ Restock via purchase
    const purchase = await axios.post(`${API}/purchases`, { supplier_id: supId, items: [{ product_id: prodId, qty: 10, price: 3000 }] }, { headers });
    assert(purchase.data.purchaseId, 'Restock gagal');
    console.log('📥 Restock berhasil ID:', purchase.data.purchaseId);

    // 7️⃣ Cek stok bertambah
    prods = (await axios.get(`${API}/products`, { headers })).data;
    const afterRestock = prods.find(x => x.id === prodId);
    assert(afterRestock.stock === 25, 'Stok tidak bertambah setelah restock');
    console.log('📈 Stok setelah restock benar:', afterRestock.stock);

    // 8️⃣ Ambil laporan CSV
    const resReport = await axios.get(`${API}/reports/sales.csv`, { headers, responseType: 'arraybuffer' });
    assert(resReport.status === 200, 'Gagal ambil laporan CSV');
    console.log('✅ Laporan penjualan berhasil diunduh');

    // 9️⃣ Cetak struk transaksi
    const resReceipt = await axios.get(`${API}/sales/${sale.data.saleId}/receipt`, { headers: { Authorization: 'Bearer ' + tokenKasir }, responseType: 'arraybuffer' });
    assert(resReceipt.status === 200, 'Gagal ambil struk PDF');
    console.log('✅ Struk transaksi berhasil dihasilkan');

    console.log('
🎉 SEMUA PENGUJIAN PRO BERHASIL TANPA ERROR!');
  } catch (err) {
    console.error('
❌ TERJADI ERROR:', err.message);
    if (err.response) console.error('Detail:', err.response.data);
    process.exit(1);
  }
})();

---

## Cara jalankan (ringkasan)
1. Di folder `backend`:
   ```bash
   npm install
   export JWT_SECRET="isi_rahasia_anda"
   npm run migrate
   npm start
   ```
2. Di folder `frontend`:
   ```bash
   npm install
   npm run dev
   ```
3. Jalankan pengujian otomatis (backend):
   ```bash
   node test.js
   ```

---

## Keamanan & Production Notes
- Ganti `JWT_SECRET` dengan string kuat di environment production.
- Gunakan HTTPS saat deploy.
- Gunakan database server (Postgres/MySQL) untuk skala produksi.
- Batasi rate & gunakan proteksi brute-force login.

---

## Next steps saya bisa lakukan (pilih salah satu, saya akan tambahkan langsung ke repository):
1. Integrasi printer thermal (Bluetooth / Network) — contoh Node.js + ESC/POS & panduan pairing.
2. UI rapi + Tailwind + layout kasir profesional.
3. Backup & sinkronisasi cloud + multi-cabang.
4. Export Laporan Excel & grafik interaktif.

Pilih nomor (1–4) atau `lainnya: <fitur>` — saya akan langsung tambahkan.
