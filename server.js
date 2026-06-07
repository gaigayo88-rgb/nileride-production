'use strict';

const express   = require('express');
const cors      = require('cors');
const path      = require('path');
const crypto    = require('crypto');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const { MongoClient, ObjectId } = require('mongodb');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Config ────────────────────────────────────────────────────
const MONGO_URI  = process.env.MONGO_URI      || '';
const JWT_SECRET = process.env.JWT_SECRET     || 'nileride-secret-2025';
const ADMIN_PWD  = process.env.ADMIN_PASSWORD || 'NileRide2025!';
const ADMIN_TOK  = crypto.createHash('sha256').update(ADMIN_PWD).digest('hex');

// ── MongoDB connection ────────────────────────────────────────
let db;
async function connectDB() {
  if (!MONGO_URI) {
    console.error('MONGO_URI env var not set.');
    process.exit(1);
  }

  // Auto-fix URI — adds ?retryWrites=true&w=majority if missing
  let uri = MONGO_URI.trim();
  if (uri.includes('.net/') && !uri.includes('?')) {
    uri += '?retryWrites=true&w=majority&appName=nileride';
    console.log('Auto-fixed URI: added query options');
  }
  if (uri.match(/\.net\/?$/) || uri.endsWith('.net')) {
    uri = uri.replace(/\/?$/, '') + '/nileride?retryWrites=true&w=majority&appName=nileride';
    console.log('Auto-fixed URI: added database name and options');
  }

  console.log('Connecting to MongoDB...');
  const client = new MongoClient(uri);
  await client.connect();
  db = client.db('nileride');
  // Indexes — safe to run every startup
  await db.collection('users').createIndex({ phone: 1 }, { unique: true, sparse: true });
  await db.collection('users').createIndex({ email: 1 }, { unique: true, sparse: true });
  await db.collection('rides').createIndex({ userId: 1 });
  await db.collection('rides').createIndex({ createdAt: -1 });
  console.log('✅  MongoDB connected');
}

// ── Middleware ────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Helpers ───────────────────────────────────────────────────
function makeToken(user) {
  return jwt.sign(
    { id: user._id.toString(), name: user.name, phone: user.phone || '', email: user.email || '' },
    JWT_SECRET, { expiresIn: '60d' }
  );
}

function requireAuth(req, res, next) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return res.status(401).json({ error: 'Please log in' });
  try {
    req.user = jwt.verify(h.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Session expired — please log in again' });
  }
}

function requireAdmin(req, res, next) {
  const t = req.headers['x-admin-token'] || req.query.token || '';
  if (t !== ADMIN_TOK) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

function requireDriver(req, res, next) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return res.status(401).json({ error: 'Login required' });
  try {
    const d = jwt.verify(h.slice(7), JWT_SECRET);
    if (!d.isDriver) return res.status(403).json({ error: 'Drivers only' });
    req.driver = d;
    next();
  } catch {
    res.status(401).json({ error: 'Session expired' });
  }
}

function genRef() {
  const c = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  return 'NR-' + Array.from({ length: 6 }, () => c[Math.floor(Math.random() * c.length)]).join('');
}

const BASE_FARE = { 'boda-boda': 200, sedan: 500, suv: 900 };
const PER_KM    = { 'boda-boda': 50,  sedan: 80,  suv: 120 };
const DISTANCES = {
  'cbd-gudele':8,'cbd-munuki':6,'cbd-jebel':9,'cbd-lologo':7,'cbd-atlabara':3,
  'cbd-airport':12,'cbd-konyo':2,'cbd-malakal':4,'cbd-tong':10,
  'gudele-munuki':10,'munuki-jebel':8,'airport-gudele':15,'jebel-lologo':6,
};
function estimateFare(type, pickup, dest, isNight) {
  const base = BASE_FARE[type] || 500;
  const pkm  = PER_KM[type] || 80;
  const p    = (pickup || '').toLowerCase();
  const d    = (dest   || '').toLowerCase();
  let km = null;
  for (const [key, v] of Object.entries(DISTANCES)) {
    const [a, b] = key.split('-');
    if ((p.includes(a) && d.includes(b)) || (p.includes(b) && d.includes(a))) { km = v; break; }
  }
  if (!km) km = Math.floor(Math.random() * 10) + 4;
  let fare = base + km * pkm;
  if (isNight) fare = Math.round(fare * 1.2);
  return { fare, km };
}

// ════════════════════════════════════════════════════════════
// CUSTOMER AUTH
// ════════════════════════════════════════════════════════════

// POST /api/register
app.post('/api/register', async (req, res) => {
  try {
    const name     = (req.body.name     || '').trim();
    const phone    = (req.body.phone    || '').trim().replace(/\s+/g, '');
    const email    = (req.body.email    || '').trim().toLowerCase();
    const password =  req.body.password || '';

    if (!name)                                    return res.status(400).json({ error: 'Enter your full name' });
    if (!phone && !email)                         return res.status(400).json({ error: 'Enter a phone number or email address' });
    if (password.length < 6)                      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    if (email && !/^\S+@\S+\.\S+$/.test(email))  return res.status(400).json({ error: 'Email address is not valid' });
    if (phone) {
      const digits = phone.replace(/[^\d]/g, '');
      if (digits.length < 8) return res.status(400).json({ error: 'Phone number is too short' });
    }

    // Check duplicate manually — avoids any index conflict error leaking
    const orQuery = [];
    if (phone) orQuery.push({ phone });
    if (email) orQuery.push({ email });
    const existing = await db.collection('users').findOne({ $or: orQuery });
    if (existing) return res.status(409).json({ error: 'An account with this phone or email already exists. Please log in.' });

    const hash = await bcrypt.hash(password, 10);
    const userDoc = {
      name,
      password: hash,
      role: 'customer',
      totalRides: 0,
      createdAt: new Date(),
    };
    if (phone) userDoc.phone = phone;
    if (email) userDoc.email = email;

    const result = await db.collection('users').insertOne(userDoc);
    const newUser = { _id: result.insertedId, ...userDoc };
    return res.status(201).json({
      success: true,
      token: makeToken(newUser),
      user: { id: newUser._id, name: newUser.name, phone: newUser.phone || '', email: newUser.email || '' },
    });

  } catch (err) {
    console.error('[register]', err.message);
    return res.status(500).json({ error: 'Could not create account — please try again' });
  }
});

// POST /api/login
app.post('/api/login', async (req, res) => {
  try {
    const phone    = (req.body.phone    || '').trim().replace(/\s+/g, '');
    const email    = (req.body.email    || '').trim().toLowerCase();
    const password =  req.body.password || '';
    const id = phone || email;

    if (!id)       return res.status(400).json({ error: 'Enter your phone number or email' });
    if (!password) return res.status(400).json({ error: 'Enter your password' });

    const query = phone ? { phone } : { email };
    const user  = await db.collection('users').findOne(query);
    if (!user) return res.status(401).json({ error: 'No account found — please register first' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: 'Wrong password — try again' });

    return res.json({
      success: true,
      token: makeToken(user),
      user: { id: user._id, name: user.name, phone: user.phone || '', email: user.email || '', totalRides: user.totalRides || 0 },
    });
  } catch (err) {
    console.error('[login]', err.message);
    return res.status(500).json({ error: 'Something went wrong — try again' });
  }
});

// GET /api/me
app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const user = await db.collection('users').findOne({ _id: new ObjectId(req.user.id) });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ id: user._id, name: user.name, phone: user.phone || '', email: user.email || '', totalRides: user.totalRides || 0, createdAt: user.createdAt });
  } catch (err) {
    res.status(500).json({ error: 'Something went wrong' });
  }
});

// PATCH /api/me
app.patch('/api/me', requireAuth, async (req, res) => {
  try {
    const { name, email, password, newPassword } = req.body || {};
    const upd = {};
    if (name)  upd.name  = name.trim();
    if (email) upd.email = email.trim().toLowerCase();
    if (newPassword) {
      if (!password) return res.status(400).json({ error: 'Current password required' });
      const user = await db.collection('users').findOne({ _id: new ObjectId(req.user.id) });
      if (!user) return res.status(404).json({ error: 'Not found' });
      const ok = await bcrypt.compare(password, user.password);
      if (!ok) return res.status(401).json({ error: 'Current password is incorrect' });
      upd.password = await bcrypt.hash(newPassword, 10);
    }
    await db.collection('users').updateOne({ _id: new ObjectId(req.user.id) }, { $set: upd });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Update failed' });
  }
});

// ════════════════════════════════════════════════════════════
// DRIVER AUTH
// ════════════════════════════════════════════════════════════

app.post('/api/driver/login', async (req, res) => {
  try {
    const { phone, password } = req.body || {};
    if (!phone || !password) return res.status(400).json({ error: 'Phone and password required' });
    const driver = await db.collection('drivers').findOne({ phone: phone.replace(/\s+/g, '') });
    if (!driver) return res.status(401).json({ error: 'Driver not found' });
    if (driver.status === 'suspended') return res.status(403).json({ error: 'Account suspended' });
    const ok = await bcrypt.compare(password, driver.password);
    if (!ok) return res.status(401).json({ error: 'Wrong password' });
    const token = jwt.sign({ id: driver._id.toString(), name: driver.name, isDriver: true }, JWT_SECRET, { expiresIn: '60d' });
    res.json({ success: true, token, driver: { id: driver._id, name: driver.name, phone: driver.phone, vehicleType: driver.vehicleType, plate: driver.plate } });
  } catch (err) {
    res.status(500).json({ error: 'Something went wrong' });
  }
});

app.get('/api/driver/rides', requireDriver, async (req, res) => {
  try {
    const rides = await db.collection('rides').find({ driverAssigned: req.driver.id }).sort({ createdAt: -1 }).toArray();
    res.json({ rides });
  } catch (err) {
    res.status(500).json({ error: 'Something went wrong' });
  }
});

app.patch('/api/driver/rides/:id', requireDriver, async (req, res) => {
  try {
    const { status } = req.body;
    if (!['completed', 'cancelled'].includes(status)) return res.status(400).json({ error: 'Invalid status' });
    const result = await db.collection('rides').updateOne(
      { _id: new ObjectId(req.params.id), driverAssigned: req.driver.id },
      { $set: { status, updatedAt: new Date() } }
    );
    if (result.matchedCount === 0) return res.status(404).json({ error: 'Ride not found' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Something went wrong' });
  }
});

// ════════════════════════════════════════════════════════════
// RIDES
// ════════════════════════════════════════════════════════════

app.get('/api/fare', (req, res) => {
  const h = new Date().getHours(), isNight = h >= 22 || h < 5;
  const { fare, km } = estimateFare(req.query.type, req.query.pickup, req.query.dest, isNight);
  res.json({ estimatedFare: fare, estimatedKm: km, nightSurcharge: isNight });
});

app.post('/api/rides', requireAuth, async (req, res) => {
  try {
    const { vehicleType, pickup, destination, date, time, paymentMethod, notes } = req.body || {};
    if (!vehicleType || !pickup || !destination) return res.status(400).json({ error: 'Vehicle, pickup and destination required' });
    const h = time ? parseInt(time) : new Date().getHours();
    const { fare, km } = estimateFare(vehicleType, pickup, destination, h >= 22 || h < 5);
    const ride = {
      ref: genRef(), userId: req.user.id, customerName: req.user.name, customerPhone: req.user.phone || '',
      vehicleType, pickup, destination,
      date: date || new Date().toISOString().split('T')[0],
      time: time || new Date().toTimeString().slice(0, 5),
      paymentMethod: paymentMethod || 'Cash (SSP)', notes: notes || '',
      status: 'pending', estimatedFare: fare, estimatedKm: km,
      driverAssigned: null, driverName: null, adminNotes: '', createdAt: new Date(),
    };
    await db.collection('rides').insertOne(ride);
    await db.collection('users').updateOne({ _id: new ObjectId(req.user.id) }, { $inc: { totalRides: 1 } });
    res.status(201).json({ success: true, ref: ride.ref, estimatedFare: ride.estimatedFare, vehicleType: ride.vehicleType });
  } catch (err) {
    console.error('[rides]', err.message);
    res.status(500).json({ error: 'Booking failed — try again' });
  }
});

app.get('/api/rides', requireAuth, async (req, res) => {
  try {
    const rides = await db.collection('rides').find({ userId: req.user.id }).sort({ createdAt: -1 }).toArray();
    res.json({ rides });
  } catch (err) {
    res.status(500).json({ error: 'Something went wrong' });
  }
});

app.get('/api/rides/:ref', requireAuth, async (req, res) => {
  try {
    const ride = await db.collection('rides').findOne({ ref: req.params.ref.toUpperCase(), userId: req.user.id });
    if (!ride) return res.status(404).json({ error: 'Ride not found' });
    res.json(ride);
  } catch (err) {
    res.status(500).json({ error: 'Something went wrong' });
  }
});

// ════════════════════════════════════════════════════════════
// ADMIN
// ════════════════════════════════════════════════════════════

app.post('/api/admin/login', (req, res) => {
  if ((req.body || {}).password === ADMIN_PWD) res.json({ success: true, token: ADMIN_TOK });
  else res.status(401).json({ error: 'Incorrect password' });
});

app.get('/api/admin/rides', requireAdmin, async (req, res) => {
  try {
    const { status, vehicleType, search, page = 1, limit = 50 } = req.query;
    const q = {};
    if (status)      q.status      = status;
    if (vehicleType) q.vehicleType = vehicleType;
    let rides = await db.collection('rides').find(q).sort({ createdAt: -1 }).toArray();
    if (search) {
      const s = search.toLowerCase();
      rides = rides.filter(r => (r.ref + r.customerName + r.customerPhone + r.pickup + r.destination).toLowerCase().includes(s));
    }
    const total = rides.length;
    const skip  = (parseInt(page) - 1) * parseInt(limit);
    res.json({ total, page: parseInt(page), rides: rides.slice(skip, skip + parseInt(limit)) });
  } catch (err) {
    res.status(500).json({ error: 'Something went wrong' });
  }
});

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const today  = new Date(); today.setHours(0, 0, 0, 0);
    const rides  = await db.collection('rides').find({}).toArray();
    const uc     = await db.collection('users').countDocuments({ role: 'customer' });
    const dc     = await db.collection('drivers').countDocuments({});
    const bt = {}, bs = {};
    let rev = 0;
    rides.forEach(r => {
      bt[r.vehicleType] = (bt[r.vehicleType] || 0) + 1;
      bs[r.status]      = (bs[r.status]      || 0) + 1;
      if (r.status === 'completed') rev += (r.estimatedFare || 0);
    });
    res.json({
      totalRides: rides.length,
      todayRides: rides.filter(r => new Date(r.createdAt) >= today).length,
      customers: uc, drivers: dc,
      pending: bs.pending || 0, assigned: bs.assigned || 0,
      completed: bs.completed || 0, cancelled: bs.cancelled || 0,
      revenue: rev, byType: bt,
    });
  } catch (err) {
    res.status(500).json({ error: 'Something went wrong' });
  }
});

app.get('/api/admin/customers', requireAdmin, async (req, res) => {
  try {
    const users = await db.collection('users').find({ role: 'customer' }).sort({ createdAt: -1 }).toArray();
    res.json({ customers: users.map(u => ({ id: u._id, name: u.name, phone: u.phone || '', email: u.email || '', totalRides: u.totalRides || 0, createdAt: u.createdAt })) });
  } catch (err) {
    res.status(500).json({ error: 'Something went wrong' });
  }
});

app.get('/api/admin/drivers', requireAdmin, async (req, res) => {
  try {
    const drivers = await db.collection('drivers').find({}).sort({ createdAt: -1 }).toArray();
    res.json({ drivers: drivers.map(d => ({ id: d._id, name: d.name, phone: d.phone, vehicleType: d.vehicleType, plate: d.plate, rating: d.rating, status: d.status })) });
  } catch (err) {
    res.status(500).json({ error: 'Something went wrong' });
  }
});

app.post('/api/admin/drivers', requireAdmin, async (req, res) => {
  try {
    const { name, phone, vehicleType, plate, password } = req.body || {};
    if (!name || !phone || !vehicleType || !plate || !password) return res.status(400).json({ error: 'All fields required' });
    const hash = await bcrypt.hash(password, 10);
    const result = await db.collection('drivers').insertOne({ name, phone: phone.replace(/\s+/g,''), vehicleType, plate, password: hash, rating: 5.0, totalRides: 0, status: 'active', createdAt: new Date() });
    res.status(201).json({ success: true, driver: { id: result.insertedId, name, phone } });
  } catch (err) {
    res.status(500).json({ error: 'Failed to add driver' });
  }
});

app.patch('/api/admin/rides/:id', requireAdmin, async (req, res) => {
  try {
    const { status, driverAssigned, driverName, notes } = req.body || {};
    const upd = { updatedAt: new Date() };
    if (status !== undefined)         upd.status         = status;
    if (driverAssigned !== undefined) upd.driverAssigned = driverAssigned;
    if (driverName !== undefined)     upd.driverName     = driverName;
    if (notes !== undefined)          upd.adminNotes     = notes;
    await db.collection('rides').updateOne({ _id: new ObjectId(req.params.id) }, { $set: upd });
    const ride = await db.collection('rides').findOne({ _id: new ObjectId(req.params.id) });
    res.json({ success: true, ride });
  } catch (err) {
    res.status(500).json({ error: 'Something went wrong' });
  }
});

app.delete('/api/admin/rides/:id', requireAdmin, async (req, res) => {
  try {
    await db.collection('rides').deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Something went wrong' });
  }
});

app.get('/api/admin/export', requireAdmin, async (req, res) => {
  try {
    const rides = await db.collection('rides').find({}).sort({ createdAt: -1 }).toArray();
    const h = ['ref','status','vehicleType','customerName','customerPhone','pickup','destination','date','time','paymentMethod','estimatedFare','driverName','adminNotes','createdAt'];
    const csv = [h.join(','), ...rides.map(r => h.map(k => `"${String(r[k] ?? '').replace(/"/g, '""')}"`).join(','))].join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="nileride-${new Date().toISOString().split('T')[0]}.csv"`);
    res.send(csv);
  } catch (err) {
    res.status(500).json({ error: 'Export failed' });
  }
});

// ── Catch-all ─────────────────────────────────────────────────
app.get('/*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ── Start ─────────────────────────────────────────────────────
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`\n🚗 NileRide running on http://localhost:${PORT}`);
    console.log(`   Admin:  http://localhost:${PORT}/admin.html`);
    console.log(`   Driver: http://localhost:${PORT}/driver.html\n`);
  });
}).catch(err => {
  console.error('Failed to connect to MongoDB:', err.message);
  process.exit(1);
});
