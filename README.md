# 🚗 NileRide — Juba's Ride Platform

## Setup Steps

### 1. Get your free MongoDB database (2 minutes)
1. Go to **mongodb.com/atlas** → Sign up free
2. Create a free cluster (M0 — free forever)
3. Click **Connect** → **Connect your application**
4. Copy the connection string — looks like:
   `mongodb+srv://username:password@cluster.mongodb.net/nileride`

### 2. Run locally
```bash
npm install
MONGO_URI="your-connection-string" node server.js
```

### 3. Deploy on Render (free)
1. Push to GitHub
2. render.com → New Web Service → connect repo
3. Start command: `node server.js`
4. **Environment Variables:**
   - `MONGO_URI` = your MongoDB Atlas connection string
   - `ADMIN_PASSWORD` = NileRide2025!
   - `JWT_SECRET` = any-long-random-string

## Pages
| URL | Purpose |
|-----|---------|
| `/` | Customer site (signup, login, book) |
| `/admin.html` | Admin dashboard (password: NileRide2025!) |
| `/driver.html` | Driver portal |
