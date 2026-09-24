/*
 PEPE LOOTS backend
 Node.js + Express + PostgreSQL

 Required environment variables on Render:
 DATABASE_URL=your Render PostgreSQL internal/external connection string
 ADMIN_PASSWORD=change-this-to-a-long-random-password
 PUBLIC_APP_URL=https://your-frontend-domain.example
 ADSGRAM_BLOCK_ID=your-block-id

 Optional:
 TELEGRAM_BOT_TOKEN=your Telegram bot token
 PORT=10000

 The frontend uses Telegram Mini App initData. In production, keep TELEGRAM_BOT_TOKEN
 configured so the server can verify Telegram's signed initData. AdsGram requires a
 Telegram Mini App for the rewarded integration documented by AdsGram.
*/

require("dotenv").config();
const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "100kb" }));

// CORS is only needed when the Mini App frontend is hosted on a different origin.
// Keep PUBLIC_APP_URL restricted to your own frontend origin in production.
app.use((req,res,next)=>{
  const origin=req.headers.origin;
  const allowed=new Set([
    PUBLIC_APP_URL,
    "http://localhost:3000",
    "http://localhost:5173"
  ].filter(Boolean));
  if(origin && allowed.has(origin)){
    res.setHeader("Access-Control-Allow-Origin",origin);
    res.setHeader("Vary","Origin");
    res.setHeader("Access-Control-Allow-Headers","Content-Type, X-Telegram-Init-Data, Authorization");
    res.setHeader("Access-Control-Allow-Methods","GET,POST,OPTIONS");
  }
  if(req.method==="OPTIONS") return res.sendStatus(204);
  next();
});

const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const PUBLIC_APP_URL = (process.env.PUBLIC_APP_URL || "").replace(/\/+$/, "");
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "";

if (!DATABASE_URL) console.warn("WARNING: DATABASE_URL is missing.");
if (!ADMIN_PASSWORD) console.warn("WARNING: ADMIN_PASSWORD is missing.");

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL && !/localhost|127\.0\.0\.1/.test(DATABASE_URL)
    ? { rejectUnauthorized: false } : false,
  max: 10
});

const DAILY_LIMIT = 10;
const AD_REWARD = 300;
const REFERRAL_REWARD = 300;
const MIN_WITHDRAWAL = 3000;
const ADMIN_TOKEN_TTL = 12 * 60 * 60 * 1000;

function randomCode() {
  return crypto.randomBytes(6).toString("hex").toUpperCase();
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function timingSafe(a,b) {
  const A=Buffer.from(a); const B=Buffer.from(b);
  return A.length===B.length && crypto.timingSafeEqual(A,B);
}

/*
 Telegram initData verification.
 Telegram sends:
   hash=<signature>&auth_date=...&user=<JSON>&query_id=...
 The secret key is HMAC-SHA256("WebAppData", bot_token).
*/
function validateTelegramInitData(initData) {
  if (!BOT_TOKEN) throw new Error("Telegram verification is not configured.");
  if (!initData) throw new Error("Telegram Mini App authorization is required.");

  const params = new URLSearchParams(initData);
  const hash = params.get("hash");
  const authDate = Number(params.get("auth_date"));
  if (!hash || !authDate) throw new Error("Invalid Telegram authorization data.");

  // Do not accept stale initData.
  if (Math.floor(Date.now()/1000) - authDate > 86400) {
    throw new Error("Telegram authorization expired. Reopen the Mini App.");
  }

  const pairs = [];
  for (const [key,value] of params.entries()) {
    if (key !== "hash") pairs.push([key,value]);
  }
  pairs.sort((a,b)=>a[0].localeCompare(b[0]));
  const dataCheckString = pairs.map(([k,v])=>`${k}=${v}`).join("\n");

  const secret = crypto.createHmac("sha256","WebAppData").update(BOT_TOKEN).digest();
  const expected = crypto.createHmac("sha256",secret).update(dataCheckString).digest("hex");
  if (!timingSafe(expected, hash)) throw new Error("Invalid Telegram authorization.");
  const user = JSON.parse(params.get("user") || "{}");
  if (!user.id) throw new Error("Telegram user ID is missing.");
  return user;
}

async function getTelegramUser(req) {
  const initData = req.get("X-Telegram-Init-Data") || "";
  return validateTelegramInitData(initData);
}

/*
 For local UI testing only, do NOT use this in production:
 add ALLOW_DEV_USER=true and call with X-Dev-User: 123.
 Withdrawal endpoints remain blocked for dev users.
*/
async function getUser(req, {allowDev=false}={}) {
  try {
    return { telegram: await getTelegramUser(req), dev:false };
  } catch (e) {
    if (process.env.ALLOW_DEV_USER === "true" && allowDev) {
      const id = String(req.get("X-Dev-User") || "").trim();
      if (/^[0-9]{1,30}$/.test(id)) return { telegram:{id:Number(id),first_name:"Dev"}, dev:true };
    }
    throw e;
  }
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      telegram_id TEXT UNIQUE NOT NULL,
      first_name TEXT DEFAULT '',
      username TEXT DEFAULT '',
      balance BIGINT NOT NULL DEFAULT 0,
      referral_code TEXT UNIQUE NOT NULL,
      referred_by TEXT REFERENCES users(telegram_id),
      referral_rewarded BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ad_daily (
      telegram_id TEXT NOT NULL REFERENCES users(telegram_id) ON DELETE CASCADE,
      watch_date DATE NOT NULL,
      watch_count INTEGER NOT NULL DEFAULT 0,
      earned BIGINT NOT NULL DEFAULT 0,
      PRIMARY KEY (telegram_id, watch_date)
    );

    CREATE TABLE IF NOT EXISTS ad_reward_claims (
      id BIGSERIAL PRIMARY KEY,
      telegram_id TEXT NOT NULL REFERENCES users(telegram_id) ON DELETE CASCADE,
      reward BIGINT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS referrals (
      id BIGSERIAL PRIMARY KEY,
      referrer_id TEXT NOT NULL REFERENCES users(telegram_id) ON DELETE CASCADE,
      referred_id TEXT UNIQUE NOT NULL REFERENCES users(telegram_id) ON DELETE CASCADE,
      reward BIGINT NOT NULL DEFAULT 300,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      rewarded_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS withdrawals (
      id BIGSERIAL PRIMARY KEY,
      telegram_id TEXT NOT NULL REFERENCES users(telegram_id) ON DELETE CASCADE,
      binance_id TEXT NOT NULL,
      amount BIGINT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      admin_note TEXT DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_withdrawals_status ON withdrawals(status);
    CREATE INDEX IF NOT EXISTS idx_withdrawals_created ON withdrawals(created_at DESC);
  `);
}

async function ensureUser(telegram, referralCode) {
  const client=await pool.connect();
  try {
    await client.query("BEGIN");

    const existing = await client.query(
      "SELECT * FROM users WHERE telegram_id=$1 FOR UPDATE", [String(telegram.id)]
    );
    if (existing.rowCount) {
      await client.query(
        "UPDATE users SET first_name=$2, username=$3, updated_at=NOW() WHERE telegram_id=$1",
        [String(telegram.id), telegram.first_name||"", telegram.username||""]
      );
      await client.query("COMMIT");
      return existing.rows[0];
    }

    let referredBy = null;
    if (referralCode) {
      const r = await client.query(
        "SELECT telegram_id FROM users WHERE referral_code=$1 LIMIT 1", [referralCode]
      );
      if (r.rowCount && String(r.rows[0].telegram_id)!==String(telegram.id)) referredBy=r.rows[0].telegram_id;
    }

    const code = randomCode();
    const inserted = await client.query(
      `INSERT INTO users(telegram_id,first_name,username,referral_code,referred_by)
       VALUES($1,$2,$3,$4,$5) RETURNING *`,
      [String(telegram.id), telegram.first_name||"", telegram.username||"", code, referredBy]
    );

    if (referredBy) {
      await client.query(
        `INSERT INTO referrals(referrer_id,referred_id,reward,status)
         VALUES($1,$2,$3,'pending')
         ON CONFLICT (referred_id) DO NOTHING`,
        [referredBy,String(telegram.id),REFERRAL_REWARD]
      );
    }

    await client.query("COMMIT");
    return inserted.rows[0];
  } catch(e) {
    await client.query("ROLLBACK"); throw e;
  } finally { client.release(); }
}

async function completeReferralIfEligible(client, telegramId) {
  // The referral is made qualifying by the user's first successful app session.
  // This avoids paying the referrer repeatedly for link clicks.
  const q = await client.query(`
    SELECT r.id,r.referrer_id,r.reward
    FROM referrals r
    WHERE r.referred_id=$1 AND r.status='pending'
    FOR UPDATE`, [String(telegramId)]);
  if (!q.rowCount) return;

  const r=q.rows[0];
  await client.query(
    "UPDATE users SET balance=balance+$2, updated_at=NOW() WHERE telegram_id=$1",
    [r.referrer_id, r.reward]
  );
  await client.query(
    "UPDATE referrals SET status='rewarded', rewarded_at=NOW() WHERE id=$1",
    [r.id]
  );
  await client.query(
    "UPDATE users SET referral_rewarded=TRUE WHERE telegram_id=$1",
    [String(telegramId)]
  );
}

async function getUserState(telegramId) {
  const q=await pool.query(`
    SELECT u.*,
      COALESCE(a.watch_count,0)::int AS ads_today,
      COALESCE((SELECT COUNT(*) FROM referrals r WHERE r.referrer_id=u.telegram_id AND r.status='rewarded'),0)::int AS referrals
    FROM users u
    LEFT JOIN ad_daily a
      ON a.telegram_id=u.telegram_id AND a.watch_date=CURRENT_DATE
    WHERE u.telegram_id=$1`, [String(telegramId)]);
  if(!q.rowCount) throw new Error("User not found.");
  const u=q.rows[0];
  const origin=PUBLIC_APP_URL || "https://YOUR-APP-DOMAIN.example";
  return {
    telegramId:u.telegram_id, firstName:u.first_name, username:u.username,
    balance:Number(u.balance), referralCode:u.referral_code,
    referralLink:`${origin}/?ref=${encodeURIComponent(u.referral_code)}`,
    referredBy:u.referred_by, referralRewarded:u.referral_rewarded,
    adsToday:Number(u.ads_today), referrals:Number(u.referrals)
  };
}

function requireAdmin(req,res,next) {
  const auth=req.get("Authorization") || "";
  const token=auth.startsWith("Bearer ")?auth.slice(7):"";
  const parts=token.split(".");
  if(!ADMIN_PASSWORD || parts.length!==2) return res.status(401).json({error:"Admin authorization required."});
  const payload=parts[0], sig=parts[1];
  const expected=crypto.createHmac("sha256",ADMIN_PASSWORD).update(payload).digest("hex");
  if(!timingSafe(expected,sig)) return res.status(401).json({error:"Invalid admin token."});
  try {
    const p=JSON.parse(Buffer.from(payload,"base64url").toString("utf8"));
    if(p.exp<Date.now() || p.role!=="admin") throw new Error();
    req.admin=p; next();
  } catch { return res.status(401).json({error:"Admin token expired."}); }
}

app.get("/health", async (req,res)=>{
  try { await pool.query("SELECT 1"); res.json({ok:true,service:"pepe-loots"}); }
  catch(e){ res.status(503).json({ok:false,error:"Database unavailable"}); }
});

app.post("/api/me", async (req,res)=>{
  try {
    const {telegram}=await getUser(req,{allowDev:true});
    const user=await ensureUser(telegram, String(req.body?.ref||"").trim().toUpperCase());
    // Referral becomes payable after the referred user reaches the app.
    // This is done exactly once.
    const client=await pool.connect();
    try { await client.query("BEGIN"); await completeReferralIfEligible(client,String(telegram.id)); await client.query("COMMIT"); }
    catch(e){ await client.query("ROLLBACK"); throw e; } finally{client.release();}
    res.json({user:await getUserState(String(telegram.id))});
  } catch(e) {
    res.status(401).json({error:e.message || "Authorization failed."});
  }
});

app.post("/api/ads/reward", async (req,res)=>{
  try {
    const {telegram,dev}=await getUser(req,{allowDev:true});
    if(dev) return res.status(403).json({error:"Dev users cannot claim rewards."});

    const client=await pool.connect();
    try {
      await client.query("BEGIN");
      const uid=String(telegram.id);
      const userQ=await client.query("SELECT * FROM users WHERE telegram_id=$1 FOR UPDATE",[uid]);
      if(!userQ.rowCount) throw new Error("User not found.");

      const daily=await client.query(
        "SELECT watch_count FROM ad_daily WHERE telegram_id=$1 AND watch_date=CURRENT_DATE FOR UPDATE",[uid]
      );
      const count=daily.rowCount?Number(daily.rows[0].watch_count):0;
      if(count>=DAILY_LIMIT) throw new Error("Daily watch limit reached.");

      // Only the exact configured reward can be credited.
      if(Number(req.body?.reward)!==AD_REWARD) throw new Error("Invalid reward.");

      await client.query(`
        INSERT INTO ad_daily(telegram_id,watch_date,watch_count,earned)
        VALUES($1,CURRENT_DATE,1,$2)
        ON CONFLICT(telegram_id,watch_date)
        DO UPDATE SET watch_count=ad_daily.watch_count+1, earned=ad_daily.earned+$2`,[uid,AD_REWARD]);

      await client.query("INSERT INTO ad_reward_claims(telegram_id,reward) VALUES($1,$2)",[uid,AD_REWARD]);
      await client.query("UPDATE users SET balance=balance+$2,updated_at=NOW() WHERE telegram_id=$1",[uid,AD_REWARD]);

      await client.query("COMMIT");
      res.json({ok:true,user:await getUserState(uid)});
    } catch(e){await client.query("ROLLBACK"); throw e;}
    finally{client.release();}
  } catch(e){res.status(400).json({error:e.message || "Reward could not be credited."});}
});

app.get("/api/withdrawals", async (req,res)=>{
  try{
    const {telegram}=await getUser(req,{allowDev:false});
    const q=await pool.query(
      `SELECT id,binance_id AS "binanceId",amount,status,admin_note AS "adminNote",created_at AS "createdAt",updated_at AS "updatedAt"
       FROM withdrawals WHERE telegram_id=$1 ORDER BY created_at DESC LIMIT 50`,[String(telegram.id)]
    );
    res.json({items:q.rows});
  }catch(e){res.status(401).json({error:e.message});}
});

app.post("/api/withdrawals", async (req,res)=>{
  try{
    const {telegram}=await getUser(req,{allowDev:false});
    const uid=String(telegram.id);
    const binanceId=String(req.body?.binanceId||"").trim();
    const amount=Number(req.body?.amount);
    if(!/^[A-Za-z0-9._-]{3,80}$/.test(binanceId)) throw new Error("Enter a valid Binance ID.");
    if(!Number.isInteger(amount)||amount<MIN_WITHDRAWAL) throw new Error(`Minimum withdrawal is ${MIN_WITHDRAWAL.toLocaleString()} PEPE.`);

    const client=await pool.connect();
    try{
      await client.query("BEGIN");
      const u=await client.query("SELECT balance FROM users WHERE telegram_id=$1 FOR UPDATE",[uid]);
      if(!u.rowCount) throw new Error("User not found.");
      if(Number(u.rows[0].balance)<amount) throw new Error("Insufficient PEPE balance.");

      const pending=await client.query(
        "SELECT id FROM withdrawals WHERE telegram_id=$1 AND status='pending' LIMIT 1",[uid]
      );
      if(pending.rowCount) throw new Error("You already have a pending withdrawal request.");

      // Reserve the amount immediately. If rejected, admin can refund it.
      await client.query("UPDATE users SET balance=balance-$2,updated_at=NOW() WHERE telegram_id=$1",[uid,amount]);
      await client.query(
        "INSERT INTO withdrawals(telegram_id,binance_id,amount,status) VALUES($1,$2,$3,'pending')",
        [uid,binanceId,amount]
      );
      await client.query("COMMIT");
      res.json({ok:true,user:await getUserState(uid)});
    }catch(e){await client.query("ROLLBACK");throw e;}finally{client.release();}
  }catch(e){res.status(400).json({error:e.message});}
});

/* Admin */
app.post("/api/admin/login",(req,res)=>{
  const password=String(req.body?.password||"");
  if(!ADMIN_PASSWORD || !timingSafe(password,ADMIN_PASSWORD))
    return res.status(401).json({error:"Invalid admin password."});
  const payload=Buffer.from(JSON.stringify({role:"admin",iat:Date.now(),exp:Date.now()+ADMIN_TOKEN_TTL})).toString("base64url");
  const sig=crypto.createHmac("sha256",ADMIN_PASSWORD).update(payload).digest("hex");
  res.json({token:`${payload}.${sig}`,expiresIn:ADMIN_TOKEN_TTL});
});

app.get("/api/admin/withdrawals",requireAdmin,async(req,res)=>{
  try{
    const q=await pool.query(`
      SELECT w.id,w.telegram_id AS "telegramId",u.first_name AS "firstName",u.username,
             w.binance_id AS "binanceId",w.amount,w.status,w.admin_note AS "adminNote",
             w.created_at AS "createdAt",w.updated_at AS "updatedAt"
      FROM withdrawals w JOIN users u ON u.telegram_id=w.telegram_id
      ORDER BY w.created_at DESC LIMIT 500`);
    res.json({items:q.rows});
  }catch(e){res.status(500).json({error:"Could not load withdrawals."});}
});

app.post("/api/admin/withdrawals/:id/status",requireAdmin,async(req,res)=>{
  const id=Number(req.params.id);
  const status=String(req.body?.status||"").toLowerCase();
  const note=String(req.body?.note||"").slice(0,500);
  if(!Number.isInteger(id)||!["approved","rejected"].includes(status))
    return res.status(400).json({error:"Status must be approved or rejected."});

  const client=await pool.connect();
  try{
    await client.query("BEGIN");
    const q=await client.query("SELECT * FROM withdrawals WHERE id=$1 FOR UPDATE",[id]);
    if(!q.rowCount) throw new Error("Withdrawal not found.");
    const w=q.rows[0];
    if(w.status!=="pending") throw new Error("This request is already processed.");

    // Rejected requests refund the reserved PEPE. Approved requests do not.
    if(status==="rejected"){
      await client.query("UPDATE users SET balance=balance+$2,updated_at=NOW() WHERE telegram_id=$1",[w.telegram_id,w.amount]);
    }
    await client.query(
      "UPDATE withdrawals SET status=$2,admin_note=$3,updated_at=NOW() WHERE id=$1",
      [id,status,note]
    );
    await client.query("COMMIT");
    res.json({ok:true});
  }catch(e){await client.query("ROLLBACK");res.status(400).json({error:e.message});}
  finally{client.release();}
});

app.get("/admin", (req,res)=>res.sendFile(path.join(__dirname,"admin.html")));
app.use(express.static(path.join(__dirname,"public")));
app.get("*",(req,res)=>{
  if(req.path.startsWith("/api/")||req.path==="/health"||req.path==="/admin") return;
  res.sendFile(path.join(__dirname,"public","index.html"));
});

initDb()
  .then(()=>app.listen(PORT,()=>console.log(`PEPE LOOTS server running on ${PORT}`)))
  .catch(err=>{console.error("Database initialization failed:",err);process.exit(1);});
