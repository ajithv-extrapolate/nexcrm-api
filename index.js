const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');

const app = express();
app.use(helmet());
app.use(cors({ origin: process.env.ALLOWED_ORIGINS || '*', credentials: true }));
app.use(express.json());

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const query = (t, v) => pool.query(t, v);
const sign = (u) => jwt.sign({ sub: u.id, org: u.org_id, role: u.role }, process.env.JWT_SECRET, { expiresIn: '8h' });

// Auth middleware
const auth = async (req, res, next) => {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing token' });
  try {
    const p = jwt.verify(h.slice(7), process.env.JWT_SECRET);
    const { rows } = await query('SELECT id,org_id,email,name,role FROM users WHERE id=$1 AND is_active=TRUE', [p.sub]);
    if (!rows.length) return res.status(401).json({ error: 'Unauthorized' });
    req.user = rows[0]; req.org_id = rows[0].org_id; next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
};

app.get('/health', (_, res) => res.json({ status: 'ok' }));

// ── AUTH ──────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { orgName, email, password, name } = req.body;
    const slug = orgName.toLowerCase().replace(/\s+/g,'-').replace(/[^a-z0-9-]/g,'') + '-' + Date.now().toString(36);
    const hash = await bcrypt.hash(password, 12);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const org = (await client.query('INSERT INTO organizations(name,slug) VALUES($1,$2) RETURNING id',[orgName,slug])).rows[0];
      const user = (await client.query('INSERT INTO users(org_id,email,name,role,password_hash) VALUES($1,$2,$3,$4,$5) RETURNING *',[org.id,email.toLowerCase(),name,'admin',hash])).rows[0];
      await client.query('SELECT seed_default_pipeline($1)',[org.id]);
      await client.query('COMMIT');
      res.status(201).json({ token: sign(user), user: { id:user.id, name:user.name, email:user.email, role:user.role, org_id:user.org_id } });
    } catch(e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
  } catch(e) { res.status(400).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const { rows } = await query('SELECT * FROM users WHERE email=$1 AND is_active=TRUE', [email.toLowerCase()]);
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    res.json({ token: sign(rows[0]), user: { id:rows[0].id, name:rows[0].name, email:rows[0].email, role:rows[0].role, org_id:rows[0].org_id } });
  } catch(e) { res.status(400).json({ error: e.message }); }
});

// ── LEADS ─────────────────────────────────────────────────
app.get('/api/leads', auth, async (req, res) => {
  try {
    const { status, search, page=1, limit=50 } = req.query;
    let w=['l.org_id=$1'], v=[req.org_id], i=2;
    if(status) { w.push(`l.status=$${i++}`); v.push(status); }
    if(search) { w.push(`(l.first_name||' '||l.last_name||coalesce(l.company,'')) ILIKE $${i++}`); v.push(`%${search}%`); }
    v.push(Number(limit),(Number(page)-1)*Number(limit));
    const {rows} = await query(`SELECT l.*,u.name AS owner_name FROM leads l LEFT JOIN users u ON u.id=l.owner_id WHERE ${w.join(' AND ')} ORDER BY l.created_at DESC LIMIT $${i++} OFFSET $${i}`,v);
    const ct = await query(`SELECT COUNT(*) FROM leads l WHERE ${w.join(' AND ')}`,v.slice(0,-2));
    res.json({ data: rows, total: Number(ct.rows[0].count) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/leads/:id', auth, async (req,res) => {
  const {rows} = await query('SELECT l.*,u.name AS owner_name FROM leads l LEFT JOIN users u ON u.id=l.owner_id WHERE l.id=$1 AND l.org_id=$2',[req.params.id,req.org_id]);
  rows.length ? res.json(rows[0]) : res.status(404).json({error:'Not found'});
});

app.post('/api/leads', auth, async (req,res) => {
  try {
    const {first_name,last_name,email,phone,company,title,status='new',source,owner_id,potential_value} = req.body;
    const {rows} = await query('INSERT INTO leads(org_id,first_name,last_name,email,phone,company,title,status,source,owner_id,potential_value) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *',[req.org_id,first_name,last_name,email,phone,company,title,status,source,owner_id||req.user.id,potential_value]);
    res.status(201).json(rows[0]);
  } catch(e) { res.status(400).json({error:e.message}); }
});

app.patch('/api/leads/:id', auth, async (req,res) => {
  try {
    const allowed=['first_name','last_name','email','phone','company','title','status','source','owner_id','potential_value','ai_score'];
    const sets=[],vals=[]; let i=1;
    for(const [k,v] of Object.entries(req.body)) if(allowed.includes(k)){sets.push(`${k}=$${i++}`);vals.push(v);}
    if(!sets.length) return res.status(400).json({error:'No valid fields'});
    vals.push(req.params.id,req.org_id);
    const {rows} = await query(`UPDATE leads SET ${sets.join(',')} WHERE id=$${i++} AND org_id=$${i++} RETURNING *`,vals);
    rows.length ? res.json(rows[0]) : res.status(404).json({error:'Not found'});
  } catch(e) { res.status(400).json({error:e.message}); }
});

app.delete('/api/leads/:id', auth, async (req,res) => {
  const {rowCount} = await query('DELETE FROM leads WHERE id=$1 AND org_id=$2',[req.params.id,req.org_id]);
  rowCount ? res.status(204).send() : res.status(404).json({error:'Not found'});
});

// ── CONTACTS ──────────────────────────────────────────────
app.get('/api/contacts', auth, async (req,res) => {
  const {rows} = await query('SELECT c.*,a.name AS account_name,u.name AS owner_name FROM contacts c LEFT JOIN accounts a ON a.id=c.account_id LEFT JOIN users u ON u.id=c.owner_id WHERE c.org_id=$1 ORDER BY c.created_at DESC LIMIT 100',[req.org_id]);
  res.json({data:rows});
});
app.post('/api/contacts', auth, async (req,res) => {
  try {
    const {first_name,last_name,email,phone,title,account_id,owner_id} = req.body;
    const {rows} = await query('INSERT INTO contacts(org_id,account_id,first_name,last_name,email,phone,title,owner_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',[req.org_id,account_id,first_name,last_name,email,phone,title,owner_id||req.user.id]);
    res.status(201).json(rows[0]);
  } catch(e) { res.status(400).json({error:e.message}); }
});

// ── ACCOUNTS ──────────────────────────────────────────────
app.get('/api/accounts', auth, async (req,res) => {
  const {rows} = await query('SELECT a.*,u.name AS owner_name FROM accounts a LEFT JOIN users u ON u.id=a.owner_id WHERE a.org_id=$1 ORDER BY a.created_at DESC LIMIT 100',[req.org_id]);
  res.json({data:rows});
});
app.post('/api/accounts', auth, async (req,res) => {
  try {
    const {name,domain,industry,employee_count,arr,status='prospect',owner_id} = req.body;
    const {rows} = await query('INSERT INTO accounts(org_id,name,domain,industry,employee_count,arr,status,owner_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',[req.org_id,name,domain,industry,employee_count,arr,status,owner_id||req.user.id]);
    res.status(201).json(rows[0]);
  } catch(e) { res.status(400).json({error:e.message}); }
});

// ── DEALS ─────────────────────────────────────────────────
app.get('/api/deals', auth, async (req,res) => {
  try {
    const {pipeline_id,stage_id,owner_id} = req.query;
    let w=['d.org_id=$1'],v=[req.org_id],i=2;
    if(pipeline_id){w.push(`d.pipeline_id=$${i++}`);v.push(pipeline_id);}
    if(stage_id){w.push(`d.stage_id=$${i++}`);v.push(stage_id);}
    if(owner_id){w.push(`d.owner_id=$${i++}`);v.push(owner_id);}
    const {rows} = await query(`SELECT d.*,a.name AS account_name,u.name AS owner_name,ps.name AS stage_name,ps.color AS stage_color,ps.probability AS stage_prob,ps.is_won,ps.is_lost FROM deals d LEFT JOIN accounts a ON a.id=d.account_id LEFT JOIN users u ON u.id=d.owner_id LEFT JOIN pipeline_stages ps ON ps.id=d.stage_id WHERE ${w.join(' AND ')} ORDER BY d.created_at DESC`,v);
    res.json({data:rows});
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.get('/api/deals/:id', auth, async (req,res) => {
  const {rows} = await query('SELECT d.*,a.name AS account_name,u.name AS owner_name,ps.name AS stage_name,ps.color AS stage_color FROM deals d LEFT JOIN accounts a ON a.id=d.account_id LEFT JOIN users u ON u.id=d.owner_id LEFT JOIN pipeline_stages ps ON ps.id=d.stage_id WHERE d.id=$1 AND d.org_id=$2',[req.params.id,req.org_id]);
  if(!rows.length) return res.status(404).json({error:'Not found'});
  const [acts,tasks,notes] = await Promise.all([
    query('SELECT * FROM activities WHERE deal_id=$1 ORDER BY occurred_at DESC LIMIT 20',[req.params.id]),
    query('SELECT * FROM tasks WHERE deal_id=$1 AND status!=\'done\' ORDER BY due_date',[req.params.id]),
    query('SELECT n.*,u.name AS author_name FROM notes n LEFT JOIN users u ON u.id=n.author_id WHERE n.deal_id=$1 ORDER BY n.created_at DESC',[req.params.id]),
  ]);
  res.json({...rows[0],activities:acts.rows,tasks:tasks.rows,notes:notes.rows});
});

app.post('/api/deals', auth, async (req,res) => {
  try {
    const {title,account_id,primary_contact_id,pipeline_id,stage_id,owner_id,value=0,expected_close} = req.body;
    const {rows} = await query('INSERT INTO deals(org_id,title,account_id,primary_contact_id,pipeline_id,stage_id,owner_id,value,expected_close) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',[req.org_id,title,account_id,primary_contact_id,pipeline_id,stage_id,owner_id||req.user.id,value,expected_close]);
    res.status(201).json(rows[0]);
  } catch(e){ res.status(400).json({error:e.message}); }
});

app.patch('/api/deals/:id/stage', auth, async (req,res) => {
  try {
    const {stage_id} = req.body;
    const {rows:stage} = await query('SELECT * FROM pipeline_stages WHERE id=$1',[stage_id]);
    if(!stage.length) return res.status(400).json({error:'Stage not found'});
    const {rows} = await query('UPDATE deals SET stage_id=$1,probability=$2 WHERE id=$3 AND org_id=$4 RETURNING *',[stage_id,stage[0].probability,req.params.id,req.org_id]);
    rows.length ? res.json(rows[0]) : res.status(404).json({error:'Not found'});
  } catch(e){ res.status(400).json({error:e.message}); }
});

app.patch('/api/deals/:id', auth, async (req,res) => {
  try {
    const allowed=['title','value','probability','expected_close','owner_id','description'];
    const sets=[],vals=[]; let i=1;
    for(const [k,v] of Object.entries(req.body)) if(allowed.includes(k)){sets.push(`${k}=$${i++}`);vals.push(v);}
    if(!sets.length) return res.status(400).json({error:'No valid fields'});
    vals.push(req.params.id,req.org_id);
    const {rows} = await query(`UPDATE deals SET ${sets.join(',')} WHERE id=$${i++} AND org_id=$${i++} RETURNING *`,vals);
    rows.length ? res.json(rows[0]) : res.status(404).json({error:'Not found'});
  } catch(e){ res.status(400).json({error:e.message}); }
});

// ── ACTIVITIES & TASKS ────────────────────────────────────
app.get('/api/activities', auth, async (req,res) => {
  const {rows} = await query('SELECT a.*,u.name AS owner_name FROM activities a LEFT JOIN users u ON u.id=a.owner_id WHERE a.org_id=$1 ORDER BY a.occurred_at DESC LIMIT 50',[req.org_id]);
  res.json({data:rows});
});
app.post('/api/activities', auth, async (req,res) => {
  try {
    const {type,subject,body,deal_id,contact_id,account_id,call_duration_sec,meeting_start,occurred_at} = req.body;
    const {rows} = await query('INSERT INTO activities(org_id,type,subject,body,owner_id,deal_id,contact_id,account_id,call_duration_sec,meeting_start,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *',[req.org_id,type,subject,body,req.user.id,deal_id,contact_id,account_id,call_duration_sec,meeting_start,occurred_at||new Date()]);
    res.status(201).json(rows[0]);
  } catch(e){ res.status(400).json({error:e.message}); }
});

app.get('/api/tasks', auth, async (req,res) => {
  const {rows} = await query('SELECT t.*,u.name AS assignee_name FROM tasks t LEFT JOIN users u ON u.id=t.assigned_to WHERE t.org_id=$1 AND t.status!=\'done\' ORDER BY t.due_date ASC LIMIT 100',[req.org_id]);
  res.json({data:rows});
});
app.post('/api/tasks', auth, async (req,res) => {
  try {
    const {title,priority='medium',due_date,assigned_to,deal_id,contact_id} = req.body;
    const {rows} = await query('INSERT INTO tasks(org_id,title,priority,due_date,owner_id,assigned_to,deal_id,contact_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',[req.org_id,title,priority,due_date,req.user.id,assigned_to||req.user.id,deal_id,contact_id]);
    res.status(201).json(rows[0]);
  } catch(e){ res.status(400).json({error:e.message}); }
});
app.patch('/api/tasks/:id', auth, async (req,res) => {
  const {status,completed_at} = req.body;
  const {rows} = await query('UPDATE tasks SET status=$1,completed_at=$2,updated_at=NOW() WHERE id=$3 AND org_id=$4 RETURNING *',[status,status==='done'?new Date():null,req.params.id,req.org_id]);
  rows.length ? res.json(rows[0]) : res.status(404).json({error:'Not found'});
});

// ── PIPELINES ─────────────────────────────────────────────
app.get('/api/pipelines', auth, async (req,res) => {
  const {rows} = await query('SELECT p.*,json_agg(ps ORDER BY ps.position) AS stages FROM pipelines p LEFT JOIN pipeline_stages ps ON ps.pipeline_id=p.id WHERE p.org_id=$1 GROUP BY p.id',[req.org_id]);
  res.json({data:rows});
});

// ── REPORTS ───────────────────────────────────────────────
app.get('/api/reports/pipeline-summary', auth, async (req,res) => {
  const {rows} = await query(`SELECT ps.id AS stage_id,ps.name AS stage_name,ps.position,ps.color,ps.probability,ps.is_won,ps.is_lost,COUNT(d.id) AS deal_count,COALESCE(SUM(d.value),0) AS total_value,COALESCE(SUM(d.value*ps.probability/100),0) AS weighted_value FROM pipeline_stages ps LEFT JOIN deals d ON d.stage_id=ps.id AND d.org_id=$1 WHERE ps.org_id=$1 AND ps.is_lost=FALSE GROUP BY ps.id ORDER BY ps.position`,[req.org_id]);
  res.json({stages:rows,total:rows.reduce((s,r)=>s+Number(r.total_value),0)});
});

app.get('/api/reports/rep-performance', auth, async (req,res) => {
  const {rows} = await query(`SELECT u.id,u.name,COUNT(d.id) FILTER(WHERE ps.is_won) AS deals_won,COUNT(d.id) FILTER(WHERE NOT ps.is_won AND NOT ps.is_lost) AS deals_open,COALESCE(SUM(d.value) FILTER(WHERE ps.is_won),0) AS revenue_won,COALESCE(SUM(d.value) FILTER(WHERE NOT ps.is_won AND NOT ps.is_lost),0) AS pipeline_value FROM users u LEFT JOIN deals d ON d.owner_id=u.id AND d.org_id=u.org_id LEFT JOIN pipeline_stages ps ON ps.id=d.stage_id WHERE u.org_id=$1 AND u.is_active=TRUE GROUP BY u.id,u.name ORDER BY revenue_won DESC`,[req.org_id]);
  res.json({data:rows});
});

// ── SEARCH ────────────────────────────────────────────────
app.get('/api/search', auth, async (req,res) => {
  const {q} = req.query;
  if(!q||q.length<2) return res.json({results:[]});
  const like = `%${q}%`;
  const [leads,contacts,accounts,deals] = await Promise.all([
    query("SELECT id,first_name||' '||last_name AS title,'lead' AS type,company AS subtitle FROM leads WHERE org_id=$1 AND (first_name||last_name||coalesce(company,'')) ILIKE $2 LIMIT 4",[req.org_id,like]),
    query("SELECT id,first_name||' '||last_name AS title,'contact' AS type,title AS subtitle FROM contacts WHERE org_id=$1 AND (first_name||last_name) ILIKE $2 LIMIT 4",[req.org_id,like]),
    query("SELECT id,name AS title,'account' AS type,industry AS subtitle FROM accounts WHERE org_id=$1 AND name ILIKE $2 LIMIT 4",[req.org_id,like]),
    query("SELECT id,title,'deal' AS type,value::TEXT AS subtitle FROM deals WHERE org_id=$1 AND title ILIKE $2 LIMIT 4",[req.org_id,like]),
  ]);
  res.json({results:[...leads.rows,...contacts.rows,...accounts.rows,...deals.rows]});
});

// Error handler
app.use((err,req,res,next) => res.status(500).json({error:err.message}));

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`NexCRM API running on port ${PORT}`));
