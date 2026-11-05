const { neon } = require('@neondatabase/serverless');
const crypto = require('crypto');

const db = () => {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is missing');
  return neon(process.env.DATABASE_URL);
};
const hash = (p) => {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + crypto.scryptSync(String(p), salt, 64).toString('hex');
};
const verify = (p, stored) => {
  if (!stored || !stored.includes(':')) return false;
  const [salt, wanted] = stored.split(':');
  const got = crypto.scryptSync(String(p), salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(got, 'hex'), Buffer.from(wanted, 'hex'));
};
const makeToken = () => crypto.randomBytes(32).toString('hex');
const send = (res, code, body) => {
  res.status(code).setHeader('Content-Type', 'application/json; charset=utf-8').end(JSON.stringify(body));
};

async function init(sql) {
  await sql`CREATE TABLE IF NOT EXISTS unisquad_users (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'student',
    banned_until TIMESTAMPTZ, ban_reason TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`;
  await sql`CREATE TABLE IF NOT EXISTS unisquad_sessions (
    token TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES unisquad_users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL
  )`;
  await sql`CREATE TABLE IF NOT EXISTS unisquad_state (
    id INTEGER PRIMARY KEY, data JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`;
  const admin = await sql`SELECT id,password_hash FROM unisquad_users WHERE LOWER(username)='admin' LIMIT 1`;
  const temporaryAdminHash = '0123456789abcdef0123456789abcdef:b73d71a9980ff5c0b357becdf2a10bba8841da7a1ad820ce28e15f2b8622fcdb8942397c8791c6c12807bb5afbd4a9ec855dfa0207d3e4b753a103246e03c0ee';
  if (!admin.length) {
    await sql`INSERT INTO unisquad_users(id,name,username,password_hash,role)
      VALUES('admin','أدمن المنصة','admin',${temporaryAdminHash},'admin')`;
  }
  const state = await sql`SELECT id,data FROM unisquad_state WHERE id=1`;
  if (admin.length && state.length) {
    const existingData = state[0].data || {};
    if (existingData.adminPasswordInitialized !== true) {
      await sql`UPDATE unisquad_users SET password_hash=${temporaryAdminHash} WHERE LOWER(username)='admin'`;
      existingData.adminPasswordInitialized = true;
      await sql`UPDATE unisquad_state SET data=${JSON.stringify(existingData)},updated_at=NOW() WHERE id=1`;
    }
  }
  if (!state.length) {
    await sql`INSERT INTO unisquad_state(id,data) VALUES(1,${JSON.stringify({
      posts: [], links: [], attendance: {}, meetings: [],
      subCodes: [
        {code:'SQ-9981',isUsed:false,usedBy:null},
        {code:'SQ-4412',isUsed:false,usedBy:null},
        {code:'SQ-7731',isUsed:false,usedBy:null}
      ], settings: { tabs: {
        feed:'الأسئلة والبوستات', links:'الروابط والمحاضرات',
        attendance:'مين النازل بكرة؟', meetings:'جلسات المذاكرة', admin:'لوحة الإشراف'
      }}
    })})`;
  }
  // Repair older databases that were created with an empty code list.
  const currentState = await sql\`SELECT data FROM unisquad_state WHERE id=1\`;
  if (currentState.length) {
    const d = currentState[0].data || {};
    if (!Array.isArray(d.subCodes) || d.subCodes.length === 0) {
      d.subCodes = [
        {code:'SQ-9981',isUsed:false,usedBy:null},
        {code:'SQ-4412',isUsed:false,usedBy:null},
        {code:'SQ-7731',isUsed:false,usedBy:null}
      ];
      await sql\`UPDATE unisquad_state SET data=\${JSON.stringify(d)},updated_at=NOW() WHERE id=1\`;
    }
  }
}

async function auth(sql, req) {
  const h = String(req.headers.authorization || '');
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!token) return null;
  const rows = await sql`SELECT u.* FROM unisquad_sessions s
    JOIN unisquad_users u ON u.id=s.user_id
    WHERE s.token=${token} AND s.expires_at>NOW() LIMIT 1`;
  return rows[0] || null;
}

async function snapshot(sql) {
  const s = await sql`SELECT data FROM unisquad_state WHERE id=1`;
  const data = s[0]?.data || {};
  const users = await sql`SELECT id,name,username,role,banned_until,ban_reason,created_at
    FROM unisquad_users ORDER BY created_at ASC`;
  return {
    ...data,
    users: users.map(u => ({
      id:u.id,name:u.name,username:u.username,role:u.role,
      bannedUntil:u.banned_until,banReason:u.ban_reason
    }))
  };
}

module.exports = async (req, res) => {
  try {
    const sql = db();
    await init(sql);
    const path = String(req.url || '').split('?')[0];

    if (req.method === 'POST' && (path.endsWith('/api') || path.endsWith('/api/'))) {
      const b = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
      if (b.action === 'login') {
        const rows = await sql`SELECT * FROM unisquad_users WHERE LOWER(username)=LOWER(${String(b.username||'').trim()}) LIMIT 1`;
        const u = rows[0];
        if (!u || !verify(b.password || '', u.password_hash))
          return send(res,401,{ok:false,error:'بيانات الدخول غير صحيحة. راجع اسم المستخدم وكلمة السر وحاول مرة أخرى.'});
        if (u.banned_until && new Date(u.banned_until)>new Date())
          return send(res,403,{ok:false,error:'حسابك محظور مؤقتًا حتى '+new Date(u.banned_until).toLocaleString('ar-EG')});
        const t=makeToken();
        await sql`INSERT INTO unisquad_sessions(token,user_id,expires_at)
          VALUES(${t},${u.id},NOW()+INTERVAL '30 days')`;
        return send(res,200,{ok:true,token:t,user:{
          id:u.id,name:u.name,username:u.username,role:u.role,
          bannedUntil:u.banned_until,banReason:u.ban_reason
        },data:await snapshot(sql)});
      }
      if (b.action === 'register') {
        const name=String(b.fullName||'').trim();
        const username=String(b.username||'').trim().toLowerCase();
        const password=String(b.password||'');
        const code=String(b.code||'').trim().toUpperCase();
        if(name.length<5) return send(res,400,{ok:false,error:'اكتب الاسم الثلاثي بشكل صحيح.'});
        if(!/^[a-zA-Z0-9_]{3,20}$/.test(username))
          return send(res,400,{ok:false,error:'اسم المستخدم يجب أن يكون 3 إلى 20 حرفًا إنجليزيًا أو رقمًا أو _. '});
        if(password.length<8) return send(res,400,{ok:false,error:'كلمة السر يجب ألا تقل عن 8 أحرف.'});
        const exists=await sql`SELECT id FROM unisquad_users WHERE LOWER(username)=LOWER(${username}) LIMIT 1`;
        if(exists.length) return send(res,409,{ok:false,error:'اسم المستخدم هذا مستخدم بالفعل.'});
        const s=await sql`SELECT data FROM unisquad_state WHERE id=1`;
        const data=s[0].data||{};
        const codes=Array.isArray(data.subCodes)?data.subCodes:[];
        const c=codes.find(x=>String(x.code).toUpperCase()===code&&!x.isUsed);
        if(!c) return send(res,400,{ok:false,error:'كود الاشتراك غير صحيح أو تم استخدامه مسبقًا.'});
        c.isUsed=true;c.usedBy=username;data.subCodes=codes;
        await sql`UPDATE unisquad_state SET data=${JSON.stringify(data)},updated_at=NOW() WHERE id=1`;
        const id=crypto.randomUUID();
        await sql`INSERT INTO unisquad_users(id,name,username,password_hash,role)
          VALUES(${id},${name},${username},${hash(password)},'student')`;
        const t=makeToken();
        await sql`INSERT INTO unisquad_sessions(token,user_id,expires_at)
          VALUES(${t},${id},NOW()+INTERVAL '30 days')`;
        return send(res,200,{ok:true,token:t,user:{id,name,username,role:'student',bannedUntil:null,banReason:null},data:await snapshot(sql)});
      }
      return send(res,400,{ok:false,error:'طلب غير معروف.'});
    }

    const u=await auth(sql,req);
    if(!u) return send(res,401,{ok:false,error:'انتهت الجلسة. سجل الدخول مرة أخرى.'});

    if(req.method==='GET') return send(res,200,{ok:true,user:{
      id:u.id,name:u.name,username:u.username,role:u.role,bannedUntil:u.banned_until,banReason:u.ban_reason
    },data:await snapshot(sql)});

    const b=typeof req.body==='string'?JSON.parse(req.body||'{}'):(req.body||{});
    const action=b.action;
    const s=await sql`SELECT data FROM unisquad_state WHERE id=1`;
    const data=s[0].data||{};
    data.posts=Array.isArray(data.posts)?data.posts:[];
    data.links=Array.isArray(data.links)?data.links:[];
    data.meetings=Array.isArray(data.meetings)?data.meetings:[];
    data.attendance=data.attendance||{};
    data.subCodes=Array.isArray(data.subCodes)?data.subCodes:[];
    data.settings=data.settings||{tabs:{}};

    const adminActions=['generate_code','update_link','delete_link','delete_post','delete_comment',
      'delete_meeting','ban_user','unban_user','delete_user','set_role','change_admin_password','update_settings','bootstrap'];
    if(adminActions.includes(action)&&u.role!=='admin')
      return send(res,403,{ok:false,error:'هذه الصلاحية للأدمن فقط.'});

    if(action==='bootstrap'){
      if(data.posts.length||data.links.length||data.meetings.length||Object.keys(data.attendance).length)
        return send(res,409,{ok:false,error:'قاعدة البيانات تحتوي على بيانات بالفعل.'});
      const incoming=b.state||{};
      data.posts=Array.isArray(incoming.posts)?incoming.posts:[];
      data.links=Array.isArray(incoming.links)?incoming.links:[];
      data.meetings=Array.isArray(incoming.meetings)?incoming.meetings:[];
      data.attendance=incoming.attendance||{};
      if(Array.isArray(incoming.subCodes) && incoming.subCodes.length) data.subCodes=incoming.subCodes;
      data.settings=incoming.settings||data.settings;
      await sql`UPDATE unisquad_state SET data=${JSON.stringify(data)},updated_at=NOW() WHERE id=1`;
      return send(res,200,{ok:true,data:await snapshot(sql)});
    }

    if(action==='create_post'){
      data.posts.unshift({id:'p_'+Date.now()+'_'+crypto.randomBytes(3).toString('hex'),
        author:u.name,username:u.username,text:String(b.text||''),time:'الآن',
        comments:[],image:b.image||null,audio:b.audio||null});
    } else if(action==='add_comment'){
      const p=data.posts.find(x=>x.id===b.postId); if(!p) return send(res,404,{ok:false,error:'المنشور غير موجود.'});
      p.comments=Array.isArray(p.comments)?p.comments:[];
      p.comments.push({id:'c_'+Date.now()+'_'+crypto.randomBytes(3).toString('hex'),
        author:u.name,username:u.username,text:String(b.text||'')});
    } else if(action==='create_link'){
      data.links.unshift({id:'l_'+Date.now()+'_'+crypto.randomBytes(3).toString('hex'),
        title:String(b.title||''),url:String(b.url||''),category:String(b.category||'other'),
        author:u.name,username:u.username});
    } else if(action==='update_link'){
      const l=data.links.find(x=>x.id===b.id); if(!l) return send(res,404,{ok:false,error:'الرابط غير موجود.'});
      Object.assign(l,{title:String(b.title||l.title),url:String(b.url||l.url),category:String(b.category||l.category)});
    } else if(action==='delete_link'){
      data.links=data.links.filter(x=>x.id!==b.id);
    } else if(action==='delete_post'){
      data.posts=data.posts.filter(x=>x.id!==b.id);
    } else if(action==='delete_comment'){
      const p=data.posts.find(x=>x.id===b.postId); if(p) p.comments=(p.comments||[]).filter(x=>x.id!==b.commentId);
    } else if(action==='vote_attendance'){
      data.attendance[u.username]=String(b.status||'');
    } else if(action==='create_meeting'){
      data.meetings.unshift({id:'m_'+Date.now()+'_'+crypto.randomBytes(3).toString('hex'),
        title:String(b.title||''),time:String(b.time||''),url:String(b.url||''),author:u.name,username:u.username});
    } else if(action==='delete_meeting'){
      data.meetings=data.meetings.filter(x=>x.id!==b.id);
    } else if(action==='generate_code'){
      data.subCodes.unshift({code:'SQ-'+Math.floor(100000+Math.random()*900000),isUsed:false,usedBy:null});
    } else if(action==='ban_user'){
      const until=new Date();until.setDate(until.getDate()+(Number(b.days)||1));
      await sql`UPDATE unisquad_users SET banned_until=${until.toISOString()},ban_reason=${String(b.reason||'')}
        WHERE id=${String(b.userId)} AND role<>'admin'`;
    } else if(action==='unban_user'){
      await sql`UPDATE unisquad_users SET banned_until=NULL,ban_reason=NULL
        WHERE id=${String(b.userId)} AND role<>'admin'`;
    } else if(action==='delete_user'){
      if(String(b.userId)===String(u.id)) return send(res,400,{ok:false,error:'لا يمكنك حذف حسابك الحالي.'});
      await sql`DELETE FROM unisquad_users WHERE id=${String(b.userId)} AND role<>'admin'`;
      if(b.username) delete data.attendance[String(b.username)];
    } else if(action==='set_role'){
      if(String(b.userId)===String(u.id)) return send(res,400,{ok:false,error:'لا تغيّر صلاحية حسابك الحالي.'});
      await sql`UPDATE unisquad_users SET role=${b.role==='admin'?'admin':'student'} WHERE id=${String(b.userId)}`;
    } else if(action==='change_admin_password'){
      if(String(b.password||'').length<8) return send(res,400,{ok:false,error:'كلمة السر يجب ألا تقل عن 8 أحرف.'});
      await sql`UPDATE unisquad_users SET password_hash=${hash(b.password)} WHERE id=${u.id}`;
    } else if(action==='update_settings'){
      data.settings={...(data.settings||{}),...(b.settings||{})};
    } else return send(res,400,{ok:false,error:'عملية غير معروفة.'});

    await sql`UPDATE unisquad_state SET data=${JSON.stringify(data)},updated_at=NOW() WHERE id=1`;
    return send(res,200,{ok:true,data:await snapshot(sql)});
  } catch(e) {
    console.error(e);
    return send(res,500,{ok:false,error:'حصل خطأ في الخادم. جرّب مرة أخرى.'});
  }
};
