const express=require("express");
const fs=require("fs");
const path=require("path");
const crypto=require("crypto");
const {spawn}=require("child_process");

const app=express(), PORT=process.env.PORT||3000, ROOT=__dirname;
const DB=path.join(ROOT,"data.json"), SD=path.join(ROOT,"servers");
fs.mkdirSync(SD,{recursive:true});
if(!fs.existsSync(DB))fs.writeFileSync(DB,JSON.stringify({users:[],servers:[]},null,2));

const readDB=()=>JSON.parse(fs.readFileSync(DB,"utf8"));
const saveDB=d=>fs.writeFileSync(DB,JSON.stringify(d,null,2));
const sessions=new Map(), procs=new Map(), logs=new Map();

app.use(express.json({limit:"25mb"}));
app.use(express.static(path.join(ROOT,"public")));

function hash(p,s=crypto.randomBytes(16).toString("hex")){return s+":"+crypto.scryptSync(p,s,64).toString("hex")}
function check(p,v){const [s,h]=v.split(":");return crypto.timingSafeEqual(Buffer.from(h,"hex"),crypto.scryptSync(p,s,64))}
function auth(req,res,next){
  const t=(req.headers.authorization||"").replace("Bearer ",""),uid=sessions.get(t);
  const db=readDB(),u=db.users.find(x=>x.id===uid);
  if(!u)return res.status(401).json({error:"Não autenticado"});
  req.user=u;next();
}
function admin(req,res,next){if(req.user.email!==process.env.ADMIN_EMAIL)return res.status(403).json({error:"Acesso administrativo negado"});next()}
function safe(s){return String(s).replace(/[^a-zA-Z0-9_-]/g,"").slice(0,40)}
function owned(req,id){return readDB().servers.find(s=>s.id===id&&s.owner===req.user.id)}
function info(s){return {...s,online:procs.has(s.id),pid:procs.get(s.id)?.pid||null}}

app.post("/api/register",(req,res)=>{
 const email=String(req.body.email||"").trim().toLowerCase(),pass=String(req.body.password||"");
 if(!/^\S+@\S+\.\S+$/.test(email)||pass.length<6)return res.status(400).json({error:"E-mail inválido ou senha curta."});
 const db=readDB();if(db.users.some(u=>u.email===email))return res.status(409).json({error:"E-mail já cadastrado."});
 const u={id:crypto.randomUUID(),email,password:hash(pass),createdAt:new Date().toISOString()};db.users.push(u);saveDB(db);
 const token=crypto.randomUUID();sessions.set(token,u.id);res.json({token,user:{id:u.id,email:u.email}});
});
app.post("/api/login",(req,res)=>{
 const email=String(req.body.email||"").trim().toLowerCase(),pass=String(req.body.password||""),u=readDB().users.find(x=>x.email===email);
 if(!u||!check(pass,u.password))return res.status(401).json({error:"Login inválido."});
 const token=crypto.randomUUID();sessions.set(token,u.id);res.json({token,user:{id:u.id,email:u.email}});
});
app.get("/api/me",auth,(req,res)=>res.json({id:req.user.id,email:req.user.email}));

app.get("/api/servers",auth,(req,res)=>res.json(readDB().servers.filter(s=>s.owner===req.user.id).map(info)));
app.post("/api/servers",auth,(req,res)=>{
 const id=safe(req.body.id),name=String(req.body.name||"Meu servidor").trim(),port=Number(req.body.port||7777);
 if(!id)return res.status(400).json({error:"ID inválido."});
 if(!Number.isInteger(port)||port<1024||port>65535)return res.status(400).json({error:"Porta inválida."});
 const db=readDB();if(db.servers.some(s=>s.id===id))return res.status(409).json({error:"ID já existe."});
 const s={id,name,port,owner:req.user.id,createdAt:new Date().toISOString()};db.servers.push(s);saveDB(db);
 fs.mkdirSync(path.join(SD,id),{recursive:true});res.json(info(s));
});

app.post("/api/servers/:id/action",auth,(req,res)=>{
 const s=owned(req,req.params.id),a=req.body.action;
 if(!s)return res.status(404).json({error:"Servidor não encontrado."});
 if(a==="stop"){const p=procs.get(s.id);if(p)p.kill();procs.delete(s.id);return res.json(info(s))}
 if(!["start","restart"].includes(a))return res.status(400).json({error:"Ação inválida."});
 if(a==="restart"){const p=procs.get(s.id);if(p)p.kill();procs.delete(s.id)}
 if(procs.has(s.id))return res.json(info(s));
 const dir=path.join(SD,s.id),exe=process.platform==="win32"?path.join(dir,"samp-server.exe"):path.join(dir,"samp-server");
 if(!fs.existsSync(exe))return res.status(400).json({error:"Coloque samp-server/samp-server.exe na pasta do servidor."});
 const p=spawn(exe,[],{cwd:dir});
 procs.set(s.id,p);logs.set(s.id,[]);
 const push=(data)=>{const l=logs.get(s.id)||[];l.push(data.toString());logs.set(s.id,l.slice(-300))};
 p.stdout?.on("data",push);p.stderr?.on("data",push);p.on("exit",(code)=>{push("\nProcesso encerrado. Código: "+code);procs.delete(s.id)});
 res.json(info(s));
});

app.get("/api/servers/:id/logs",auth,(req,res)=>{
 const s=owned(req,req.params.id);if(!s)return res.status(404).json({error:"Servidor não encontrado."});
 res.json({logs:(logs.get(s.id)||[]).join("")});
});

app.get("/api/servers/:id/files",auth,(req,res)=>{
 const s=owned(req,req.params.id);if(!s)return res.status(404).json({error:"Servidor não encontrado."});
 const dir=path.join(SD,s.id);
 res.json(fs.readdirSync(dir,{withFileTypes:true}).map(x=>({name:x.name,type:x.isDirectory()?"dir":"file"})));
});

app.post("/api/servers/:id/file",auth,(req,res)=>{
 const s=owned(req,req.params.id);if(!s)return res.status(404).json({error:"Servidor não encontrado."});
 const name=path.basename(String(req.body.name||""));if(!name||name.includes(".."))return res.status(400).json({error:"Nome inválido."});
 fs.writeFileSync(path.join(SD,s.id,name),String(req.body.content||""));res.json({ok:true});
});

app.get("/api/admin/stats",auth,admin,(req,res)=>{
 const db=readDB();res.json({users:db.users.length,servers:db.servers.length,online:db.servers.filter(s=>procs.has(s.id)).length});
});

app.get("*splat",(req,res)=>res.sendFile(path.join(ROOT,"public","index.html")));
app.listen(PORT,()=>console.log("SA-MP Host v0.3 em http://localhost:"+PORT));
