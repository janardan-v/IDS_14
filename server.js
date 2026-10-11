const express = require("express");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const app = express(), PORT = process.env.PORT || 3000;
const DATA = path.join(__dirname, "data"), USERS = path.join(DATA, "users.json");
const TTL = 60_000, challenges = new Map(), sessions = new Map();
fs.mkdirSync(DATA, {recursive:true});
if (!fs.existsSync(USERS)) fs.writeFileSync(USERS, "{}");
app.use(express.json({limit:"16kb"}));
app.use(express.static(path.join(__dirname,"public")));
const keys = crypto.generateKeyPairSync("rsa",{modulusLength:2048,publicKeyEncoding:{type:"spki",format:"pem"},privateKeyEncoding:{type:"pkcs8",format:"pem"}});
const readUsers=()=>JSON.parse(fs.readFileSync(USERS,"utf8"));
const writeUsers=u=>fs.writeFileSync(USERS,JSON.stringify(u,null,2),{mode:0o600});
function audit(event,details={}) {
  fs.appendFileSync(path.join(DATA,"audit.log"),JSON.stringify({time:new Date().toISOString(),event,...details})+"\n");
}
function b64(value,n) {
  if(typeof value!=="string"||!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return null;
  const b=Buffer.from(value,"base64");
  return b.length===n&&b.toString("base64")===value?b:null;
}
const signedPayload=(u,c,e)=>`${u}\n${c}\n${e}`;
app.get("/api/status",(_q,s)=>s.json({status:"online",challengeTtlSeconds:60}));
app.get("/api/public-key",(_q,s)=>s.json({algorithm:"RSA-PSS-SHA256",publicKey:keys.publicKey}));
app.post("/api/register",(q,s)=>{
  const {username,salt,verifier}=q.body||{};
  if(typeof username!=="string"||! /^[A-Za-z0-9_.-]{1,40}$/.test(username))
    return s.status(400).json({error:"Username must be 1–40 letters, digits, dot, underscore or hyphen."});
  if(!b64(salt,16)||!b64(verifier,32)) return s.status(400).json({error:"Invalid salt or verifier."});
  const users=readUsers();
  if(users[username]) return s.status(409).json({error:"Username already exists."});
  users[username]={salt,verifier,createdAt:new Date().toISOString()}; writeUsers(users);
  audit("REGISTER",{username,passwordReceived:false});
  s.status(201).json({message:`User "${username}" registered. Salt and PBKDF2 verifier stored; password not received.`});
});
app.post("/api/request-challenge",(q,s)=>{
  const {username}=q.body||{}, user=readUsers()[username];
  if(typeof username!=="string"||!user) return s.status(404).json({error:"Unknown username. Register first."});
  const challengeId=crypto.randomBytes(18).toString("base64url");
  const challenge=crypto.randomBytes(32).toString("base64"), expiresAt=Date.now()+TTL;
  const payload=signedPayload(username,challenge,expiresAt);
  const signature=crypto.sign("sha256",Buffer.from(payload),{key:keys.privateKey,padding:crypto.constants.RSA_PKCS1_PSS_PADDING,saltLength:32}).toString("base64");
  challenges.set(challengeId,{username,challenge,expiresAt,used:false});
  audit("CHALLENGE_ISSUED",{username,challengeId});
  s.json({challengeId,challenge,salt:user.salt,expiresAt,expiresInSeconds:60,signature,signedPayload:payload});
});
app.post("/api/verify",(q,s)=>{
  const {username,challengeId,response}=q.body||{}, item=challenges.get(challengeId);
  if(typeof username!=="string"||typeof challengeId!=="string"||typeof response!=="string")
    return s.status(400).json({error:"Malformed verification request."});
  if(!item||item.username!==username) return s.status(401).json({error:"Unknown challenge."});
  if(item.used){audit("REPLAY_BLOCKED",{username,challengeId});return s.status(409).json({error:"Challenge already used — REPLAY ATTACK BLOCKED."});}
  item.used=true;
  if(Date.now()>item.expiresAt) return s.status(401).json({error:"Challenge expired. Request a new one."});
  const verifier=b64(readUsers()[username]?.verifier,32), supplied=b64(response,32);
  if(!verifier||!supplied) return s.status(401).json({error:"Invalid HMAC response."});
  const expected=crypto.createHmac("sha256",verifier).update(Buffer.from(item.challenge,"base64")).digest();
  if(expected.length!==supplied.length||!crypto.timingSafeEqual(expected,supplied)){
    audit("LOGIN_FAILED",{username,reason:"hmac_mismatch"});
    return s.status(401).json({error:"LOGIN FAILED (HMAC mismatch)."});
  }
  const token=crypto.randomBytes(32).toString("base64url");
  sessions.set(token,{username,createdAt:Date.now()}); audit("LOGIN_SUCCESS",{username});
  s.json({message:"LOGIN SUCCESS",sessionToken:token});
});
app.get("/api/audit",(_q,s)=>{
  const file=path.join(DATA,"audit.log");
  const events=fs.existsSync(file)?fs.readFileSync(file,"utf8").trim().split("\n").filter(Boolean).slice(-30).map(x=>JSON.parse(x)):[];
  s.json({events});
});
app.listen(PORT,()=>console.log(`IDS Experiment 14 running at http://localhost:${PORT}`));
