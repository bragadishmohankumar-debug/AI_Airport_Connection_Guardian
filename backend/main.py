from __future__ import annotations
import asyncio, hashlib, hmac, json, math, os, secrets, sqlite3, time, urllib.parse, urllib.request, datetime
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, Request, Response, Cookie, Header, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field

BASE = Path(__file__).resolve().parent.parent
FRONT = BASE / 'frontend'; DATA = BASE / 'data'; DATA.mkdir(exist_ok=True)
DB = DATA / 'guardian.db'
VERSION = '2.1.0'
SESSION_TTL = 8 * 60 * 60
SECURE_COOKIE = os.getenv('COOKIE_SECURE', '0') == '1'
AVIATIONSTACK_KEY = os.getenv('AVIATIONSTACK_API_KEY', '').strip()
OPEN_METEO_ENABLED = os.getenv('OPEN_METEO_ENABLED', '1') != '0'
REFRESH_SECONDS = max(30, int(os.getenv('REFRESH_SECONDS', '60')))
OPEN_SKY_ENABLED = os.getenv('OPEN_SKY_ENABLED', '1') != '0'
OPEN_SKY_BBOX = {'lamin': 12.85, 'lomin': 80.05, 'lamax': 13.15, 'lomax': 80.30}
LIVE_FLIGHTS: list[dict] = []
LIVE_FLIGHTS_UPDATED = 0

app = FastAPI(title='AI Airport Connection Guardian', version=VERSION, docs_url='/api/docs', redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=['http://127.0.0.1:8000','http://localhost:8000'], allow_credentials=True, allow_methods=['*'], allow_headers=['*'])
RATE: dict[str, list[float]] = {}
CLIENTS: set[WebSocket] = set()

# Demo data is intentionally transparent: it is synthetic airport/operational data for a complete local demo.
FLIGHTS = [
    {'id':'6E604','airline':'IndiGo','number':'6E 604','from':'MAA','to':'DEL','from_name':'Chennai','to_name':'Delhi','dep':'08:10','arr':'11:05','terminal':'T1','gate':'A04','status':'On time','delay':0},
    {'id':'AI201','airline':'Air India','number':'AI 201','from':'DEL','to':'LHR','from_name':'Delhi','to_name':'London','dep':'11:55','arr':'16:40','terminal':'T3','gate':'B12','status':'On time','delay':0},
    {'id':'6E6817','airline':'IndiGo','number':'6E 6817','from':'MAA','to':'BOM','from_name':'Chennai','to_name':'Mumbai','dep':'10:25','arr':'12:20','terminal':'T2','gate':'C07','status':'On time','delay':0},
    {'id':'AI642','airline':'Air India','number':'AI 642','from':'BOM','to':'DEL','from_name':'Mumbai','to_name':'Delhi','dep':'13:10','arr':'15:20','terminal':'T2','gate':'D08','status':'On time','delay':0},
    {'id':'6E112','airline':'IndiGo','number':'6E 112','from':'DEL','to':'BLR','from_name':'Delhi','to_name':'Bengaluru','dep':'12:20','arr':'15:10','terminal':'T1','gate':'A11','status':'On time','delay':0},
]

# Delhi-style indoor digital twin used for the prototype. Nodes represent passenger-accessible zones.
ZONES = {
    'A04': {'name':'Gate A04','x':18,'y':67,'terminal':'T3','type':'gate'},
    'Security': {'name':'Security','x':43,'y':52,'terminal':'T3','type':'security'},
    'Immigration': {'name':'Immigration','x':55,'y':35,'terminal':'T3','type':'immigration'},
    'Baggage': {'name':'Baggage Hall','x':74,'y':64,'terminal':'T3','type':'baggage'},
    'B12': {'name':'Gate B12','x':84,'y':27,'terminal':'T3','type':'gate'},
    'Ground': {'name':'Ground Transport','x':80,'y':84,'terminal':'T3','type':'ground'},
    'HelpDesk': {'name':'Connection Desk','x':57,'y':72,'terminal':'T3','type':'support'},
}
ROUTES = {
    'A04': {'Security':7,'HelpDesk':8}, 'Security':{'A04':7,'Immigration':5,'HelpDesk':5},
    'Immigration':{'Security':5,'B12':9,'Baggage':7}, 'Baggage':{'Immigration':7,'B12':8,'Ground':5},
    'B12':{'Immigration':9,'Baggage':8,'Ground':6}, 'HelpDesk':{'A04':8,'Security':5,'Ground':6},
    'Ground':{'B12':6,'Baggage':5,'HelpDesk':6}
}

class Login(BaseModel): email: EmailStr; password: str = Field(min_length=1, max_length=128)
class Register(BaseModel): name: str = Field(min_length=2, max_length=80); email: EmailStr; password: str = Field(min_length=8, max_length=128)
class Setup(BaseModel): inbound_id: str; outbound_id: str; passenger_zone: str = 'A04'; bags: int = Field(default=1, ge=0, le=8); immigration: bool = False
class Position(BaseModel): zone: str
class Scenario(BaseModel): delay: int = Field(default=0, ge=0, le=240); gate_change: Optional[str] = None; baggage_delay: int = Field(default=0, ge=0, le=60); crowd: int = Field(default=50, ge=0, le=100)


def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c

def limit(key: str, n=20, window=60):
    now=time.time(); vals=[x for x in RATE.get(key,[]) if now-x<window]
    if len(vals)>=n: raise HTTPException(429,'Too many requests. Try again shortly.')
    vals.append(now); RATE[key]=vals

def hash_pw(pw,salt=None):
    salt=salt or secrets.token_bytes(16); return hashlib.scrypt(pw.encode(),salt=salt,n=2**14,r=8,p=1,dklen=32).hex(),salt.hex()
def verify_pw(pw,h,s): return hmac.compare_digest(hashlib.scrypt(pw.encode(),salt=bytes.fromhex(s),n=2**14,r=8,p=1,dklen=32).hex(),h)
def th(t): return hashlib.sha256(t.encode()).hexdigest()

def init_db():
    c=db(); c.executescript('''
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE NOT NULL,name TEXT NOT NULL,password_hash TEXT NOT NULL,salt TEXT NOT NULL,created_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL,csrf TEXT NOT NULL,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
    CREATE TABLE IF NOT EXISTS connection_sessions(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,inbound_id TEXT NOT NULL,outbound_id TEXT NOT NULL,zone TEXT NOT NULL,bags INTEGER NOT NULL,immigration INTEGER NOT NULL,scenario TEXT NOT NULL,created_at INTEGER NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
    '''); c.commit(); c.close()

def session_row(token):
    if not token: raise HTTPException(401,'Please sign in again.')
    c=db(); r=c.execute('SELECT s.*,u.email,u.name FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?',(th(token),int(time.time()))).fetchone(); c.close()
    if not r: raise HTTPException(401,'Your session has expired. Please sign in again.')
    return r

def csrf_ok(s,h):
    if not h or not hmac.compare_digest(h,s['csrf']): raise HTTPException(403,'Security check failed. Refresh the page.')
def set_cookie(resp,token): resp.set_cookie('guardian_session',token,httponly=True,secure=SECURE_COOKIE,samesite='lax',max_age=SESSION_TTL,path='/')
def new_session(uid):
    token=secrets.token_urlsafe(32); csrf=secrets.token_urlsafe(24); now=int(time.time()); c=db(); c.execute('INSERT INTO sessions VALUES(?,?,?,?,?)',(th(token),uid,csrf,now,now+SESSION_TTL)); c.execute('DELETE FROM sessions WHERE expires_at<?',(now,)); c.commit(); c.close(); return token,csrf

def http_json(url,timeout=8):
    req=urllib.request.Request(url,headers={'User-Agent':'AirportConnectionGuardian/1.0'})
    with urllib.request.urlopen(req,timeout=timeout) as r: return json.loads(r.read().decode())

def _iso_minutes(value: str | None) -> str:
    if not value:
        return ''
    return value[11:16] if len(value) >= 16 else value

def _map_aviationstack(x: dict) -> dict:
    f=x.get('flight',{}); dep=x.get('departure',{}); arr=x.get('arrival',{}); live=x.get('live') or {}
    number=f.get('iata') or f.get('number') or '—'
    return {
        'id': f"live-{f.get('icao') or number}-{x.get('flight_date') or ''}",
        'airline': (x.get('airline') or {}).get('name') or 'Unknown',
        'number': number,
        'from': dep.get('iata') or dep.get('icao') or '—',
        'to': arr.get('iata') or arr.get('icao') or '—',
        'from_name': dep.get('airport') or dep.get('iata') or '—',
        'to_name': arr.get('airport') or arr.get('iata') or '—',
        'dep': _iso_minutes(dep.get('scheduled') or dep.get('estimated')),
        'arr': _iso_minutes(arr.get('scheduled') or arr.get('estimated')),
        'terminal': dep.get('terminal') or arr.get('terminal') or '—',
        'gate': dep.get('gate') or arr.get('gate') or '—',
        'status': x.get('flight_status') or 'unknown',
        'delay': int(round((dep.get('delay') or 0))),
        'scheduled_departure': dep.get('scheduled'),
        'estimated_departure': dep.get('estimated'),
        'scheduled_arrival': arr.get('scheduled'),
        'estimated_arrival': arr.get('estimated'),
        'latitude': live.get('latitude'),
        'longitude': live.get('longitude'),
        'altitude_m': live.get('altitude'),
        'speed_kmh': round((live.get('speed_horizontal') or 0) * 1.852, 1) if live.get('speed_horizontal') else None,
        'source': 'Aviationstack',
        'updated': int(time.time())
    }

def flight_data(query: str = ''):
    global LIVE_FLIGHTS, LIVE_FLIGHTS_UPDATED
    if not AVIATIONSTACK_KEY:
        return {'items': FLIGHTS, 'live': False, 'source':'Demo airport data', 'message':'Set AVIATIONSTACK_API_KEY for live flight-status polling.', 'updated': int(time.time())}
    try:
        params={'access_key':AVIATIONSTACK_KEY,'limit':100}
        q=query.strip().upper()
        if q:
            params['flight_iata']=q
        else:
            params['dep_iata']='DEL'
        d=http_json('https://api.aviationstack.com/v1/flights?'+urllib.parse.urlencode(params),12)
        items=[_map_aviationstack(x) for x in d.get('data',[])]
        if items:
            LIVE_FLIGHTS=items
            LIVE_FLIGHTS_UPDATED=int(time.time())
            return {'items':items, 'live':True, 'source':'Aviationstack', 'updated':LIVE_FLIGHTS_UPDATED}
        return {'items': FLIGHTS, 'live':False, 'source':'Aviationstack', 'message':'Provider returned no matching flights.', 'updated':int(time.time())}
    except Exception as e:
        return {'items':LIVE_FLIGHTS or FLIGHTS, 'live':bool(LIVE_FLIGHTS), 'source':'Aviationstack cache' if LIVE_FLIGHTS else 'Demo airport data', 'message':'Live provider unavailable; showing the last known data.' if LIVE_FLIGHTS else 'Live provider unavailable; using transparent demo data.', 'error':str(e), 'updated':LIVE_FLIGHTS_UPDATED or int(time.time())}

def open_sky():
    if not OPEN_SKY_ENABLED:
        return {'items': [], 'live': False, 'source':'disabled', 'updated':int(time.time())}
    try:
        q=urllib.parse.urlencode(OPEN_SKY_BBOX)
        d=http_json('https://opensky-network.org/api/states/all?'+q,12)
        rows=[]
        stamp=d.get('time')
        for x in d.get('states') or []:
            if len(x) < 12:
                continue
            rows.append({
                'icao24':x[0],
                'callsign':(x[1] or '').strip(),
                'longitude':x[5],
                'latitude':x[6],
                'altitude_m':x[7],
                'on_ground':x[8],
                'velocity_ms':x[9],
                'heading':x[10],
                'vertical_rate_ms':x[11],
                'updated_at': datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc).isoformat() if stamp else None
            })
        return {'items':rows,'live':True,'source':'OpenSky Network','updated':int(time.time())}
    except Exception as e:
        return {'items':[],'live':False,'source':'OpenSky Network','error':str(e),'updated':int(time.time())}

def weather():
    if not OPEN_METEO_ENABLED: return {'live':False,'source':'disabled'}
    try:
        q=urllib.parse.urlencode({'latitude':28.5562,'longitude':77.1000,'current':'temperature_2m,precipitation,wind_speed_10m,weather_code','timezone':'Asia/Kolkata'})
        d=http_json('https://api.open-meteo.com/v1/forecast?'+q); cur=d.get('current',{})
        return {'live':True,'source':'Open-Meteo','temperature':cur.get('temperature_2m'),'precipitation':cur.get('precipitation'),'wind':cur.get('wind_speed_10m'),'code':cur.get('weather_code'),'updated':int(time.time())}
    except Exception as e: return {'live':False,'source':'unavailable','error':str(e)}

def get_session_state(uid):
    c=db(); r=c.execute('SELECT * FROM connection_sessions WHERE user_id=? ORDER BY id DESC LIMIT 1',(uid,)).fetchone(); c.close()
    if not r: return None
    try: scenario=json.loads(r['scenario'])
    except: scenario={}
    return {'id':r['id'],'inbound_id':r['inbound_id'],'outbound_id':r['outbound_id'],'zone':r['zone'],'bags':r['bags'],'immigration':bool(r['immigration']),'scenario':scenario}

def flight_by_id(fid):
    hit = next((f for f in LIVE_FLIGHTS if f['id']==fid), None)
    if hit:
        return hit
    hit = next((f for f in FLIGHTS if f['id']==fid), None)
    if hit:
        return hit
    if fid.startswith('live-') and AVIATIONSTACK_KEY:
        parts=fid.split('-')
        if len(parts) >= 2:
            q=parts[1]
            try:
                rows=flight_data(q).get('items',[])
                return next((f for f in rows if f.get('id')==fid or f.get('number','').replace(' ','').upper()==q.replace(' ','')), None)
            except Exception:
                return None
    return None

def minutes(hm):
    if not hm:
        raise ValueError('Missing flight time')
    raw=hm[11:16] if len(hm)>=16 and hm[4]=='-' else hm[:5]
    h,m=map(int,raw.split(':')); return h*60+m

def safe_minutes(hm, fallback=0):
    try: return minutes(hm)
    except Exception: return fallback

def connection_engine(inbound,outbound,zone,bags,immigration,scenario):
    inbound=dict(inbound); outbound=dict(outbound)
    delay=int(scenario.get('delay',0)); baggage_delay=int(scenario.get('baggage_delay',0)); crowd=int(scenario.get('crowd',50)); gate_change=scenario.get('gate_change')
    inbound_arr=safe_minutes(inbound.get('arr'), 0)
    outbound_dep=safe_minutes(outbound.get('dep'), inbound_arr + 60)
    # Handle connections that cross midnight.
    if outbound_dep <= inbound_arr:
        outbound_dep += 24*60
    inbound['arrival_minutes']=inbound_arr+delay
    outbound_gate=gate_change or outbound.get('gate','B12') or 'B12'
    boarding_close=outbound_dep-15
    available=max(0,boarding_close-inbound['arrival_minutes'])
    # Base transfer components in minutes. Crowd changes walking/security slightly.
    walk=ROUTES.get(zone,{}).get(outbound_gate, 15)
    if walk is None: walk=15
    walk=round(walk*(1+max(0,crowd-50)/250),1)
    security=8 + round(max(0,crowd-50)/25)
    immigration_time=10 if immigration else 0
    baggage=10 + baggage_delay if bags else 0
    buffer=5
    required=walk+security+immigration_time+baggage+buffer
    margin=available-required
    risk=max(0,min(99, round(50 - margin*3.4 + crowd*.18 + (10 if bags else 0))))
    if margin >= 12: level='SAFE'
    elif margin >= 0: level='TIGHT'
    elif margin >= -10: level='AT RISK'
    else: level='LIKELY MISSED'
    actions=[]
    if level in ('AT RISK','LIKELY MISSED'):
        actions=['Proceed directly to the connection route','Avoid non-essential airport stops']
        if bags: actions.append('Check baggage transfer status at the connection desk')
        if immigration: actions.append('Use the fastest available immigration lane')
        actions.append('Prepare airline connection support / rebooking options')
    else: actions=['Continue to the assigned gate','Keep boarding pass ready','Watch for gate or delay updates']
    return {'bags':bags,'immigration':immigration,'level':level,'risk':risk,'available_minutes':available,'required_minutes':round(required,1),'margin_minutes':round(margin,1),'walk_minutes':walk,'security_minutes':security,'immigration_minutes':immigration_time,'baggage_minutes':baggage,'buffer_minutes':buffer,'outbound_gate':outbound_gate,'boarding_close':f"{outbound.get('dep','—')} - 15 min",'actions':actions,'inbound_delay':delay,'crowd':crowd,'baggage_status':'At risk' if baggage_delay>10 else 'Transfer expected','message':{'SAFE':'Your connection has a healthy time buffer.','TIGHT':'Your connection is possible, but avoid delays.','AT RISK':'Your connection is at risk. Follow the rescue plan.','LIKELY MISSED':'The current transfer window is insufficient; recovery should be prepared.'}[level]}

def graph_route(start,goal):
    if start==goal:return [start],0
    dist={k:math.inf for k in ZONES}; prev={}; dist[start]=0; seen=set()
    while len(seen)<len(ZONES):
        u=min((k for k in ZONES if k not in seen),key=lambda k:dist[k],default=None)
        if u is None or dist[u]==math.inf:break
        seen.add(u)
        for v,w in ROUTES.get(u,{}).items():
            nd=dist[u]+w
            if nd<dist[v]: dist[v]=nd; prev[v]=u
    if goal not in prev and goal!=start:return [start,goal],15
    path=[]; x=goal
    while x!=start:path.append(x);x=prev[x]
    path.append(start);path.reverse();return path,round(dist[goal],1)

def state_payload(uid):
    s=get_session_state(uid)
    if not s:
        s={'inbound_id':'6E604','outbound_id':'AI201','zone':'A04','bags':1,'immigration':False,'scenario':{'delay':0,'gate_change':None,'baggage_delay':0,'crowd':50}}
    inbound=flight_by_id(s['inbound_id']) or FLIGHTS[0]; outbound=flight_by_id(s['outbound_id']) or FLIGHTS[1]
    # Live flight records drive the connection engine when available; the airport digital twin remains deterministic.
    engine=connection_engine(inbound,outbound,s['zone'],s['bags'],s['immigration'],s['scenario'])
    path,eta=graph_route(s['zone'],engine['outbound_gate'])
    rec=engine.copy(); rec['route']=path; rec['route_eta']=eta
    scenario_view={**s['scenario'],'bags':s['bags'],'immigration':s['immigration']}
    return {'inbound':inbound,'outbound':outbound,'engine':rec,'position':ZONES.get(s['zone'],ZONES['A04']),'zone':s['zone'],'zones':ZONES,'route_edges':ROUTES,'scenario':scenario_view,'weather':weather(),'flights':(LIVE_FLIGHTS or FLIGHTS),'source':{'flights':'Aviationstack' if LIVE_FLIGHTS else ('Aviationstack unavailable' if AVIATIONSTACK_KEY else 'Demo airport data'),'airspace':'OpenSky Network','weather':'Open-Meteo','indoor':'Airport Digital Twin demo','baggage':'Demo operational feed','ground':'Demo transport feed'},'updated':{'flights':LIVE_FLIGHTS_UPDATED,'weather':int(time.time())}}

@app.middleware('http')
async def security(request,call_next):
    r=await call_next(request)
    r.headers.update({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'strict-origin-when-cross-origin','Permissions-Policy':'geolocation=(self),camera=(),microphone=()','Content-Security-Policy':"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self' https://api.open-meteo.com https://api.aviationstack.com http://api.aviationstack.com; frame-ancestors 'none'"})
    if request.url.path.startswith('/api/'):r.headers['Cache-Control']='no-store'
    return r

@app.on_event('startup')
async def startup():
    init_db(); c=db();
    if not c.execute('SELECT id FROM users WHERE email=?',('demo@guardian.ai',)).fetchone():
        h,s=hash_pw('Guardian@123'); c.execute('INSERT INTO users(email,name,password_hash,salt,created_at) VALUES(?,?,?,?,?)',('demo@guardian.ai','Demo Traveller',h,s,int(time.time()))); c.commit()
    c.close(); asyncio.create_task(broadcast_loop())
    if AVIATIONSTACK_KEY:
        try: flight_data()
        except Exception: pass

async def broadcast(msg):
    for ws in list(CLIENTS):
        try: await ws.send_json(msg)
        except: CLIENTS.discard(ws)

async def broadcast_loop():
    while True:
        await asyncio.sleep(REFRESH_SECONDS)
        # The demo delay drifts only if the user explicitly sets a scenario; no hidden fake-live claim is made.
        fd = flight_data() if AVIATIONSTACK_KEY else {'items':FLIGHTS,'live':False,'source':'Demo airport data','updated':int(time.time())}
        sky = open_sky()
        await broadcast({'type':'heartbeat','time':int(time.time()),'weather':weather(),'flights':fd,'airspace':sky})

@app.get('/api/health')
def health(): return {'ok':True,'app':'AI Airport Connection Guardian','version':VERSION,'live_flight_provider':bool(AVIATIONSTACK_KEY),'weather_provider':OPEN_METEO_ENABLED}

@app.post('/api/register')
def register(p:Register,request:Request,response:Response):
    limit('register:'+str(request.client.host),5,300); email=p.email.lower().strip()
    if not(any(x.islower() for x in p.password) and any(x.isupper() for x in p.password) and any(x.isdigit() for x in p.password)): raise HTTPException(400,'Use uppercase, lowercase and a number.')
    h,s=hash_pw(p.password); c=db()
    try: cur=c.execute('INSERT INTO users(email,name,password_hash,salt,created_at) VALUES(?,?,?,?,?)',(email,p.name.strip(),h,s,int(time.time()))); c.commit();uid=cur.lastrowid
    except sqlite3.IntegrityError: c.close(); raise HTTPException(409,'An account with this email already exists.')
    c.close();tok,csrf=new_session(uid);set_cookie(response,tok);return {'ok':True,'csrf':csrf}

@app.post('/api/login')
def login(p:Login,request:Request,response:Response):
    limit('login:'+str(request.client.host),10,300);c=db();r=c.execute('SELECT * FROM users WHERE email=?',(p.email.lower().strip(),)).fetchone();c.close()
    if not r or not verify_pw(p.password,r['password_hash'],r['salt']):raise HTTPException(401,'Email or password is incorrect.')
    tok,csrf=new_session(r['id']);set_cookie(response,tok);return {'ok':True,'csrf':csrf}

@app.post('/api/logout')
def logout(response:Response,token:Optional[str]=Cookie(default=None,alias='guardian_session')):
    if token:
        c=db();c.execute('DELETE FROM sessions WHERE token_hash=?',(th(token),));c.commit();c.close()
    response.delete_cookie('guardian_session',path='/');return {'ok':True}

@app.get('/api/state')
def state(token:Optional[str]=Cookie(default=None,alias='guardian_session')):
    s=session_row(token);return {'user':{'name':s['name'],'email':s['email'],'csrf':s['csrf']},'state':state_payload(s['user_id'])}

@app.post('/api/connection/setup')
def setup(p:Setup,token:Optional[str]=Cookie(default=None,alias='guardian_session'),x_csrf:Optional[str]=Header(default=None,alias='X-CSRF-Token')):
    s=session_row(token);csrf_ok(s,x_csrf)
    if p.inbound_id==p.outbound_id:raise HTTPException(400,'Choose two different flights.')
    if not flight_by_id(p.inbound_id) or not flight_by_id(p.outbound_id):raise HTTPException(404,'Flight not found.')
    if p.passenger_zone not in ZONES:raise HTTPException(400,'Unknown airport zone.')
    scenario={'delay':0,'gate_change':None,'baggage_delay':0,'crowd':50}
    c=db();c.execute('INSERT INTO connection_sessions(user_id,inbound_id,outbound_id,zone,bags,immigration,scenario,created_at) VALUES(?,?,?,?,?,?,?,?)',(s['user_id'],p.inbound_id,p.outbound_id,p.passenger_zone,p.bags,int(p.immigration),json.dumps(scenario),int(time.time())));c.commit();c.close()
    return {'ok':True,'state':state_payload(s['user_id'])}

@app.post('/api/position')
def position(p:Position,token:Optional[str]=Cookie(default=None,alias='guardian_session'),x_csrf:Optional[str]=Header(default=None,alias='X-CSRF-Token')):
    s=session_row(token);csrf_ok(s,x_csrf)
    if p.zone not in ZONES:raise HTTPException(400,'Unknown airport zone.')
    c=db();r=c.execute('SELECT id FROM connection_sessions WHERE user_id=? ORDER BY id DESC LIMIT 1',(s['user_id'],)).fetchone()
    if not r:raise HTTPException(400,'Set up a connection first.')
    c.execute('UPDATE connection_sessions SET zone=? WHERE id=?',(p.zone,r['id']));c.commit();c.close();return {'ok':True,'state':state_payload(s['user_id'])}

@app.post('/api/scenario')
def scenario(p:Scenario,token:Optional[str]=Cookie(default=None,alias='guardian_session'),x_csrf:Optional[str]=Header(default=None,alias='X-CSRF-Token')):
    s=session_row(token);csrf_ok(s,x_csrf);c=db();r=c.execute('SELECT * FROM connection_sessions WHERE user_id=? ORDER BY id DESC LIMIT 1',(s['user_id'],)).fetchone()
    if not r: raise HTTPException(400,'Set up a connection first.')
    old=json.loads(r['scenario']); merged={**old,**p.model_dump(exclude_none=True)}
    c.execute('UPDATE connection_sessions SET scenario=? WHERE id=?',(json.dumps(merged),r['id']));c.commit();c.close();return {'ok':True,'state':state_payload(s['user_id'])}

@app.get('/api/flights')
def flights(token:Optional[str]=Cookie(default=None,alias='guardian_session')):
    session_row(token);return flight_data()

@app.get('/api/flights/search')
def flight_search(q:str='',token:Optional[str]=Cookie(default=None,alias='guardian_session')):
    session_row(token)
    return flight_data(q)

@app.get('/api/airspace')
def airspace(token:Optional[str]=Cookie(default=None,alias='guardian_session')):
    session_row(token)
    return open_sky()

@app.websocket('/ws/live')
async def ws_live(ws:WebSocket):
    await ws.accept();CLIENTS.add(ws)
    try:
        while True: await ws.receive_text()
    except WebSocketDisconnect: CLIENTS.discard(ws)
    except Exception: CLIENTS.discard(ws)

@app.get('/')
def home():return FileResponse(FRONT/'index.html')
@app.get('/{path:path}')
def static(path:str):
    p=FRONT/path
    if p.exists() and p.is_file():return FileResponse(p)
    return FileResponse(FRONT/'index.html')
