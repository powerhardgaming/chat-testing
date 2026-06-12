import os, json, threading, time, hashlib, uuid
import requests
from aiohttp import web

BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
MAX_MESSAGES  = 20
MAX_CHARS     = 300
MAX_USERNAME  = 100

SOAPYCORE_VERSION = 5

UPDATE_LOG = [
    {"version": "5.0.0", "date": "2026-06-01", "notes": "SoCore5: Group chats, Gold theme, chunked media, typing indicators, online presence"},
    {"version": "4.0.0", "date": "2026-05-01", "notes": "SoapyCore 4: Video sending, Artemis theme, 100-char usernames, SShell"},
    {"version": "3.1.0", "date": "2026-04-12", "notes": "SoapyAero (SCore3): Screen sharing, Frutiger Aero glass theme"},
]

# ── Persistence files ─────────────────────────────────────────
USERS_FILE  = os.path.join(BASE_DIR, "users.json")
GROUPS_FILE = os.path.join(BASE_DIR, "groups.json")

def load_json(path, default):
    if os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except:
            return default
    return default

def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)  # atomic write

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

users_db  = load_json(USERS_FILE,  {})
groups_db = load_json(GROUPS_FILE, {})   # id -> {id, name, image, password_hash, creator, created_at}
users_lock  = threading.Lock()
groups_lock = threading.Lock()

# ── Runtime state (not persisted — only messages/presence) ────
clients       = set()           # all ws connections
user_map      = {}              # ws -> {username, room}
room_messages = {}              # room_id -> [msg, ...]   (public = "public")
typing_state  = {}              # room_id -> {username: timestamp}

# ── GitHub ABG sync ───────────────────────────────────────────
GH_TOKEN  = os.environ.get("GH_TOKEN", "")
GH_REPO   = os.environ.get("GH_REPO", "")
ABG_CACHE = {"url": None}

def get_abg_url():
    if not GH_TOKEN or not GH_REPO:
        return None
    for ext in ["png","jpg","jpeg","gif","webp"]:
        try:
            r = requests.get(
                f"https://api.github.com/repos/{GH_REPO}/contents/ABG.{ext}",
                headers={"Authorization": f"token {GH_TOKEN}",
                         "Accept": "application/vnd.github.v3+json"},
                timeout=8
            )
            if r.status_code == 200:
                return r.json().get("download_url")
        except:
            pass
    return None

threading.Thread(target=lambda: ABG_CACHE.__setitem__("url", get_abg_url()), daemon=True).start()

# ── Helpers ───────────────────────────────────────────────────
def get_room_clients(room_id):
    return [ws for ws, info in user_map.items() if info.get("room") == room_id]

def get_online_in_room(room_id):
    return [info["username"] for ws, info in user_map.items() if info.get("room") == room_id]

async def broadcast(room_id, payload, exclude=None):
    dead = []
    for ws in get_room_clients(room_id):
        if ws is exclude:
            continue
        try:
            await ws.send_json(payload)
        except:
            dead.append(ws)
    for ws in dead:
        clients.discard(ws)
        user_map.pop(ws, None)

async def broadcast_all(payload, exclude=None):
    dead = []
    for ws in set(clients):
        if ws is exclude:
            continue
        try:
            await ws.send_json(payload)
        except:
            dead.append(ws)
    for ws in dead:
        clients.discard(ws)
        user_map.pop(ws, None)

def store_message(room_id, payload):
    if room_id not in room_messages:
        room_messages[room_id] = []
    room_messages[room_id].append(payload)
    while len(room_messages[room_id]) > MAX_MESSAGES:
        room_messages[room_id].pop(0)

# ── HTTP: Auth ────────────────────────────────────────────────
async def index(request):
    return web.FileResponse(os.path.join(BASE_DIR, "index.html"))

async def auth_signup(request):
    body = await request.json()
    username = body.get("username","").strip()
    password = body.get("password","")
    if not username or not password:
        return web.json_response({"ok":False,"error":"Fill all fields"})
    if len(username) < 2:
        return web.json_response({"ok":False,"error":"Username too short"})
    if len(username) > MAX_USERNAME:
        return web.json_response({"ok":False,"error":f"Username too long (max {MAX_USERNAME} chars)"})
    if len(password) < 4:
        return web.json_response({"ok":False,"error":"Password too short (min 4)"})
    with users_lock:
        if username in users_db:
            return web.json_response({"ok":False,"error":"Username taken"})
        users_db[username] = hash_pw(password)
        save_json(USERS_FILE, users_db)
    return web.json_response({"ok":True,"username":username})

async def auth_login(request):
    body = await request.json()
    username = body.get("username","").strip()
    password = body.get("password","")
    with users_lock:
        stored = users_db.get(username)
    if not stored or stored != hash_pw(password):
        return web.json_response({"ok":False,"error":"Invalid username or password"})
    return web.json_response({"ok":True,"username":username})

async def change_password(request):
    body = await request.json()
    username = body.get("username","").strip()
    old_pw   = body.get("old_password","")
    new_pw   = body.get("new_password","")
    if not username or not old_pw or not new_pw:
        return web.json_response({"ok":False,"error":"Fill all fields"})
    if len(new_pw) < 4:
        return web.json_response({"ok":False,"error":"Password too short (min 4)"})
    with users_lock:
        stored = users_db.get(username)
        if not stored or stored != hash_pw(old_pw):
            return web.json_response({"ok":False,"error":"Current password incorrect"})
        users_db[username] = hash_pw(new_pw)
        save_json(USERS_FILE, users_db)
    return web.json_response({"ok":True})

async def change_username(request):
    body = await request.json()
    old_name = body.get("old_username","").strip()
    new_name = body.get("new_username","").strip()
    password = body.get("password","")
    if not old_name or not new_name or not password:
        return web.json_response({"ok":False,"error":"Fill all fields"})
    if len(new_name) < 2:
        return web.json_response({"ok":False,"error":"Username too short"})
    if len(new_name) > MAX_USERNAME:
        return web.json_response({"ok":False,"error":f"Username too long (max {MAX_USERNAME} chars)"})
    with users_lock:
        stored = users_db.get(old_name)
        if not stored or stored != hash_pw(password):
            return web.json_response({"ok":False,"error":"Password incorrect"})
        if new_name in users_db and new_name != old_name:
            return web.json_response({"ok":False,"error":"Username already taken"})
        pw_hash = users_db.pop(old_name)
        users_db[new_name] = pw_hash
        save_json(USERS_FILE, users_db)
    return web.json_response({"ok":True,"username":new_name})

# ── HTTP: Groups ──────────────────────────────────────────────
async def list_groups(request):
    with groups_lock:
        groups = list(groups_db.values())
    # Strip password hash from public listing
    public = [{
        "id":         g["id"],
        "name":       g["name"],
        "image":      g.get("image",""),
        "creator":    g["creator"],
        "created_at": g["created_at"],
        "member_count": g.get("member_count", 0),
        "has_password": bool(g.get("password_hash",""))
    } for g in groups]
    return web.json_response({"ok":True,"groups":public})

async def create_group(request):
    body = await request.json()
    name     = body.get("name","").strip()
    password = body.get("password","")
    image    = body.get("image","")     # base64 data URL or ""
    creator  = body.get("creator","").strip()
    if not name or not creator:
        return web.json_response({"ok":False,"error":"Name and creator required"})
    if len(name) > 60:
        return web.json_response({"ok":False,"error":"Name too long"})
    group_id = str(uuid.uuid4())[:8]
    group = {
        "id":            group_id,
        "name":          name,
        "image":         image,
        "password_hash": hash_pw(password) if password else "",
        "creator":       creator,
        "created_at":    int(time.time()),
        "member_count":  0
    }
    with groups_lock:
        groups_db[group_id] = group
        save_json(GROUPS_FILE, groups_db)
    # Broadcast new group to all clients
    public_group = {k: v for k, v in group.items() if k != "password_hash"}
    public_group["has_password"] = bool(group["password_hash"])
    await broadcast_all({"type": "group_created", "group": public_group})
    return web.json_response({"ok":True,"group_id":group_id})

async def join_group(request):
    body     = await request.json()
    group_id = body.get("group_id","")
    password = body.get("password","")
    with groups_lock:
        group = groups_db.get(group_id)
    if not group:
        return web.json_response({"ok":False,"error":"Group not found"})
    if group.get("password_hash") and group["password_hash"] != hash_pw(password):
        return web.json_response({"ok":False,"error":"Wrong password"})
    return web.json_response({"ok":True,"group": {
        "id":      group["id"],
        "name":    group["name"],
        "image":   group.get("image",""),
        "creator": group["creator"]
    }})

async def update_group(request):
    body     = await request.json()
    group_id = body.get("group_id","")
    username = body.get("username","").strip()
    with groups_lock:
        group = groups_db.get(group_id)
    if not group:
        return web.json_response({"ok":False,"error":"Group not found"})
    if group["creator"] != username:
        return web.json_response({"ok":False,"error":"Only the group creator can edit settings"})
    # Update allowed fields
    if "name" in body:
        n = body["name"].strip()
        if not n or len(n) > 60:
            return web.json_response({"ok":False,"error":"Invalid name"})
        group["name"] = n
    if "password" in body:
        group["password_hash"] = hash_pw(body["password"]) if body["password"] else ""
    if "image" in body:
        group["image"] = body["image"]
    with groups_lock:
        groups_db[group_id] = group
        save_json(GROUPS_FILE, groups_db)
    public_group = {k: v for k, v in group.items() if k != "password_hash"}
    public_group["has_password"] = bool(group.get("password_hash",""))
    await broadcast_all({"type":"group_updated","group":public_group})
    return web.json_response({"ok":True})

async def delete_group(request):
    body     = await request.json()
    group_id = body.get("group_id","")
    username = body.get("username","").strip()
    with groups_lock:
        group = groups_db.get(group_id)
    if not group:
        return web.json_response({"ok":False,"error":"Group not found"})
    if group["creator"] != username:
        return web.json_response({"ok":False,"error":"Only the creator can delete this group"})
    with groups_lock:
        del groups_db[group_id]
        save_json(GROUPS_FILE, groups_db)
    room_messages.pop(group_id, None)
    await broadcast_all({"type":"group_deleted","group_id":group_id})
    return web.json_response({"ok":True})

# ── HTTP: Media ───────────────────────────────────────────────
# Chunked upload: client POSTs chunks, server assembles, then broadcasts
pending_uploads = {}   # upload_id -> {chunks: {}, total: n, type, room, sender}
uploads_lock    = threading.Lock()

async def upload_chunk(request):
    body      = await request.json()
    upload_id = body.get("upload_id","")
    chunk_idx = int(body.get("chunk_idx", 0))
    total     = int(body.get("total_chunks", 1))
    data      = body.get("data","")      # base64 chunk
    media_type= body.get("media_type","image")
    room_id   = body.get("room_id","public")
    sender    = body.get("sender","?")
    mime      = body.get("mime","image/jpeg")

    with uploads_lock:
        if upload_id not in pending_uploads:
            pending_uploads[upload_id] = {
                "chunks": {}, "total": total,
                "type": media_type, "room": room_id,
                "sender": sender, "mime": mime
            }
        pending_uploads[upload_id]["chunks"][chunk_idx] = data

        up = pending_uploads[upload_id]
        if len(up["chunks"]) >= up["total"]:
            # Assemble
            ordered = "".join(up["chunks"][i] for i in range(up["total"]))
            full_data = f"data:{mime};base64,{ordered}"
            payload = {
                "type":    up["type"],
                "name":    up["sender"],
                "content": full_data,
                "room":    up["room"]
            }
            store_message(up["room"], payload)
            del pending_uploads[upload_id]
            # Broadcast async (can't await here, schedule it)
            import asyncio
            asyncio.ensure_future(broadcast(up["room"], payload))
            return web.json_response({"ok":True,"complete":True})

    return web.json_response({"ok":True,"complete":False})

# ── HTTP: Misc ────────────────────────────────────────────────
async def get_sounds(request):
    if not GH_TOKEN or not GH_REPO:
        return web.json_response({"ts":None,"send":None,"click":None})
    sounds = {}
    for name, key in [("TS.mp3","ts"),("Send.mp3","send"),("Click.mp3","click")]:
        try:
            r = requests.get(
                f"https://api.github.com/repos/{GH_REPO}/contents/{name}",
                headers={"Authorization":f"token {GH_TOKEN}","Accept":"application/vnd.github.v3+json"},
                timeout=6
            )
            sounds[key] = r.json().get("download_url") if r.status_code == 200 else None
        except:
            sounds[key] = None
    return web.json_response(sounds)

async def get_abg(request):
    return web.json_response({"url": ABG_CACHE.get("url")})

async def get_update_log(request):
    return web.json_response({"updates": UPDATE_LOG})

async def get_theme_info(request):
    return web.json_response({"accent":"#c9a227","bg":"#0b0c0f","text":"#fff8e1","version":SOAPYCORE_VERSION})

async def verify_user(request):
    data = await request.json()
    username = data.get("username","").strip()
    password = data.get("password","")
    with users_lock:
        stored = users_db.get(username)
    if stored and stored == hash_pw(password):
        return web.json_response({"ok":True,"username":username})
    return web.json_response({"ok":False,"error":"Invalid credentials"}, status=401)

# ── WebSocket ─────────────────────────────────────────────────
TYPING_TIMEOUT = 4   # seconds before typing indicator expires

async def ws_handler(request):
    ws = web.WebSocketResponse(max_msg_size=1_000_000)  # 1MB per WS message (media uses HTTP chunks)
    await ws.prepare(request)
    clients.add(ws)
    user_info = {"username": None, "room": "public"}
    user_map[ws] = user_info

    try:
        async for msg in ws:
            if msg.type != web.WSMsgType.TEXT:
                continue
            data = json.loads(msg.data)
            t    = data.get("type","")
            username = user_info.get("username","?")

            # ── Join ──────────────────────────────────────────
            if t == "join":
                uname = data.get("name","Anonymous")
                user_info["username"] = uname
                user_info["room"]     = "public"
                # Send history for public room
                await ws.send_json({"type":"history","messages":room_messages.get("public",[])})
                # Send current group list
                with groups_lock:
                    groups = list(groups_db.values())
                public_groups = [{
                    "id":       g["id"],"name":g["name"],"image":g.get("image",""),
                    "creator":  g["creator"],"created_at":g["created_at"],
                    "has_password": bool(g.get("password_hash",""))
                } for g in groups]
                await ws.send_json({"type":"groups_list","groups":public_groups})
                # Announce presence in public
                await broadcast("public", {"type":"user_joined","name":uname,"room":"public"}, exclude=ws)
                await ws.send_json({"type":"online_list","room":"public","users":get_online_in_room("public")})

            # ── Switch room ───────────────────────────────────
            elif t == "switch_room":
                old_room = user_info["room"]
                new_room = data.get("room_id","public")
                # Leave old room
                await broadcast(old_room, {"type":"user_left","name":username,"room":old_room}, exclude=ws)
                # Update room
                user_info["room"] = new_room
                # Send history
                await ws.send_json({"type":"history","messages":room_messages.get(new_room,[]),"room":new_room})
                # Announce presence
                await broadcast(new_room, {"type":"user_joined","name":username,"room":new_room}, exclude=ws)
                # Send online list for new room
                await ws.send_json({"type":"online_list","room":new_room,"users":get_online_in_room(new_room)})
                # Broadcast updated online list to everyone in new room
                await broadcast(new_room, {"type":"online_list","room":new_room,"users":get_online_in_room(new_room)})

            # ── Message ───────────────────────────────────────
            elif t == "message":
                room   = user_info["room"]
                content= data.get("content","")
                if len(content) > MAX_CHARS:
                    await ws.send_json({"type":"error","content":f"Max {MAX_CHARS} chars"})
                    continue
                # Clear typing
                if room in typing_state:
                    typing_state[room].pop(username, None)
                payload = {"type":"message","name":username,"content":content,"room":room}
                store_message(room, payload)
                await broadcast(room, payload)
                await ws.send_json(payload)  # echo back to sender

            # ── Typing ────────────────────────────────────────
            elif t == "typing":
                room = user_info["room"]
                if room not in typing_state:
                    typing_state[room] = {}
                typing_state[room][username] = time.time()
                typers = [u for u, ts in typing_state[room].items()
                          if time.time() - ts < TYPING_TIMEOUT and u != username]
                # Broadcast to room (excluding self)
                await broadcast(room, {"type":"typing","room":room,"users":typers + [username]}, exclude=ws)

            # ── Stop typing ───────────────────────────────────
            elif t == "stop_typing":
                room = user_info["room"]
                if room in typing_state:
                    typing_state[room].pop(username, None)
                typers = [u for u, ts in typing_state.get(room,{}).items()
                          if time.time() - ts < TYPING_TIMEOUT]
                await broadcast(room, {"type":"typing","room":room,"users":typers})

            # ── Audio (small, sent inline) ────────────────────
            elif t == "audio":
                room    = user_info["room"]
                content = data.get("content","")
                payload = {"type":"audio","name":username,"content":content,"room":room}
                store_message(room, payload)
                await broadcast(room, payload)
                await ws.send_json(payload)

    finally:
        room = user_info.get("room","public")
        username = user_info.get("username","?")
        clients.discard(ws)
        user_map.pop(ws, None)
        # Clean typing
        if room in typing_state:
            typing_state[room].pop(username, None)
        # Notify room
        await broadcast(room, {"type":"user_left","name":username,"room":room})
        await broadcast(room, {"type":"online_list","room":room,"users":get_online_in_room(room)})
    return ws

# ── Typing cleanup task ───────────────────────────────────────
async def typing_cleanup(app):
    import asyncio
    while True:
        now = time.time()
        for room_id in list(typing_state.keys()):
            expired = [u for u, ts in typing_state[room_id].items() if now - ts > TYPING_TIMEOUT]
            for u in expired:
                del typing_state[room_id][u]
        await asyncio.sleep(2)

# ── App ───────────────────────────────────────────────────────
app = web.Application(client_max_size=30*1024*1024)

app.router.add_get("/",                        index)
app.router.add_get("/ws",                      ws_handler)
app.router.add_post("/api/signup",             auth_signup)
app.router.add_post("/api/login",              auth_login)
app.router.add_post("/api/change_password",    change_password)
app.router.add_post("/api/change_username",    change_username)
app.router.add_get("/api/sounds",              get_sounds)
app.router.add_get("/api/abg",                 get_abg)
app.router.add_get("/api/updates",             get_update_log)
app.router.add_get("/api/theme",               get_theme_info)
app.router.add_post("/api/verify",             verify_user)
# Groups
app.router.add_get("/api/groups",              list_groups)
app.router.add_post("/api/groups/create",      create_group)
app.router.add_post("/api/groups/join",        join_group)
app.router.add_post("/api/groups/update",      update_group)
app.router.add_post("/api/groups/delete",      delete_group)
# Chunked media upload
app.router.add_post("/api/upload/chunk",       upload_chunk)

@web.middleware
async def cors_mw(request, handler):
    if request.method == "OPTIONS":
        return web.Response(headers={
            "Access-Control-Allow-Origin":  "*",
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
        })
    r = await handler(request)
    r.headers["Access-Control-Allow-Origin"] = "*"
    return r

app.middlewares.append(cors_mw)
app.on_startup.append(lambda a: __import__('asyncio').ensure_future(typing_cleanup(a)))

SELF_URL = os.environ.get("SELF_URL","")
def keep_alive():
    while True:
        try:
            if SELF_URL: requests.get(SELF_URL, timeout=10)
        except: pass
        time.sleep(360)
threading.Thread(target=keep_alive, daemon=True).start()

port = int(os.environ.get("PORT", 8000))
web.run_app(app, host="0.0.0.0", port=port)