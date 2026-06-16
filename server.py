import os, json, threading, time, hashlib, uuid, secrets
import asyncio
import requests
from aiohttp import web

BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
MAX_MESSAGES  = 20
MAX_CHARS     = 300
MAX_USERNAME  = 100
SOAPYCORE_VERSION = 5

UPDATE_LOG = [
    {"version":"5.1.0","date":"2026-06-12","notes":"SoCore5.1: Persistent sessions, group admins, kick/promote, bug fixes"},
    {"version":"5.0.0","date":"2026-06-01","notes":"SoCore5: Group chats, Gold theme, chunked media, typing indicators"},
    {"version":"4.0.0","date":"2026-05-01","notes":"SoapyCore 4: Video sending, Artemis theme, 100-char usernames"},
]

# ── Persistence ───────────────────────────────────────────────
USERS_FILE    = os.path.join(BASE_DIR, "users.json")
GROUPS_FILE   = os.path.join(BASE_DIR, "groups.json")
SESSIONS_FILE = os.path.join(BASE_DIR, "sessions.json")

def load_json(path, default):
    if os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            return default
    return default

def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

# users_db:    { username: password_hash }
# groups_db:   { group_id: { id, name, image, password_hash, creator, created_at,
#                            admins:[...], members:[...] } }
# sessions_db: { token: { username, created_at } }
users_db    = load_json(USERS_FILE,    {})
groups_db   = load_json(GROUPS_FILE,   {})
sessions_db = load_json(SESSIONS_FILE, {})

users_lock    = threading.Lock()
groups_lock   = threading.Lock()
sessions_lock = threading.Lock()

SESSION_TTL = 60 * 60 * 24 * 30   # 30 days

def clean_sessions():
    now = time.time()
    with sessions_lock:
        expired = [t for t, s in sessions_db.items() if now - s["created_at"] > SESSION_TTL]
        for t in expired:
            del sessions_db[t]
        if expired:
            save_json(SESSIONS_FILE, sessions_db)

def create_session(username):
    token = secrets.token_hex(32)
    with sessions_lock:
        sessions_db[token] = {"username": username, "created_at": int(time.time())}
        save_json(SESSIONS_FILE, sessions_db)
    return token

def verify_session(token):
    """Returns username or None."""
    if not token:
        return None
    with sessions_lock:
        s = sessions_db.get(token)
    if not s:
        return None
    if time.time() - s["created_at"] > SESSION_TTL:
        with sessions_lock:
            sessions_db.pop(token, None)
            save_json(SESSIONS_FILE, sessions_db)
        return None
    return s["username"]

def invalidate_session(token):
    with sessions_lock:
        sessions_db.pop(token, None)
        save_json(SESSIONS_FILE, sessions_db)

# ── GitHub ABG ────────────────────────────────────────────────
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
                headers={"Authorization":f"token {GH_TOKEN}","Accept":"application/vnd.github.v3+json"},
                timeout=8
            )
            if r.status_code == 200:
                return r.json().get("download_url")
        except Exception:
            pass
    return None

threading.Thread(target=lambda: ABG_CACHE.__setitem__("url", get_abg_url()), daemon=True).start()

# ── Runtime state ─────────────────────────────────────────────
clients       = set()     # all active WebSocket connections
user_map      = {}        # ws -> {"username": str, "room": str}
room_messages = {}        # room_id -> [msg, ...]
typing_state  = {}        # room_id -> {username: timestamp}

TYPING_TIMEOUT = 4

# ── Helpers ───────────────────────────────────────────────────
def get_room_clients(room_id):
    return [ws for ws, info in user_map.items() if info.get("room") == room_id]

def get_online_in_room(room_id):
    return [info["username"] for ws, info in user_map.items()
            if info.get("room") == room_id and info.get("username")]

async def broadcast(room_id, payload, exclude=None):
    dead = []
    for ws in list(get_room_clients(room_id)):
        if ws is exclude:
            continue
        try:
            await ws.send_json(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        clients.discard(ws)
        user_map.pop(ws, None)

async def broadcast_all(payload, exclude=None):
    dead = []
    for ws in list(clients):
        if ws is exclude:
            continue
        try:
            await ws.send_json(payload)
        except Exception:
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

def public_group(g):
    """Return group dict safe to send to clients (no password hash)."""
    return {
        "id":          g["id"],
        "name":        g["name"],
        "image":       g.get("image",""),
        "creator":     g["creator"],
        "admins":      g.get("admins", []),
        "members":     g.get("members", []),
        "created_at":  g["created_at"],
        "has_password": bool(g.get("password_hash",""))
    }

def is_group_admin(group, username):
    """True if user is creator or in admins list."""
    return username == group["creator"] or username in group.get("admins", [])

# ── HTTP: static ──────────────────────────────────────────────
async def index(request):
    return web.FileResponse(os.path.join(BASE_DIR, "index.html"))

# ── HTTP: Auth ────────────────────────────────────────────────
async def auth_signup(request):
    body     = await request.json()
    username = body.get("username","").strip()
    password = body.get("password","")
    if not username or not password:
        return web.json_response({"ok":False,"error":"Fill all fields"})
    if len(username) < 2:
        return web.json_response({"ok":False,"error":"Username too short"})
    if len(username) > MAX_USERNAME:
        return web.json_response({"ok":False,"error":f"Username too long (max {MAX_USERNAME})"})
    if len(password) < 4:
        return web.json_response({"ok":False,"error":"Password too short (min 4)"})
    with users_lock:
        if username in users_db:
            return web.json_response({"ok":False,"error":"Username taken"})
        users_db[username] = hash_pw(password)
        save_json(USERS_FILE, users_db)
    token = create_session(username)
    return web.json_response({"ok":True,"username":username,"token":token})

async def auth_login(request):
    body     = await request.json()
    username = body.get("username","").strip()
    password = body.get("password","")
    with users_lock:
        stored = users_db.get(username)
    if not stored or stored != hash_pw(password):
        return web.json_response({"ok":False,"error":"Invalid username or password"})
    token = create_session(username)
    return web.json_response({"ok":True,"username":username,"token":token})

async def auth_token(request):
    """Verify a saved session token and return username."""
    body  = await request.json()
    token = body.get("token","")
    uname = verify_session(token)
    if not uname:
        return web.json_response({"ok":False,"error":"Session expired"})
    return web.json_response({"ok":True,"username":uname})

async def auth_signout(request):
    body  = await request.json()
    token = body.get("token","")
    invalidate_session(token)
    return web.json_response({"ok":True})

async def change_password(request):
    body     = await request.json()
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
    body     = await request.json()
    old_name = body.get("old_username","").strip()
    new_name = body.get("new_username","").strip()
    password = body.get("password","")
    if not old_name or not new_name or not password:
        return web.json_response({"ok":False,"error":"Fill all fields"})
    if len(new_name) < 2:
        return web.json_response({"ok":False,"error":"Username too short"})
    if len(new_name) > MAX_USERNAME:
        return web.json_response({"ok":False,"error":f"Username too long (max {MAX_USERNAME})"})
    with users_lock:
        stored = users_db.get(old_name)
        if not stored or stored != hash_pw(password):
            return web.json_response({"ok":False,"error":"Password incorrect"})
        if new_name in users_db and new_name != old_name:
            return web.json_response({"ok":False,"error":"Username already taken"})
        pw_hash = users_db.pop(old_name)
        users_db[new_name] = pw_hash
        save_json(USERS_FILE, users_db)
    # Update all sessions for this user
    with sessions_lock:
        for s in sessions_db.values():
            if s["username"] == old_name:
                s["username"] = new_name
        save_json(SESSIONS_FILE, sessions_db)
    # Update creator/admin/member records in groups
    with groups_lock:
        changed = False
        for g in groups_db.values():
            if g["creator"] == old_name:
                g["creator"] = new_name; changed = True
            if old_name in g.get("admins",[]):
                g["admins"] = [new_name if u==old_name else u for u in g["admins"]]; changed = True
            if old_name in g.get("members",[]):
                g["members"] = [new_name if u==old_name else u for u in g["members"]]; changed = True
        if changed:
            save_json(GROUPS_FILE, groups_db)
    return web.json_response({"ok":True,"username":new_name})

# ── HTTP: Groups ──────────────────────────────────────────────
async def list_groups(request):
    with groups_lock:
        groups = list(groups_db.values())
    return web.json_response({"ok":True,"groups":[public_group(g) for g in groups]})

async def create_group(request):
    body     = await request.json()
    name     = body.get("name","").strip()
    password = body.get("password","")
    image    = body.get("image","")
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
        "admins":        [],
        "members":       [creator],
        "created_at":    int(time.time()),
    }
    with groups_lock:
        groups_db[group_id] = group
        save_json(GROUPS_FILE, groups_db)
    await broadcast_all({"type":"group_created","group":public_group(group)})
    return web.json_response({"ok":True,"group_id":group_id})

async def join_group(request):
    body     = await request.json()
    group_id = body.get("group_id","")
    password = body.get("password","")
    username = body.get("username","").strip()
    with groups_lock:
        group = groups_db.get(group_id)
    if not group:
        return web.json_response({"ok":False,"error":"Group not found"})
    if group.get("password_hash") and group["password_hash"] != hash_pw(password):
        return web.json_response({"ok":False,"error":"Wrong password"})
    # Add to members if not already
    with groups_lock:
        if username and username not in group.get("members",[]):
            group.setdefault("members",[]).append(username)
            save_json(GROUPS_FILE, groups_db)
    await broadcast_all({"type":"group_updated","group":public_group(group)})
    return web.json_response({"ok":True,"group":public_group(group)})

async def update_group(request):
    body     = await request.json()
    group_id = body.get("group_id","")
    username = body.get("username","").strip()
    with groups_lock:
        group = groups_db.get(group_id)
    if not group:
        return web.json_response({"ok":False,"error":"Group not found"})
    if not is_group_admin(group, username):
        return web.json_response({"ok":False,"error":"Only admins can edit group settings"})
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
    await broadcast_all({"type":"group_updated","group":public_group(group)})
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

async def promote_member(request):
    """Creator promotes a member to admin."""
    body     = await request.json()
    group_id = body.get("group_id","")
    actor    = body.get("username","").strip()     # who is doing the action
    target   = body.get("target","").strip()       # who to promote
    with groups_lock:
        group = groups_db.get(group_id)
    if not group:
        return web.json_response({"ok":False,"error":"Group not found"})
    if group["creator"] != actor:
        return web.json_response({"ok":False,"error":"Only the creator can promote members"})
    if target == group["creator"]:
        return web.json_response({"ok":False,"error":"Creator is already the owner"})
    admins = group.setdefault("admins", [])
    if target not in admins:
        admins.append(target)
    # Make sure they're also a member
    group.setdefault("members",[])
    if target not in group["members"]:
        group["members"].append(target)
    with groups_lock:
        save_json(GROUPS_FILE, groups_db)
    pg = public_group(group)
    await broadcast_all({"type":"group_updated","group":pg})
    # Notify the group room
    await broadcast(group_id, {"type":"system_msg","room":group_id,
        "content":f"{target} was promoted to admin by {actor}"})
    return web.json_response({"ok":True,"group":pg})

async def demote_member(request):
    """Creator demotes an admin back to member."""
    body     = await request.json()
    group_id = body.get("group_id","")
    actor    = body.get("username","").strip()
    target   = body.get("target","").strip()
    with groups_lock:
        group = groups_db.get(group_id)
    if not group:
        return web.json_response({"ok":False,"error":"Group not found"})
    if group["creator"] != actor:
        return web.json_response({"ok":False,"error":"Only the creator can demote admins"})
    admins = group.get("admins",[])
    if target in admins:
        admins.remove(target)
    with groups_lock:
        save_json(GROUPS_FILE, groups_db)
    pg = public_group(group)
    await broadcast_all({"type":"group_updated","group":pg})
    await broadcast(group_id, {"type":"system_msg","room":group_id,
        "content":f"{target} was demoted to member by {actor}"})
    return web.json_response({"ok":True,"group":pg})

async def kick_member(request):
    """Creator or admin kicks a member."""
    body     = await request.json()
    group_id = body.get("group_id","")
    actor    = body.get("username","").strip()
    target   = body.get("target","").strip()
    with groups_lock:
        group = groups_db.get(group_id)
    if not group:
        return web.json_response({"ok":False,"error":"Group not found"})
    if not is_group_admin(group, actor):
        return web.json_response({"ok":False,"error":"Only admins can kick members"})
    if target == group["creator"]:
        return web.json_response({"ok":False,"error":"Cannot kick the group creator"})
    # Admins can't kick other admins (only creator can)
    if target in group.get("admins",[]) and actor != group["creator"]:
        return web.json_response({"ok":False,"error":"Only the creator can kick admins"})
    # Remove from members and admins
    members = group.get("members",[])
    admins  = group.get("admins",[])
    if target in members:  members.remove(target)
    if target in admins:   admins.remove(target)
    with groups_lock:
        save_json(GROUPS_FILE, groups_db)
    pg = public_group(group)
    await broadcast_all({"type":"group_updated","group":pg})
    # Tell the kicked user's WS to leave the room
    for ws, info in list(user_map.items()):
        if info.get("username") == target and info.get("room") == group_id:
            try:
                await ws.send_json({"type":"kicked","group_id":group_id,"by":actor})
            except Exception:
                pass
    await broadcast(group_id, {"type":"system_msg","room":group_id,
        "content":f"{target} was kicked by {actor}"})
    return web.json_response({"ok":True,"group":pg})

# ── HTTP: Chunked media upload ─────────────────────────────────
pending_uploads = {}
uploads_lock    = threading.Lock()

async def upload_chunk(request):
    body      = await request.json()
    upload_id = body.get("upload_id","")
    chunk_idx = int(body.get("chunk_idx", 0))
    total     = int(body.get("total_chunks", 1))
    data      = body.get("data","")
    media_type= body.get("media_type","image")
    room_id   = body.get("room_id","public")
    sender    = body.get("sender","?")
    mime      = body.get("mime","image/jpeg")

    with uploads_lock:
        if upload_id not in pending_uploads:
            pending_uploads[upload_id] = {
                "chunks":{}, "total":total, "type":media_type,
                "room":room_id, "sender":sender, "mime":mime
            }
        pending_uploads[upload_id]["chunks"][chunk_idx] = data
        up = pending_uploads[upload_id]
        if len(up["chunks"]) >= up["total"]:
            ordered   = "".join(up["chunks"][i] for i in range(up["total"]))
            full_data = f"data:{mime};base64,{ordered}"
            payload   = {"type":up["type"],"name":up["sender"],"content":full_data,"room":up["room"]}
            store_message(up["room"], payload)
            del pending_uploads[upload_id]
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
            r = requests.get(f"https://api.github.com/repos/{GH_REPO}/contents/{name}",
                headers={"Authorization":f"token {GH_TOKEN}","Accept":"application/vnd.github.v3+json"},timeout=6)
            sounds[key] = r.json().get("download_url") if r.status_code==200 else None
        except Exception:
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
    uname = verify_session(data.get("token",""))
    if uname:
        return web.json_response({"ok":True,"username":uname})
    return web.json_response({"ok":False,"error":"Invalid session"}, status=401)

# ── WebSocket ─────────────────────────────────────────────────
async def ws_handler(request):
    ws = web.WebSocketResponse(max_msg_size=1_000_000)
    await ws.prepare(request)
    clients.add(ws)
    # Each connection gets its own info dict — username starts None
    user_info = {"username": None, "room": "public"}
    user_map[ws] = user_info

    try:
        async for msg in ws:
            if msg.type != web.WSMsgType.TEXT:
                continue
            data = json.loads(msg.data)
            t    = data.get("type","")
            # Always read username fresh from user_info (not a stale local variable)
            username = user_info["username"]

            # ── Join ──────────────────────────────────────────
            if t == "join":
                uname = data.get("name","Anonymous")
                user_info["username"] = uname
                user_info["room"]     = "public"
                username = uname  # update local ref too

                await ws.send_json({"type":"history","messages":room_messages.get("public",[]),"room":"public"})

                with groups_lock:
                    grps = list(groups_db.values())
                await ws.send_json({"type":"groups_list","groups":[public_group(g) for g in grps]})

                # Announce to public room (exclude self so self doesn't see "X joined")
                await broadcast("public",{"type":"user_joined","name":uname,"room":"public"},exclude=ws)
                # Send online list (self is already in user_map so get_online_in_room includes us)
                online = get_online_in_room("public")
                await ws.send_json({"type":"online_list","room":"public","users":online})
                await broadcast("public",{"type":"online_list","room":"public","users":online},exclude=ws)

            # ── Switch room ───────────────────────────────────
            elif t == "switch_room":
                if username is None:
                    continue
                old_room = user_info["room"]
                new_room = data.get("room_id","public")
                if old_room == new_room:
                    continue

                # Leave old room — broadcast before updating room field
                await broadcast(old_room,{"type":"user_left","name":username,"room":old_room},exclude=ws)
                old_online = get_online_in_room(old_room)
                # Remove self from old count then broadcast
                await broadcast(old_room,{"type":"online_list","room":old_room,"users":old_online})

                user_info["room"] = new_room

                await ws.send_json({"type":"history","messages":room_messages.get(new_room,[]),"room":new_room})
                await broadcast(new_room,{"type":"user_joined","name":username,"room":new_room},exclude=ws)
                new_online = get_online_in_room(new_room)
                await ws.send_json({"type":"online_list","room":new_room,"users":new_online})
                await broadcast(new_room,{"type":"online_list","room":new_room,"users":new_online},exclude=ws)

            # ── Message ───────────────────────────────────────
            elif t == "message":
                if username is None:
                    continue
                room    = user_info["room"]
                content = data.get("content","")
                if len(content) > MAX_CHARS:
                    await ws.send_json({"type":"error","content":f"Max {MAX_CHARS} chars"})
                    continue
                if room in typing_state:
                    typing_state[room].pop(username, None)
                payload = {"type":"message","name":username,"content":content,"room":room}
                store_message(room, payload)
                await broadcast(room, payload)
                await ws.send_json(payload)

            # ── Typing ────────────────────────────────────────
            elif t == "typing":
                if username is None:
                    continue
                room = user_info["room"]
                typing_state.setdefault(room,{})[username] = time.time()
                typers = [u for u, ts in typing_state[room].items()
                          if time.time()-ts < TYPING_TIMEOUT]
                await broadcast(room,{"type":"typing","room":room,"users":typers},exclude=ws)

            elif t == "stop_typing":
                if username is None:
                    continue
                room = user_info["room"]
                typing_state.get(room,{}).pop(username, None)
                typers = [u for u, ts in typing_state.get(room,{}).items()
                          if time.time()-ts < TYPING_TIMEOUT]
                await broadcast(room,{"type":"typing","room":room,"users":typers})

            # ── Audio ─────────────────────────────────────────
            elif t == "audio":
                if username is None:
                    continue
                room    = user_info["room"]
                content = data.get("content","")
                payload = {"type":"audio","name":username,"content":content,"room":room}
                store_message(room, payload)
                await broadcast(room, payload)
                await ws.send_json(payload)

    finally:
        # Always use user_info here — local `username` may be stale
        uname = user_info.get("username")
        room  = user_info.get("room","public")

        clients.discard(ws)
        user_map.pop(ws, None)

        if uname:
            typing_state.get(room,{}).pop(uname, None)
            await broadcast(room,{"type":"user_left","name":uname,"room":room})
            online = get_online_in_room(room)
            await broadcast(room,{"type":"online_list","room":room,"users":online})

    return ws

# ── Typing cleanup ────────────────────────────────────────────
async def typing_cleanup(_app):
    while True:
        now = time.time()
        for room_id in list(typing_state.keys()):
            expired = [u for u, ts in list(typing_state[room_id].items())
                       if now-ts > TYPING_TIMEOUT]
            for u in expired:
                typing_state[room_id].pop(u, None)
        await asyncio.sleep(2)

async def on_startup(_app):
    asyncio.ensure_future(typing_cleanup(_app))
    clean_sessions()

# ── CORS middleware ───────────────────────────────────────────
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

# ── App ───────────────────────────────────────────────────────
app = web.Application(
    client_max_size=30*1024*1024,
    middlewares=[cors_mw]
)
app.on_startup.append(on_startup)

app.router.add_get("/",                            index)
app.router.add_get("/ws",                          ws_handler)
app.router.add_post("/api/signup",                 auth_signup)
app.router.add_post("/api/login",                  auth_login)
app.router.add_post("/api/auth/token",             auth_token)
app.router.add_post("/api/auth/signout",           auth_signout)
app.router.add_post("/api/change_password",        change_password)
app.router.add_post("/api/change_username",        change_username)
app.router.add_get("/api/sounds",                  get_sounds)
app.router.add_get("/api/abg",                     get_abg)
app.router.add_get("/api/updates",                 get_update_log)
app.router.add_get("/api/theme",                   get_theme_info)
app.router.add_post("/api/verify",                 verify_user)
app.router.add_get("/api/groups",                  list_groups)
app.router.add_post("/api/groups/create",          create_group)
app.router.add_post("/api/groups/join",            join_group)
app.router.add_post("/api/groups/update",          update_group)
app.router.add_post("/api/groups/delete",          delete_group)
app.router.add_post("/api/groups/promote",         promote_member)
app.router.add_post("/api/groups/demote",          demote_member)
app.router.add_post("/api/groups/kick",            kick_member)
app.router.add_post("/api/upload/chunk",           upload_chunk)

# ── Keep-alive ────────────────────────────────────────────────
SELF_URL = os.environ.get("SELF_URL","")
def keep_alive():
    while True:
        try:
            if SELF_URL: requests.get(SELF_URL, timeout=10)
        except Exception: pass
        time.sleep(360)
threading.Thread(target=keep_alive, daemon=True).start()

# ── Run ───────────────────────────────────────────────────────
port = int(os.environ.get("PORT", 8000))
print(f"[SoapyAero] Starting on port {port}", flush=True)
web.run_app(app, host="0.0.0.0", port=port, print=print)
