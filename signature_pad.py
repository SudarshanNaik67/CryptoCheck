"""
CryptoCheck - Handwritten Signature + Fingerprint module
=========================================================

* Starts a tiny local web server that serves a signature pad.
  - Laptop : open it in a browser and sign with the mouse / touchpad.
  - Phone  : open the same link and sign with your finger.
* Optional fingerprint check using WebAuthn (the phone's own fingerprint
  sensor, e.g. Samsung). The fingerprint itself NEVER leaves the phone -
  the phone only returns a cryptographic proof that the sensor accepted
  the finger. That proof is verified here with the `cryptography` library.
* The result is saved as  <file>.signed.json  (+ <file>.signature.png)
  and protected by the Ed25519 key of CryptoCheck.

No extra pip packages are needed (standard library + cryptography).
"""

import base64
import hashlib
import json
import os
import secrets
import atexit
import re
import shutil
import socket
import subprocess
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

PORT = 8765
CRED_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "cryptocheck_webauthn.json"
)
MAX_BODY = 3 * 1024 * 1024  # 3 MB


# ---------------------------------------------------------------
# helpers
# ---------------------------------------------------------------

def b64u_decode(text):
    text = text + "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text.encode())


def b64u_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def get_lan_ip():
    """IP address of this laptop on the Wi-Fi network."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def load_credentials():
    try:
        with open(CRED_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return []


def save_credentials(creds):
    with open(CRED_FILE, "w", encoding="utf-8") as f:
        json.dump(creds, f, indent=2)


# ---------------------------------------------------------------
# signing session
# ---------------------------------------------------------------

class SignSession:
    def __init__(self, file_name, file_hash, require_biometric):
        self.token = secrets.token_urlsafe(6)
        self.file_name = file_name
        self.file_hash = file_hash
        self.require_biometric = require_biometric
        self.challenge = b64u_encode(os.urandom(32))
        self.result = None          # filled when the user submits
        self.lock = threading.Lock()

    def rotate_challenge(self):
        self.challenge = b64u_encode(os.urandom(32))


_session = None
_server = None


def start_session(file_path, file_hash, require_biometric):
    """Create a new signing session and make sure the server is running."""
    global _session, _server
    _session = SignSession(os.path.basename(file_path), file_hash, require_biometric)
    if _server is None:
        _server = ThreadingHTTPServer(("0.0.0.0", PORT), _Handler)
        threading.Thread(target=_server.serve_forever, daemon=True).start()
    return _session


def stop_server():
    global _server
    if _server is not None:
        _server.shutdown()
        _server.server_close()
        _server = None



# ---------------------------------------------------------------
# automatic HTTPS tunnel (cloudflared) - needed for the fingerprint
# ---------------------------------------------------------------

tunnel_url = None
_tunnel_proc = None


def _find_cloudflared():
    here = os.path.dirname(os.path.abspath(__file__))
    for name in ("cloudflared.exe", "cloudflared"):
        path = os.path.join(here, name)
        if os.path.exists(path):
            return path
    return shutil.which("cloudflared")


def start_tunnel():
    """
    Start cloudflared in the background (once). The public https address
    appears later in `tunnel_url`. Returns False if cloudflared is missing.
    """
    global _tunnel_proc
    if _tunnel_proc is not None and _tunnel_proc.poll() is None:
        return True

    exe = _find_cloudflared()
    if not exe:
        return False

    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    _tunnel_proc = subprocess.Popen(
        [exe, "tunnel", "--url", f"http://localhost:{PORT}"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, creationflags=flags,
    )

    def reader(proc):
        global tunnel_url
        for line in proc.stdout:          # keep draining the pipe
            m = re.search(r"https://[a-z0-9-]+\.trycloudflare\.com", line)
            if m and tunnel_url is None:
                tunnel_url = m.group(0)

    threading.Thread(target=reader, args=(_tunnel_proc,), daemon=True).start()
    return True


def stop_tunnel():
    global _tunnel_proc, tunnel_url
    if _tunnel_proc is not None and _tunnel_proc.poll() is None:
        _tunnel_proc.terminate()
    _tunnel_proc = None
    tunnel_url = None


atexit.register(stop_tunnel)

# ---------------------------------------------------------------
# WebAuthn (fingerprint) verification
# ---------------------------------------------------------------

class AuthError(Exception):
    pass


def _check_client_data(raw, expected_type, session):
    try:
        data = json.loads(raw)
    except ValueError:
        raise AuthError("Bad clientDataJSON")
    if data.get("type") != expected_type:
        raise AuthError("Wrong WebAuthn type")
    if data.get("challenge") != session.challenge:
        raise AuthError("Challenge mismatch (possible replay)")
    host = urlparse(data.get("origin", "")).hostname
    if not host:
        raise AuthError("No origin")
    return host


def register_credential(session, body):
    client_raw = b64u_decode(body["client_data"])
    rp_id = _check_client_data(client_raw, "webauthn.create", session)
    if rp_id != body.get("rp_id"):
        raise AuthError("rp_id mismatch")
    pub = serialization.load_der_public_key(b64u_decode(body["public_key"]))
    if not isinstance(pub, ec.EllipticCurvePublicKey) or pub.curve.name != "secp256r1":
        raise AuthError("Only ES256 (P-256) keys are supported")
    creds = [c for c in load_credentials() if c["id"] != body["id"]]
    creds.append({
        "id": body["id"],
        "rp_id": rp_id,
        "public_key": body["public_key"],
        "registered": datetime.now().isoformat(timespec="seconds"),
    })
    save_credentials(creds)
    session.rotate_challenge()


def verify_assertion(session, a):
    """Verify a fingerprint assertion. Returns credential id on success."""
    client_raw = b64u_decode(a["clientDataJSON"])
    rp_id = _check_client_data(client_raw, "webauthn.get", session)

    cred = next((c for c in load_credentials()
                 if c["id"] == a["id"] and c["rp_id"] == rp_id), None)
    if cred is None:
        raise AuthError("Fingerprint not registered for this address")

    auth = b64u_decode(a["authenticatorData"])
    if len(auth) < 37 or auth[:32] != hashlib.sha256(rp_id.encode()).digest():
        raise AuthError("rpIdHash mismatch")
    flags = auth[32]
    if not flags & 0x01:
        raise AuthError("User not present")
    if not flags & 0x04:
        raise AuthError("Fingerprint / screen-lock was not verified")

    signed = auth + hashlib.sha256(client_raw).digest()
    pub = serialization.load_der_public_key(b64u_decode(cred["public_key"]))
    try:
        pub.verify(b64u_decode(a["signature"]), signed, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise AuthError("Fingerprint signature invalid")
    session.rotate_challenge()
    return cred["id"]


# ---------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    # -- utils
    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _authorised(self, token):
        return _session is not None and secrets.compare_digest(
            token or "", _session.token)

    # -- GET
    def do_GET(self):
        url = urlparse(self.path)
        token = parse_qs(url.query).get("t", [""])[0]
        if not self._authorised(token):
            return self._send(403, "Invalid or expired link.", "text/plain")

        if url.path == "/":
            return self._send(200, PAGE_HTML, "text/html")

        if url.path == "/api/session":
            rp = parse_qs(url.query).get("rp", [""])[0]
            ids = [c["id"] for c in load_credentials() if c["rp_id"] == rp]
            return self._send(200, {
                "file_name": _session.file_name,
                "file_hash": _session.file_hash,
                "challenge": _session.challenge,
                "require_biometric": _session.require_biometric,
                "credential_ids": ids,
                "done": _session.result is not None,
            })
        self._send(404, "Not found", "text/plain")

    # -- POST
    def do_POST(self):
        url = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0 or length > MAX_BODY:
            return self._send(413, {"error": "Bad size"})
        try:
            body = json.loads(self.rfile.read(length))
        except ValueError:
            return self._send(400, {"error": "Bad JSON"})
        if not self._authorised(body.get("t")):
            return self._send(403, {"error": "Invalid or expired link"})

        s = _session
        with s.lock:
            try:
                if url.path == "/api/register":
                    register_credential(s, body)
                    return self._send(200, {"ok": True, "challenge": s.challenge})

                if url.path == "/api/sign":
                    return self._handle_sign(s, body)
            except (AuthError, KeyError, ValueError) as e:
                return self._send(400, {"error": str(e)})
        self._send(404, {"error": "Not found"})

    def _handle_sign(self, s, body):
        if s.result is not None:
            return self._send(409, {"error": "Already signed"})

        image = body.get("image", "")
        prefix = "data:image/png;base64,"
        if not image.startswith(prefix):
            return self._send(400, {"error": "Signature image missing"})
        png = base64.b64decode(image[len(prefix):])
        if not png.startswith(b"\x89PNG") or len(png) > 2 * 1024 * 1024:
            return self._send(400, {"error": "Invalid signature image"})
        if int(body.get("points", 0)) < 15:
            return self._send(400, {"error": "Signature is too short - please sign again"})

        biometric_id = None
        if body.get("assertion"):
            biometric_id = verify_assertion(s, body["assertion"])
        elif s.require_biometric:
            return self._send(400, {"error": "Fingerprint verification is required"})

        s.result = {
            "png": png,
            "signer": (body.get("signer") or "").strip()[:80] or "Unnamed signer",
            "biometric_credential": biometric_id,
            "device": self.headers.get("User-Agent", "")[:200],
            "client_ip": self.client_address[0],
        }
        self._send(200, {"ok": True})


# ---------------------------------------------------------------
# signed record (saved next to the file)
# ---------------------------------------------------------------

def _canonical(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def save_signed_record(file_path, file_hash, result, private_key):
    """Create <file>.signed.json (+ .signature.png). Returns record path."""
    record = {
        "format": "CryptoCheck-Signed-Record-v1",
        "file_name": os.path.basename(file_path),
        "file_sha256": file_hash,
        "signed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "signer": result["signer"],
        "fingerprint_verified": result["biometric_credential"] is not None,
        "fingerprint_credential": result["biometric_credential"],
        "signing_device": result["device"],
        "handwritten_signature_png": base64.b64encode(result["png"]).decode(),
        "handwritten_signature_sha256": hashlib.sha256(result["png"]).hexdigest(),
    }
    record["ed25519_signature"] = base64.b64encode(
        private_key.sign(_canonical(record))).decode()

    record_path = file_path + ".signed.json"
    with open(record_path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)
    with open(file_path + ".signature.png", "wb") as f:
        f.write(result["png"])
    return record_path


def verify_signed_record(file_path, public_key):
    """
    Returns (ok, message, record_or_None).
    Checks: file hash, Ed25519 signature on the record, embedded image hash.
    """
    record_path = file_path + ".signed.json"
    if not os.path.exists(record_path):
        return False, "No .signed.json record found for this file.", None
    try:
        with open(record_path, "r", encoding="utf-8") as f:
            record = json.load(f)
        sig = base64.b64decode(record.pop("ed25519_signature"))
        public_key.verify(sig, _canonical(record))
    except (InvalidSignature, KeyError, ValueError):
        return False, "The signed record was modified or is not from this CryptoCheck key.", None

    png = base64.b64decode(record["handwritten_signature_png"])
    if hashlib.sha256(png).hexdigest() != record["handwritten_signature_sha256"]:
        return False, "The signature image was tampered with.", None
    if sha256_file(file_path) != record["file_sha256"]:
        return False, "The FILE has changed since it was signed.", record
    return True, "Signature record and file are authentic.", record


# ---------------------------------------------------------------
# the web page (works with mouse, touch and pen)
# ---------------------------------------------------------------

PAGE_HTML = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
<title>CryptoCheck - Sign</title>
<style>
 :root{--bg:#071426;--panel:#0d1f38;--panel2:#102746;--b:#1d4770;--t:#eef6ff;--m:#91a9c4;
       --blue:#1688ff;--green:#18c996;--red:#ef5350;--purple:#7c4dff}
 *{box-sizing:border-box}
 body{margin:0;background:var(--bg);color:var(--t);font-family:Segoe UI,Roboto,Arial,sans-serif}
 header{background:#081a31;padding:16px 20px;font-size:20px;font-weight:700}
 header small{color:#62b6ff;font-size:11px;margin-left:10px;letter-spacing:1px}
 main{max-width:640px;margin:0 auto;padding:16px}
 .card{background:var(--panel);border:1px solid var(--b);border-radius:12px;padding:16px;margin-bottom:14px}
 .lbl{color:var(--m);font-size:11px;font-weight:700;letter-spacing:1px;margin-bottom:6px}
 .mono{font-family:Consolas,monospace;font-size:12px;word-break:break-all;color:#b8cce0}
 canvas{width:100%;height:240px;background:#fff;border-radius:8px;touch-action:none;display:block;cursor:crosshair}
 input[type=text]{width:100%;padding:12px;border-radius:8px;border:1px solid var(--b);background:var(--panel2);color:var(--t);font-size:15px}
 button{border:0;border-radius:8px;color:#fff;padding:13px 18px;font-size:15px;font-weight:700;cursor:pointer}
 .row{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
 .row button{flex:1;min-width:130px}
 #clear{background:#4a5d78}#reg{background:var(--purple)}#send{background:var(--green)}
 button:disabled{opacity:.45}
 #msg{min-height:22px;font-size:14px;margin-top:10px}
 .ok{color:var(--green)}.err{color:var(--red)}
</style></head><body>
<header>🛡 CryptoCheck <small>SIGN DOCUMENT</small></header>
<main>
 <div class="card">
  <div class="lbl">FILE TO SIGN</div>
  <div id="fname" style="font-weight:700">…</div>
  <div class="lbl" style="margin-top:10px">SHA-256</div>
  <div id="fhash" class="mono">…</div>
 </div>

 <div class="card">
  <div class="lbl">YOUR NAME</div>
  <input id="name" type="text" placeholder="Full name" autocomplete="name">
  <div class="lbl" style="margin-top:14px">SIGN BELOW (finger / mouse / pen)</div>
  <canvas id="pad"></canvas>
  <div class="row"><button id="clear">Clear</button></div>
 </div>

 <div class="card">
  <div class="lbl">FINGERPRINT AUTHENTICATION</div>
  <div id="bio" style="font-size:14px;color:var(--m)">Checking…</div>
  <div class="row"><button id="reg" style="display:none">Register my fingerprint</button></div>
 </div>

 <button id="send" style="width:100%;font-size:17px;padding:16px">✓ Sign &amp; Submit</button>
 <div id="msg"></div>
</main>

<script>
const T = new URLSearchParams(location.search).get('t');
const $ = id => document.getElementById(id);
let S = null, points = 0, bioReady = false;

const b2u = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const u2b = s => { s = s.replace(/-/g,'+').replace(/_/g,'/'); s += '='.repeat((4 - s.length % 4) % 4);
                   return Uint8Array.from(atob(s), c => c.charCodeAt(0)); };
const say = (t, cls) => { $('msg').textContent = t; $('msg').className = cls || ''; };

/* ---------- signature pad ---------- */
const cv = $('pad'), ctx = cv.getContext('2d');
function resize(){
  const r = cv.getBoundingClientRect(), d = window.devicePixelRatio || 1;
  const keep = points ? cv.toDataURL() : null;
  cv.width = r.width * d; cv.height = r.height * d;
  ctx.setTransform(d,0,0,d,0,0);
  ctx.lineWidth = 2.6; ctx.lineCap = 'round'; ctx.lineJoin = 'round'; ctx.strokeStyle = '#0a1f44';
  ctx.fillStyle = '#fff'; ctx.fillRect(0,0,r.width,r.height);
  if (keep){ const i = new Image(); i.onload = () => ctx.drawImage(i,0,0,r.width,r.height); i.src = keep; }
}
resize(); window.addEventListener('resize', resize);

let drawing = false, last = null;
const pos = e => { const r = cv.getBoundingClientRect(); return {x:e.clientX-r.left, y:e.clientY-r.top}; };
cv.addEventListener('pointerdown', e => { drawing = true; last = pos(e); cv.setPointerCapture(e.pointerId);
  ctx.beginPath(); ctx.arc(last.x,last.y,1.3,0,7); ctx.fillStyle='#0a1f44'; ctx.fill(); points++; e.preventDefault(); });
cv.addEventListener('pointermove', e => { if(!drawing) return; const p = pos(e);
  ctx.beginPath(); ctx.moveTo(last.x,last.y); ctx.lineTo(p.x,p.y); ctx.stroke(); last = p; points++; e.preventDefault(); });
['pointerup','pointercancel','pointerleave'].forEach(n => cv.addEventListener(n, () => drawing = false));
$('clear').onclick = () => { points = 0; const r = cv.getBoundingClientRect(); ctx.fillStyle='#fff'; ctx.fillRect(0,0,r.width,r.height); };

/* ---------- session + fingerprint ---------- */
async function load(){
  const r = await fetch('/api/session?t='+encodeURIComponent(T)+'&rp='+encodeURIComponent(location.hostname));
  if(!r.ok){ say('Invalid or expired link.','err'); $('send').disabled = true; return; }
  S = await r.json();
  $('fname').textContent = S.file_name; $('fhash').textContent = S.file_hash;
  if (S.done){ say('This file was already signed.','ok'); $('send').disabled = true; }

  const can = window.isSecureContext && window.PublicKeyCredential;
  if (!can){
    $('bio').innerHTML = 'Fingerprint is <b>not available</b> on this address (the browser needs HTTPS or localhost). ' +
      (S.require_biometric ? '<span class="err">Fingerprint is REQUIRED for this signature - open the HTTPS link.</span>' : 'You can still sign without it.');
    return;
  }
  if (S.credential_ids.length){ bioReady = true;
    $('bio').innerHTML = '<span class="ok">✓ Fingerprint registered for this device.</span> You will be asked to touch the sensor when you submit.';
  } else {
    $('bio').textContent = 'No fingerprint registered here yet. Tap the button and touch your fingerprint sensor.';
    $('reg').style.display = 'block';
  }
}

$('reg').onclick = async () => {
  try{
    const cred = await navigator.credentials.create({publicKey:{
      challenge: u2b(S.challenge), rp:{name:'CryptoCheck', id: location.hostname},
      user:{id:new TextEncoder().encode('cryptocheck-user'), name:'cryptocheck', displayName:'CryptoCheck User'},
      pubKeyCredParams:[{type:'public-key', alg:-7}],
      authenticatorSelection:{authenticatorAttachment:'platform', userVerification:'required'},
      timeout:60000, attestation:'none'}});
    const r = await fetch('/api/register', {method:'POST', body: JSON.stringify({
      t:T, id:cred.id, rp_id:location.hostname,
      public_key:b2u(cred.response.getPublicKey()), client_data:b2u(cred.response.clientDataJSON)})});
    const j = await r.json();
    if(!r.ok) throw new Error(j.error);
    S.challenge = j.challenge; S.credential_ids=[cred.id]; bioReady = true;
    $('reg').style.display='none';
    $('bio').innerHTML = '<span class="ok">✓ Fingerprint registered.</span> You will be asked to touch the sensor when you submit.';
  }catch(e){ say('Registration failed: '+e.message,'err'); }
};

$('send').onclick = async () => {
  if(points < 15){ say('Please draw your signature first.','err'); return; }
  $('send').disabled = true; say('Working…');
  try{
    let assertion = null;
    if (bioReady){
      say('Touch your fingerprint sensor…');
      const a = await navigator.credentials.get({publicKey:{
        challenge: u2b(S.challenge), rpId: location.hostname, userVerification:'required', timeout:60000,
        allowCredentials: S.credential_ids.map(id => ({type:'public-key', id:u2b(id)}))}});
      assertion = {id:a.id, authenticatorData:b2u(a.response.authenticatorData),
                   clientDataJSON:b2u(a.response.clientDataJSON), signature:b2u(a.response.signature)};
    }
    const r = await fetch('/api/sign', {method:'POST', body: JSON.stringify({
      t:T, signer:$('name').value, points, image:cv.toDataURL('image/png'), assertion})});
    const j = await r.json();
    if(!r.ok) throw new Error(j.error);
    say('✓ Signed! You can go back to CryptoCheck on the laptop.','ok');
  }catch(e){ say('Failed: '+e.message,'err'); $('send').disabled = false; }
};
load();
</script></body></html>
"""