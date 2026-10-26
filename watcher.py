"""Loki'deki kritik/500 hataları ClickUp'a task olarak açar.

Aynı hata (fingerprint) ikinci kez task açmaz, mevcut task'a yorum olarak sayı düşer.
Sadece stdlib. DRY_RUN=1 ile ClickUp'a dokunmadan ne yapacağını yazar.
"""
import hashlib
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone


def load_env(path=".env"):
    if os.path.exists(path):
        for line in open(path):
            k, sep, v = line.strip().partition("=")
            if sep and not k.startswith("#"):
                os.environ.setdefault(k.strip(), v.strip())


load_env()
LOKI = os.environ.get("LOKI_URL", "http://localhost:3100").rstrip("/")
TOKEN = os.environ.get("CLICKUP_TOKEN", "")
LIST_ID = os.environ.get("CLICKUP_LIST_ID", "")
ASSIGNEES = [int(x) for x in os.environ.get("CLICKUP_ASSIGNEES", "").split(",") if x.strip()]
INTERVAL = int(os.environ.get("INTERVAL_SEC", "300"))
COMMENT_EVERY = int(os.environ.get("COMMENT_EVERY_MIN", "60")) * 60
FIRST_LOOKBACK = int(os.environ.get("FIRST_LOOKBACK_MIN", "15")) * 60
STATE_FILE = os.environ.get("STATE_FILE", "data/state.json")
DRY_RUN = os.environ.get("DRY_RUN") == "1"
LAG = 60  # Loki'ye geç düşen satırlar için
PAGE = 5000
TR = timezone(timedelta(hours=3))
# Ortamına dokunamadığımız, sürekli aynı hatayı basan app'ler (örn. bozuk dev ortamı)
IGNORE_APPS = [x.strip() for x in os.environ.get("IGNORE_APPS", "").split(",") if x.strip()]
SKIP = f', app!~"{"|".join(IGNORE_APPS)}"' if IGNORE_APPS else ""

# Symfony uncaught exception'ları "critical" basıyor; Node tarafında 500 ya da uncaught olanlar.
# metadata.statusCode: orav'ın Nest filter'ı; iç içe context.statusCode'lar (centrio) aynı olayın kopyası, alınmıyor.
# env= label'li stream'lerde (Logo, mentorluk, logoakademi) level stream label'i degil yapisal metadata:
# {level=...} selector'u bunlari hic gormuyor, level filtre asamasinda secilir. Monolog error'larindan
# sadece kritik olanlar (PHP Error, DB, upstream 5xx); 4xx is kurali hatalari (BadRequest vb.) disarida.
QUERIES = [
    '{level="critical"' + SKIP + '}',
    '{env=~".+"' + SKIP + '} | level="critical"',
    '{env=~".+"' + SKIP + '} | level="error" |~ "(Error|ErrorException|TypeError|ParseError|QueryException|PDOException|'
    'NoTypeDetectedException)\\\\(code:|SQLSTATE|Call to a member function|Unhandled error event|Operation [A-Za-z]+ Error|'
    'status[^:]{0,3}:5[0-9]{2}" !~ "is deprecated"',
    '{level="error"' + SKIP + '} |~ "uncaughtException|unhandledRejection|Unhandled error event|\\"status\\":5[0-9]{2}|\\"metadata\\":\\\\{\\"statusCode\\":5[0-9]{2}| - 5[0-9]{2}\\""',
]

# Nest'in 4xx exception'ları uncaught diye loglanıyor ama 500 değil.
# ponytail: düz HttpException de atlanıyor (gözlenenlerin hepsi 4xx), 500 kaçarsa status alanına bakılmalı
FOURXX = re.compile(r"^((Http|Unauthorized|NotFound|BadRequest|Forbidden|Gone|Conflict|UnprocessableEntity|"
                    r"NotAcceptable|MethodNotAllowed|PayloadTooLarge|TooManyRequests)Exception|ForbiddenError)$")
# Escape'li JSON (\"client_secret\":\"...\") ve "Authorization":"Bearer <token>" de maskelenir.
SECRET_RE = re.compile(r'((?:secret|password|passwd|token|api[_-]?key|authorization|client_id)\\*["\']?\s*[=:]\s*\\*["\']?'
                       r'(?:Bearer\s+)?)[^"\'\\&\s,}]+', re.I)
# OAuth "code": statusCode/errorCode ve kisa kodlar (GENERIC_ERROR, 499) maskelenmez.
OAUTH_CODE_RE = re.compile(r'((?<![A-Za-z_])code\\*["\']?\s*[=:]\s*\\*["\']?)[A-Za-z0-9._~-]{16,}', re.I)
MONOLOG = re.compile(r"^\[[^\]]+\] [\w-]+\.\w+: (.*?) (?:\{.*\}|\[\]) (?:\{.*\}|\[\])\s*$", re.S)
VOLATILE = [
    (re.compile(r"\(SQL: .*", re.S), ""),  # Laravel QueryException: ayni DB hatasi farkli sorgularda tek task
    (re.compile(r"\?[^\s\"']*"), ""),  # query string
    (re.compile(r"\{[^}]*\}"), ""),  # story.NOT_FOUND{slug:...}
    (re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I), "<uuid>"),
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b"), "<email>"),
    (re.compile(r"\b[0-9a-f]{12,}\b", re.I), "<hex>"),
    (re.compile(r"\d+"), "#"),
    (re.compile(r"\s+"), " "),
]


def mask(s):
    return OAUTH_CODE_RE.sub(r"\1***", SECRET_RE.sub(r"\1***", s))


def stack_name(stack):
    """Stack'in ilk satırındaki exception adı ("TypeError: x" -> TypeError; ":" yoksa ilk satır)."""
    first = (stack or "").strip().splitlines()[0] if (stack or "").strip() else ""
    return first.split(":", 1)[0].strip()


def parse(labels, line):
    """-> (exception, message) ya da twin/gürültü satırıysa None."""
    exc = labels.get("exception_class", "")
    if line.lstrip().startswith("{"):
        try:
            d = json.loads(line)
        except ValueError:
            d = None
        if isinstance(d, dict):
            msg = str(d.get("message", ""))
            meta = d.get("metadata") or {}
            # aynı olayın ikinci kopyaları: PX-Logger tekrarı, uncaught sarmalayıcısı, mesajsız http_response
            if msg.startswith("[PX-Logger]") or msg.startswith("Uncaught exception") or meta.get("event") == "http_response":
                return None
            name = meta.get("errorName") or exc
            if FOURXX.match(name or ""):
                return None
            if meta.get("event") == "http_exception":  # URL değil asıl hata: "GET /x - 500" -> "TypeError: ..."
                return stack_name(meta.get("stack")) or exc, str(meta.get("message") or msg)
            if int(meta.get("statusCode") or 0) >= 500 and (meta.get("error") or meta.get("stack")):
                # Nest filter'ı (orav): mesaj hep "Internal Server Error", asıl hata metadata.error/stack'te
                return name or stack_name(meta.get("stack")) or exc, error_summary(meta) or msg
            return name, msg.removeprefix("uncaughtException: ")
    # Monolog tek satır: "[ts] loki.ERROR: mesaj {context} []"; exception context'te "[object] (Sınıf(code: N): ...)"
    mono = MONOLOG.match(line.strip())
    if mono:
        cls = re.search(r"\(([\w\\\\]+)\(code:", line)
        return (cls.group(1).replace("\\\\", "\\") if cls else exc), mono.group(1)
    # Symfony/monolog düz metin: "Exception: X\nMessage: Y"
    m = re.search(r"^Exception: (.+)$", line, re.M)
    mm = re.search(r"^Message: (.+)$", line, re.M)
    return (m.group(1) if m else exc), (mm.group(1) if mm else line.splitlines()[0] if line else "")


def error_summary(meta):
    """Prisma: "Invalid `this.prisma.x.create()` invocation: <asıl sebep>", diğerleri ilk satır."""
    lines = [x.strip() for x in str(meta.get("error") or meta.get("stack") or "").splitlines() if x.strip()]
    if not lines:
        return ""
    if lines[0].startswith("Invalid `"):
        return f"{lines[0].removesuffix(' in')}: {lines[-1]}"
    return lines[0]


def fingerprint(app, exc, msg):
    norm = msg
    for rx, rep in VOLATILE:
        norm = rx.sub(rep, norm)
    return hashlib.sha1(f"{app}|{exc}|{norm.strip()[:300]}".encode()).hexdigest()[:16]


def http(method, url, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read() or b"{}")


def loki_range(query, start_ns, end_ns):
    """İleri yönde sayfalayarak tüm satırları döner: [(ts_ns, labels, line)]."""
    out = []
    while True:
        qs = urllib.parse.urlencode({"query": query, "start": start_ns, "end": end_ns, "limit": PAGE, "direction": "forward"})
        res = http("GET", f"{LOKI}/loki/api/v1/query_range?{qs}")["data"]["result"]
        page = [(int(ts), s["stream"], line) for s in res for ts, line in s["values"]]
        out += page
        if len(page) < PAGE:
            return out
        start_ns = max(p[0] for p in page) + 1


def clickup(method, path, body=None):
    if DRY_RUN:
        print("DRY", method, path, json.dumps(body, ensure_ascii=False)[:400])
        return {"id": "dry", "status": {"type": "open"}}
    return http(method, f"https://api.clickup.com/api/v2{path}", body, {"Authorization": TOKEN})


def fmt(ns):
    return datetime.fromtimestamp(ns / 1e9, TR).strftime("%d.%m %H:%M:%S")


def create_task(g):
    lb = g["labels"]
    env = lb.get("environment") or lb.get("env") or "-"
    title = f"[{g['app']}] {g['exc'].rsplit(chr(92), 1)[-1] + ': ' if g['exc'] else ''}{g['msg']}"
    desc = "\n".join([
        f"**Proje (app):** {g['app']}",
        f"**Ortam:** {env}",
        f"**Seviye:** {lb.get('level')}",
        f"**Exception:** {g['exc'] or '-'}",
        f"**Host:** {lb.get('host') or lb.get('hostname') or '-'}",
        f"**İlk görülme:** {fmt(g['first'])}",
        f"**Bu taramada:** {g['count']} log",
        f"**Fingerprint:** `{g['fp']}`",
        "",
        "Loki sorgusu:",
        f"```\n{{app=\"{g['app']}\", level=\"{lb.get('level')}\"}}\n```",
        "Örnek log:",
        f"```\n{mask(g['sample'])[:4000]}\n```",
        "",
        "_Bu task loki-clickup watcher tarafından otomatik açıldı. Aynı hata tekrar düşerse yeni task açılmaz, buraya yorum eklenir._",
    ])
    body = {
        "name": mask(title)[:200],
        "markdown_description": desc,
        "assignees": ASSIGNEES,
        "priority": 2 if env.startswith("prod") else 3,
        "custom_item_id": 1004,  # workspace'teki "Bug" task tipi
    }
    return clickup("POST", f"/list/{LIST_ID}/task", body)["id"]


def flush_comment(st, now):
    """Bekleyen sayıyı task'a yorum olarak yazar. Task silinmişse False."""
    try:
        task = clickup("GET", f"/task/{st['task_id']}")
    except urllib.error.HTTPError as e:
        if e.code in (401, 404):  # silinmiş ya da erişim yok
            return False
        raise
    text = f"{fmt(st['pending_from'])} - {fmt(st['pending_to'])} arası {st['pending']} yeni log düştü. Toplam: {st['total']}."
    if task.get("status", {}).get("type") == "closed":
        clickup("PUT", f"/task/{st['task_id']}", {"status": "new report"})
        text = "Çözüldü olarak kapatılmıştı ama hata tekrar düştü, task yeniden açıldı.\n" + text
    clickup("POST", f"/task/{st['task_id']}/comment", {"comment_text": text, "notify_all": False})
    st.update(pending=0, last_comment=now)
    return True


def load_state():
    try:
        return json.load(open(STATE_FILE))
    except FileNotFoundError:
        return {"last_end": 0, "errors": {}}


def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE) or ".", exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    json.dump(state, open(tmp, "w"), ensure_ascii=False, indent=1)
    os.replace(tmp, STATE_FILE)


def scan(state):
    now = time.time()
    end_ns = int((now - LAG) * 1e9)
    start_ns = state["last_end"] + 1 if state["last_end"] else int((now - LAG - FIRST_LOOKBACK) * 1e9)

    groups = {}
    for q in QUERIES:
        for ts, labels, line in loki_range(q, start_ns, end_ns):
            parsed = parse(labels, line)
            if not parsed:
                continue
            exc, msg = parsed
            app = labels.get("app") or labels.get("service_name") or "?"
            fp = fingerprint(app, exc, msg)
            g = groups.setdefault(fp, {"fp": fp, "app": app, "exc": exc, "msg": msg.strip()[:160], "labels": labels,
                                       "sample": line, "count": 0, "first": ts, "last": ts})
            g["count"] += 1
            g["first"], g["last"] = min(g["first"], ts), max(g["last"], ts)

    for fp, g in groups.items():
        st = state["errors"].get(fp)
        if st:
            st["pending"] += g["count"]
            st["total"] += g["count"]
            st["pending_from"] = st.get("pending_from") if st["pending"] > g["count"] else g["first"]
            st["pending_to"] = g["last"]
        else:
            task_id = create_task(g)
            print(f"yeni task {task_id} {g['app']} {g['msg'][:80]}", flush=True)
            st = state["errors"][fp] = {"task_id": task_id, "app": g["app"], "msg": g["msg"], "total": g["count"],
                                        "pending": 0, "last_comment": now}
        save_state(state)  # task açıldıysa çökse bile tekrar açmasın

    for fp, st in list(state["errors"].items()):
        if st["pending"] and now - st["last_comment"] >= COMMENT_EVERY:
            if not flush_comment(st, now):
                del state["errors"][fp]  # silinmiş task: bir sonraki düşüşte yeni task açılır
            save_state(state)

    state["last_end"] = end_ns
    save_state(state)
    print(f"{fmt(end_ns)} tarandı: {sum(g['count'] for g in groups.values())} log, {len(groups)} farklı hata", flush=True)


def main():
    if not DRY_RUN and (not TOKEN or not ASSIGNEES or not LIST_ID):
        sys.exit("CLICKUP_TOKEN, CLICKUP_LIST_ID ve CLICKUP_ASSIGNEES gerekli")
    once = "--once" in sys.argv
    while True:
        state = load_state()
        try:
            scan(state)
        except Exception as e:  # ağ hatası vs: last_end ilerlemez, sonraki turda aynı aralık tekrar taranır
            print(f"hata: {e!r}", flush=True)
        if once:
            return
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
