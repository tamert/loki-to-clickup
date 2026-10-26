"""python3 -I test_watcher.py: maskeleme ve parse'in gercek log bicimleriyle kontrolu."""
import importlib.util
import os

os.environ["DRY_RUN"] = "1"
spec = importlib.util.spec_from_file_location("w", os.path.join(os.path.dirname(os.path.abspath(__file__)), "watcher.py"))
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)

# Logo: escape'li ve duz JSON secret'lar, Bearer token, OAuth code
line = ('body: {\\"code\\":\\"19cefc0123456789abcd\\",\\"client_id\\":\\"53b101aa\\",\\"client_secret\\":\\"c4a22dzz\\"} '
        '"header":{"Authorization":"Bearer 184DF2SECRET","code":"19cefc0123456789abcd"} "statusCode":500 "code":"GENERIC_ERROR" "code":499')
m = w.mask(line)
for secret in ("19cefc0123456789abcd", "53b101aa", "c4a22dzz", "184DF2SECRET"):
    assert secret not in m, (secret, m)
for kept in ('"statusCode":500', '"code":"GENERIC_ERROR"', '"code":499', "Bearer ***"):
    assert kept in m, (kept, m)

# Monolog: mesaj ve exception sinifi
mono = ('[2026-10-20T08:00:22+03:00] loki.ERROR: SQLSTATE[HY000] [2002] getaddrinfo failed '
        '{"exception":"[object] (Illuminate\\\\Database\\\\QueryException(code: 2002): SQLSTATE at /x.php:1)"} []')
assert w.parse({}, mono) == ("Illuminate\\Database\\QueryException", "SQLSTATE[HY000] [2002] getaddrinfo failed"), w.parse({}, mono)
crit = '[2026-10-23T12:41:33+03:00] loki.CRITICAL: Recovered seats : 1cba3bb1 {"SubscriptionId":"1"} []'
assert w.parse({"exception_class": ""}, crit) == ("", "Recovered seats : 1cba3bb1")

# Stack'te ":" yoksa ad sadece ilk satir; ForbiddenError 4xx sayilir
assert w.stack_name("Error\n    at Query.run (x.js:1)") == "Error"
assert w.FOURXX.match("ForbiddenError") and w.FOURXX.match("NotFoundException")
print("ok")
