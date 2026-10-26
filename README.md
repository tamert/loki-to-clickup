# clickup-loki

Loki'deki kritik/500 hataları 5 dakikada bir tarar, ClickUp "Hata Bildirimleri" listesine `[app] Exception: mesaj` başlığıyla task açar.
Aynı hata (app + exception + sayı/uuid/query temizlenmiş mesaj) tekrar düşerse yeni task açılmaz; en fazla saatte bir "X - Y arası N yeni log düştü" yorumu eklenir.
Task "resolved" yapılmışsa ve hata tekrar düşerse task yeniden açılır.

Taranan: `{level="critical"}` + `{level="error"}` içinden uncaught / 500 olanlar. Nest 4xx exception'ları (Unauthorized, NotFound, BadRequest...) atlanır. `IGNORE_APPS` içindeki app'ler (virgülle) hiç taranmaz.

```bash
cp .env.example .env            # token'ı gir
DRY_RUN=1 FIRST_LOOKBACK_MIN=1440 STATE_FILE=/tmp/s.json python3 watcher.py --once   # ClickUp'a dokunmadan dene
docker compose up -d --build
docker logs -f clickup-loki
```

Durum `data/state.json` içinde (fingerprint -> task id). Silinirse aynı hatalar için yeni task açılır.
