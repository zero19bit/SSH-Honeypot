# راهنمای استقرار Production

## ۱. پیش‌شرط

این سرویس را روی VPS یا VM جدا اجرا کنید. SSH مدیریتی واقعی نباید روی همان
endpoint عمومی Honeypot باشد. قبل از استفاده از پورت عمومی ۲۲، دسترسی مدیریتی
خود را از طریق VPN، کنسول ارائه‌دهنده یا یک IP/پورت allowlist‌شده تضمین کنید.
در صورت امکان Docker را در Rootless Mode اجرا کنید؛ user عددی داخل container
به‌تنهایی جایگزین Rootless Docker در سطح daemon نیست.

## ۲. ساخت Image

```bash
docker compose build --pull
```

## ۳. ساخت Host Key پایدار

```bash
docker run --rm --entrypoint python \
  fake-ubuntu-ssh-honeypot:3.0.1 \
  -m honeypot.keygen > host-key.b64
```

فایل بالا یک خط base64 دارد. آن را خارج از repository نگهداری کنید:

```bash
cp .env.example .env
chmod 600 .env
```

سپس مقدار `HONEYPOT_HOST_KEY_B64` را در `.env` با محتوای همان خط جایگزین کنید.
خود برنامه فایل کلید را نمی‌خواند؛ Docker مقدار را از محیط به حافظه process
تزریق می‌کند.

## ۴. اجرا و بررسی

```bash
docker compose up -d
docker compose ps
docker compose logs --tail=50 honeypot
```

خروجی `docker compose ps` باید وضعیت `healthy` نشان دهد. healthcheck با
TCP محلی به listener وصل می‌شود و ممکن است در JSONL رویداد اتصال ایجاد کند.

**پیش از انتشار پورت به اینترنت**: شبکهٔ Compose فعلاً `internal: false`
است و به‌تنهایی egress را نمی‌بندد. پیش‌فرض جدید bind آدرس `127.0.0.1`
است. برای دسترسی عمومی، اول خروجی کانتینر را در firewall میزبان یا سیاست
شبکهٔ VM/ابر مسدود و بررسی کنید، سپس مقدار `HONEYPOT_PUBLIC_BIND=0.0.0.0`
را در `.env` بگذارید و `docker compose up -d` را تکرار کنید. اگر `.env`
قدیمی‌تان مقدار `0.0.0.0` دارد، استقرار قبلی خودبه‌خود محلی نمی‌شود.

تست اتصال:

```bash
ssh -p 2222 \
  -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no \
  root@127.0.0.1
```

## ۵. انتقال به پورت عمومی ۲۲

فقط بعد از انتقال SSH مدیریتی، مقدار زیر را تغییر دهید:

```dotenv
HONEYPOT_PUBLIC_PORT=22
```

process داخل container همچنان non-root و روی 2222 می‌ماند؛ Docker فقط پورت
میزبان را publish می‌کند.

## ۶. لاگ‌ها

هر خط یک JSON مستقل است. Docker حداکثر پنج فایل ۱۰ مگابایتی نگه می‌دارد.
رویدادهای مهم:

- `listener_started` و fingerprint کلید؛
- `authentication`؛
- `command`؛
- `intelligence_alert` با قانون و امتیاز ریسک، بدون تکرار متن فرمان؛
- `connection_rejected` و علت rate limit؛
- `runtime_metrics`؛
- `disconnect`؛
- `startup_failed`.
- `analyzer_error` در صورت خرابی تحلیل؛ نشست همچنان سرویس می‌گیرد.

فیلدهای v3.0.0 مانند `event: command` و `analysis` پابرجا هستند. برای
اعتبارسنجی یک خروجی متعلق به یک اجرای فرایند:

```bash
docker compose logs --no-color --no-log-prefix honeypot > honeypot.jsonl
python3 tools/analyze_log.py honeypot.jsonl
```

زنجیرهٔ هش در شروع مجدد process از genesis شروع می‌شود؛ لاگ‌های چند اجرای
متوالی را برای اعتبارسنجی به تفکیک هر اجرا صادر کنید. قبل از تغییر نسخه از
لاگ‌ها نسخهٔ خارج از میزبان تهیه کنید.

برای محیطی با محدودیت حقوقی از این مقدار استفاده کنید:

```dotenv
HONEYPOT_CREDENTIAL_LOG_MODE=sha256
```

## ۷. به‌روزرسانی امن

```bash
python -m pytest
pip-audit -r requirements.lock
docker compose build --pull --no-cache
docker compose up -d
```

Host Key قبلی را حفظ کنید تا fingerprint عوض نشود. قبل از ارتقا از لاگ‌های مهم
خروجی بگیرید و بعد از اجرا رویداد `listener_started` و وضعیت container را بررسی
کنید.
در مهاجرت از v2، مقدارهای واقعی `.env` و کلید قبلی را خارج از ZIP جدید نگه
دارید و به پوشهٔ استقرار نسخهٔ ۳ منتقل کنید؛ بستهٔ منتشرشده این اسرار را
در خود ندارد. برای تنظیم هشدار می‌توانید `HONEYPOT_ALERT_MIN_RISK=65` را
به `.env` اضافه کنید. گزارش SQLite را فقط روی سیستم تحلیلگر و خارج از
container اجرا کنید؛ دستورات آن در README آمده است.

## ۸. توقف و بازیابی

```bash
docker compose down --timeout 15
```

با SIGTERM، listener بسته می‌شود، socketهای فعال قطع می‌شوند، threadها فرصت
خروج می‌گیرند و صف لاگ flush می‌شود. داده‌های VFS فقط در RAM هستند و با پایان
هر session یا container از بین می‌روند.
