# SSH Honeypot (Basic Version)

A simple SSH Honeypot written in Python using the paramiko library.
This project is currently a basic implementation intended for experimentation, learning, and further development.

The current version only captures login attempts (username/password) and logs them.
Future versions are planned to include more advanced honeypot features.

---

## Features

- Fake SSH server
- Logs connection attempts
- Captures username and password attempts
- Stores logs in a file
- Lightweight and easy to run

---

## Project Structure
```markdown
HONEY_POT/
│
├── main.py
├── fake_host_key
├── requirements.txt
├── ssh_honeypot.log
└── .venv

```
---

## Install Requirements

First make sure Python 3 is installed.

```markdown
pip install -r requirements.txt
```
or

```markdown
pip install paramiko
```
---

## Host Key

The repository already includes a sample SSH host key named:

```
fake_host_key
```

This key is included only for convenience in this basic version.

You can generate your own key and replace it with:

```
ssh-keygen -t rsa -b 2048 -f fake_host_key
```

This will create a new private key that the honeypot will use as its SSH server identity.

---

Running the Honeypot

```
python main.py
```

The honeypot will listen on:

```
0.0.0.0:22
```

### Note: Running on port 22 may require administrator/root privileges.

---

## Logs

All connection and login attempts are saved in:

```
ssh_honeypot.log
```

### Example:
```
[+] Connection from 192.168.1.10:53421
[!] Login attempt: root:123456
```
---

## Important Notice

This project is intended for:
- Security research
- Honeypot experimentation
- Learning purposes

Do not deploy it on networks you do not own or without authorization.

---

## Project Status

This repository currently contains a basic version of the honeypot.
Future improvements may include:

- Fake shell interaction
- Advanced logging (JSON / Database)
- Attacker behavior tracking
- Multi‑client handling
- Alert systems (Telegram / Webhook)
- Web dashboard


---

---
# هانی پات SSH (نسخه پایه)

این پروژه یک SSH Honeypot ساده است که با استفاده از زبان Python و کتابخانه paramiko ساخته شده است.
این نسخه یک نسخه پایه (Basic Version) است و برای یادگیری، آزمایش و توسعه‌های بعدی منتشر شده است.

در حال حاضر برنامه فقط تلاش‌های ورود (username و password) را ثبت کرده و در فایل لاگ ذخیره می‌کند.

---

## ویژگی‌ها

- سرور SSH جعلی
- ثبت اتصال‌ها
- ذخیره تلاش‌های ورود
- سبک و ساده برای اجرا
- ذخیره لاگ در فایل

---

## ساختار پروژه
```
HONEY_POT/
│
├── main.py
├── fake_host_key
├── requirements.txt
├── ssh_honeypot.log
└── .venv
```
---

## نصب پیش‌نیازها

ابتدا مطمئن شوید Python 3 نصب است.
```
pip install -r requirements.txt
```
یا
```
pip install paramiko
```
---
## کلیدسرور(Host Key)

در داخل پروژه یک کلید نمونه با نام زیر قرار داده شده است:
```
fake_host_key
```
این کلید فقط برای اجرای سریع نسخه پایه قرار داده شده است.

برای ساخت کلید جدید می‌توانید از دستور زیر استفاده کنید:
```
ssh-keygen -t rsa -b 2048 -f fake_host_key
```
---

## اجرای برنامه
```
python main.py
```
سرور روی آدرس زیر گوش می‌دهد:
```
0.0.0.0:22
```
توجه: استفاده از پورت 22 معمولاً نیاز به دسترسی root یا administrator دارد.

---

## لاگ‌ها

تمام اتصال‌ها و تلاش‌های ورود در فایل زیر ذخیره می‌شوند:
```
ssh_honeypot.log
```
---

## هشدار

این پروژه فقط برای اهداف آموزشی، تحقیقاتی و آزمایش هانی‌پات ساخته شده است.
از اجرای آن روی شبکه‌هایی که مالک آن نیستید یا بدون مجوز خودداری کنید.

---

## وضعیت پروژه

این پروژه در حال حاضر یک نسخه پایه است و در آینده قابلیت‌های بیشتری مانند موارد زیر به آن اضافه خواهد شد:

- شبیه‌سازی شل جعلی
- لاگ‌گیری پیشرفته
- تحلیل رفتار مهاجم
- مدیریت چند اتصال همزمان
- سیستم هشدار
- داشبورد وب
