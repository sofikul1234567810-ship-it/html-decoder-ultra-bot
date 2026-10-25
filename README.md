# Telegram HTML Decoder Bot — Render Webhook

## GitHub
Upload `main.py`, `requirements.txt`, and `render.yaml` to a GitHub repository.

## Render
Create a new Web Service and connect the repository.
Build command: `pip install -r requirements.txt`
Start command: `uvicorn main:api --host 0.0.0.0 --port $PORT`

Set Environment Variables:
- `BOT_TOKEN`: token from Telegram @BotFather
- `WEBHOOK_SECRET`: random secret containing only A-Z, a-z, 0-9, underscore, hyphen (Render can generate one)
- `RENDER_EXTERNAL_URL`: your public Render HTTPS URL, without a trailing slash

Then deploy, open the service URL to check for `{"status":"ok"}`, and send `/start` to your Telegram bot.

Supports HTML/HTM/TXT up to 2 MB, HTML entity decoding, formatting, inline JS/CSS extraction, URL decoding, and readable Base64 candidates. It does not run uploaded JavaScript, crack passwords, or bypass encryption. AES-GCM encrypted data requires the correct password/key and matching algorithm. Free Render services may sleep when inactive.
