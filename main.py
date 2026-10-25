import base64
import html
import logging
import os
import re
from io import BytesIO
from pathlib import Path
from typing import Optional
from urllib.parse import unquote

from bs4 import BeautifulSoup
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from telegram import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Update,
)
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("html-decoder-bot")

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
RENDER_EXTERNAL_URL = os.getenv("RENDER_EXTERNAL_URL", "").strip().rstrip("/")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "").strip()
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_REPLY_CHARS = 3000

if not BOT_TOKEN:
    raise RuntimeError("Missing BOT_TOKEN environment variable.")
if not RENDER_EXTERNAL_URL.startswith("https://"):
    raise RuntimeError("Set RENDER_EXTERNAL_URL to the public HTTPS URL of this Render service.")
if not WEBHOOK_SECRET:
    WEBHOOK_SECRET = "html_decoder_" + re.sub(r"[^A-Za-z0-9_-]", "", BOT_TOKEN)[:40]
if not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", WEBHOOK_SECRET):
    raise RuntimeError("WEBHOOK_SECRET must contain only letters, numbers, '_' or '-'.")

telegram_app = Application.builder().token(BOT_TOKEN).build()
api = FastAPI(title="Telegram HTML Decoder Bot")


def menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🧹 Decode / Clean HTML", callback_data="decode"),
            InlineKeyboardButton("🔗 URL Decode", callback_data="url"),
        ],
        [
            InlineKeyboardButton("📚 Formats", callback_data="formats"),
            InlineKeyboardButton("ℹ️ Help", callback_data="help"),
        ],
    ])


def inspect_source(source: str) -> dict:
    source = source.lstrip("\ufeff")
    unescaped = html.unescape(source)
    soup = BeautifulSoup(unescaped, "html.parser")
    pretty = soup.prettify()
    scripts = [tag.get_text("\n", strip=False) for tag in soup.find_all("script")]
    styles = [tag.get_text("\n", strip=False) for tag in soup.find_all("style")]
    title = soup.title.get_text(" ", strip=True) if soup.title else ""

    markers = sorted(set(re.findall(
        r"\b(VAULT|salt|nonce|ciphertext|decrypt|encrypt|AES-GCM|AES-CBC|"
        r"PBKDF2|CryptoJS|SubtleCrypto|atob|btoa|obfuscat(?:e|ed|ion))\b",
        unescaped, re.IGNORECASE
    )))
    b64_candidates = re.findall(
        r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/=_-])",
        unescaped
    )
    readable_candidates = []
    for candidate in b64_candidates[:8]:
        try:
            decoded = base64.b64decode(candidate + "=" * ((4 - len(candidate) % 4) % 4))
            text = decoded.decode("utf-8")
            if text and sum(ch.isprintable() or ch in "\r\n\t" for ch in text) / len(text) > .9:
                readable_candidates.append(text[:1000])
        except Exception:
            pass
    return {
        "pretty": pretty,
        "scripts": scripts,
        "styles": styles,
        "title": title,
        "markers": markers,
        "b64": readable_candidates,
    }


async def send_text_or_file(message, text: str, filename: str) -> None:
    if len(text) <= MAX_REPLY_CHARS:
        await message.reply_text(text or "(কোনো ফলাফল নেই)")
    else:
        buf = BytesIO(text.encode("utf-8"))
        buf.name = filename
        await message.reply_document(document=buf, filename=filename)


async def run_decode(message, source: str, filename: str) -> None:
    result = inspect_source(source)
    report = (
        "✅ HTML inspection complete\n"
        f"📄 File: {filename}\n"
        f"🏷️ Title: {result['title'] or 'Not found'}\n"
        f"📜 Inline JS blocks: {len(result['scripts'])}\n"
        f"🎨 Inline CSS blocks: {len(result['styles'])}\n"
        "🔐 Security markers: " + (", ".join(result["markers"]) if result["markers"] else "none detected") +
        "\n\n⚠️ Formatting/Base64 inspection is not the same as decrypting encrypted data. "
        "AES-GCM data needs the correct password/key and matching algorithm."
    )
    await message.reply_text(report)
    await send_text_or_file(message, result["pretty"], "cleaned.html")
    if result["scripts"]:
        await send_text_or_file(message, "\n\n/* SCRIPT BLOCK */\n\n".join(result["scripts"]), "extracted.js")
    if result["styles"]:
        await send_text_or_file(message, "\n\n/* STYLE BLOCK */\n\n".join(result["styles"]), "extracted.css")
    if result["b64"]:
        await send_text_or_file(message, "\n\n--- readable Base64 candidate ---\n\n".join(result["b64"]), "base64-decoded.txt")


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_message:
        await update.effective_message.reply_text(
            "👋 HTML Decoder Bot-এ স্বাগতম!\n\n"
            "HTML/HTM/TXT ফাইল পাঠাও অথবা HTML text paste করো।\n"
            "আমি HTML entity decode, markup clean/format, inline JS/CSS extract, "
            "URL decode ও কিছু readable Base64 text পরীক্ষা করতে পারি।\n\n"
            "🔐 AES-GCM/PBKDF2-এর মতো encrypted content সঠিক key/password ছাড়া "
            "ডিক্রিপ্ট করা যায় না। আমি password crack করি না এবং uploaded JavaScript চালাই না।",
            reply_markup=menu(),
        )


async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await start(update, context)


async def buttons(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query:
        return
    await query.answer()
    if query.data == "url":
        context.user_data["mode"] = "url"
        await query.message.reply_text("URL-encoded text পাঠাও; আমি percent-encoding decode করব.")
    elif query.data == "formats":
        await query.message.reply_text(
            "Supported input: .html, .htm, .txt (max 2 MB), or pasted text.\n"
            "Available: HTML entities, formatting, JS/CSS extraction, URL decode, readable Base64 candidates."
        )
    elif query.data == "help":
        await query.message.reply_text("ফাইল পাঠাও অথবা HTML টেক্সট paste করো। /start দিয়ে মেনু ফেরত আনো।")
    else:
        context.user_data["mode"] = "html"
        await query.message.reply_text("এখন HTML/HTM/TXT ফাইল পাঠাও অথবা HTML text paste করো।")


async def text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    if not message or not message.text:
        return
    text_in = message.text
    if len(text_in.encode("utf-8")) > MAX_FILE_BYTES:
        await message.reply_text("টেক্সট ২ MB-এর বেশি। ছোট অংশে পাঠাও।")
        return
    if context.user_data.pop("mode", None) == "url":
        await send_text_or_file(message, unquote(text_in), "url-decoded.txt")
        return
    await run_decode(message, text_in, "pasted.html")


async def document_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    if not message or not message.document:
        return
    doc = message.document
    filename = doc.file_name or "upload.html"
    if Path(filename).suffix.lower() not in {".html", ".htm", ".txt"}:
        await message.reply_text("শুধু .html, .htm অথবা .txt ফাইল পাঠাও।")
        return
    if doc.file_size and doc.file_size > MAX_FILE_BYTES:
        await message.reply_text("ফাইল ২ MB-এর বেশি। ছোট ফাইল পাঠাও।")
        return
    tg_file = await context.bot.get_file(doc.file_id)
    raw = await tg_file.download_as_bytearray()
    if len(raw) > MAX_FILE_BYTES:
        await message.reply_text("ফাইল ২ MB-এর বেশি।")
        return
    await run_decode(message, bytes(raw).decode("utf-8", errors="replace"), filename)


telegram_app.add_handler(CommandHandler("start", start))
telegram_app.add_handler(CommandHandler("help", help_cmd))
telegram_app.add_handler(CallbackQueryHandler(buttons))
telegram_app.add_handler(MessageHandler(filters.Document.ALL, document_handler))
telegram_app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, text_handler))


@api.get("/")
async def health():
    return {"status": "ok", "service": "telegram-html-decoder-bot"}


@api.post("/webhook")
async def webhook(
    request: Request,
    x_telegram_bot_api_secret_token: Optional[str] = Header(default=None),
):
    if x_telegram_bot_api_secret_token != WEBHOOK_SECRET:
        raise HTTPException(status_code=403, detail="Invalid webhook secret")
    try:
        payload = await request.json()
        update = Update.de_json(payload, telegram_app.bot)
        await telegram_app.process_update(update)
    except Exception:
        logger.exception("Could not process Telegram update")
    return JSONResponse({"ok": True})


@api.on_event("startup")
async def startup():
    await telegram_app.initialize()
    await telegram_app.start()
    await telegram_app.bot.set_webhook(
        url=f"{RENDER_EXTERNAL_URL}/webhook",
        secret_token=WEBHOOK_SECRET,
        allowed_updates=Update.ALL_TYPES,
    )
    logger.info("Telegram webhook configured.")


@api.on_event("shutdown")
async def shutdown():
    await telegram_app.stop()
    await telegram_app.shutdown()
