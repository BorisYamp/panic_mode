/// Path: PanicMode/QUICKSTART.md
# PanicMode Quick Start - All Integrations

## Setup Guide for All Channels

### 🔵 Telegram (FREE - 2 minutes)

**Why:** Instant, reliable, works worldwide, no cost

1. Open Telegram, search for `@BotFather`
2. Send: `/newbot`
3. Follow instructions, save the **bot token**
4. Message your bot anything
5. Get your chat ID:
```bash
   curl https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates
```
6. Find `"chat":{"id":123456789}` in the response

**Config:**
```yaml
telegram:
  enabled: true
  bot_token: "YOUR_TOKEN_FROM_BOTFATHER"
  chat_id: "YOUR_CHAT_ID"
```

---

### 📧 Email (FREE - 3 minutes)

**Why:** Universal, always works, good backup

#### Gmail Setup:
1. Enable 2FA: https://myaccount.google.com/security
2. Get App Password: https://myaccount.google.com/apppasswords
3. Create new app password (select "Mail" and your device)
4. Copy the 16-character password

**Config:**
```yaml
email:
  enabled: true
  smtp_host: "smtp.gmail.com"
  smtp_port: 587
  smtp_username: "your.email@gmail.com"
  smtp_password: "xxxx xxxx xxxx xxxx"  # App password
  from_email: "your.email@gmail.com"
  to_email: "alert@example.com"
  use_tls: true
```

#### Other Providers:

**Outlook/Hotmail:**
```yaml
smtp_host: "smtp-mail.outlook.com"
smtp_port: 587
```

**Yahoo:**
```yaml
smtp_host: "smtp.mail.yahoo.com"
smtp_port: 587
```

**ProtonMail Bridge (self-hosted):**
```yaml
smtp_host: "127.0.0.1"
smtp_port: 1025
use_tls: false
```

---

### 🔔 Ntfy (FREE - 1 minute)

**Why:** Persistent push, works offline, self-hostable

1. Visit https://ntfy.sh
2. Pick a unique topic: `myserver-RANDOM123`
3. Subscribe in app or bookmark URL
4. Done!

**Config:**
```yaml
ntfy:
  enabled: true
  server: "https://ntfy.sh"
  topic: "myserver-RANDOM123"  # Make it unique!
```

**Pro tip:** Self-host for privacy:
```bash
docker run -p 80:80 binwiederhier/ntfy serve
```

---

### 💬 Discord (FREE - 2 minutes)

**Why:** Great for teams, visual, free forever

1. Open Discord server settings
2. Integrations → Webhooks → New Webhook
3. Copy webhook URL
4. Paste in config

**Config:**
```yaml
discord:
  enabled: true
  webhook_url: "https://discord.com/api/webhooks/123/abc..."
```

---

### 📞 Twilio (PAID - 5 minutes, ~$1-2/month)

**Why:** PHONE CALLS wake you up for critical issues

**Cost breakdown:**
- Phone number: $1/month
- Calls: $0.013/minute (~$0.03 per 2-minute call)
- SMS: $0.0075/message
- **Example:** 10 emergencies/month = $1.30 total

**Setup:**
1. Sign up: https://www.twilio.com/try-twilio
2. Get phone number (Console → Phone Numbers → Buy a number)
3. Get credentials (Console → Account → API credentials)
4. Copy Account SID, Auth Token, and phone number

**Config:**
```yaml
twilio:
  enabled: true
  account_sid: "ACxxxxxxxxxxxxxxxx"
  auth_token: "your_auth_token"
  from_number: "+12345678901"

# In alerts section:
critical:
  - channel: "twilio_call"
    contacts:
      - name: "You"
        phone: "+1YOUR_PHONE"
        retries: 3
```

**Budget tip:** Use only for critical alerts, disable for warnings

---

## Quick Test Setup

### Minimal (Telegram only):
```yaml
performance:
  cpu_limit: 5.0
  memory_limit_mb: 50
  check_interval: "5s"

monitors:
  - name: "Test Alert"
    type: "cpu_usage"
    threshold: 1      # Triggers immediately
    duration: "5s"
    actions: [alert_critical]

actions: {}

alerts:
  critical:
    - channel: "telegram"
      chat_id: "YOUR_CHAT_ID"

integrations:
  telegram:
    enabled: true
    bot_token: "YOUR_TOKEN"
    chat_id: "YOUR_CHAT_ID"
```

### Full Stack (All channels):

Use `examples/basic.yaml` and fill in ALL integrations!

---

## Build & Run
```bash
# Build
cargo build --release

# Install both binaries
sudo cp target/release/panicmode /usr/local/bin/
sudo cp target/release/panicmode-ctl /usr/local/bin/

# Run (will send test alerts immediately with threshold: 1)
sudo ./target/release/panicmode examples/basic.yaml
```

---

## Testing Each Channel

### Test Telegram:
Set CPU threshold to 1%, should alert immediately

### Test Email:
Check spam folder if not receiving!

### Test Ntfy:
Visit https://ntfy.sh/YOUR_TOPIC in browser

### Test Discord:
Check your webhook channel

### Test Twilio:
**Warning:** This will CALL YOU!
Set threshold low and wait for alert

---

## Recommended Setup Strategies

### Strategy 1: Free Only (Recommended for most)
- ✅ Telegram (primary)
- ✅ Email (backup)
- ✅ Ntfy (persistent)
- ❌ Twilio (disabled)

### Strategy 2: Critical Infrastructure
- ✅ All channels enabled
- ✅ Twilio calls for critical only
- ✅ Telegram + Email for warnings

### Strategy 3: Team Setup
- ✅ Discord (main team channel)
- ✅ Telegram (individual alerts)
- ✅ Email (audit trail)

### Strategy 4: Paranoid (Maximum Redundancy)
- ✅ Everything enabled
- ✅ Multiple contact phones
- ✅ Self-hosted Ntfy
- ✅ Custom webhook to your monitoring

---

## Cost Comparison

| Channel  | Setup Time | Monthly Cost | Reliability | Wake You Up? |
|----------|------------|--------------|-------------|--------------|
| Telegram | 2 min      | $0           | ⭐⭐⭐⭐⭐   | ✅ (with sound) |
| Email    | 3 min      | $0           | ⭐⭐⭐⭐     | ❌ (unless watching) |
| Ntfy     | 1 min      | $0           | ⭐⭐⭐⭐⭐   | ✅ (push) |
| Discord  | 2 min      | $0           | ⭐⭐⭐⭐     | ✅ (if watching) |
| Twilio   | 5 min      | $1-2         | ⭐⭐⭐⭐⭐   | ✅✅ (PHONE CALL) |

---

## Troubleshooting

### Telegram not working:
- Check bot token is correct
- Make sure you messaged the bot first
- Verify chat_id is a number (not username)

### Email not working:
- Check spam folder
- For Gmail: use App Password, not regular password
- Enable "Less secure app access" if needed
- Check SMTP port (587 for TLS, 465 for SSL)

### Ntfy not working:
- Topic must be unique (someone else might use it)
- Try adding random numbers: `myserver-479281`
- Check server URL includes https://

### Discord not working:
- Webhook URL must be complete
- Check channel permissions
- Test webhook with curl first

### Twilio not working:
- Verify phone number has SMS/Voice capabilities
- Check account balance
- Numbers must include country code (+1 for US)

---

## Security Best Practices

1. **Never commit credentials to git**
```bash
   echo "config.yaml" >> .gitignore
```

2. **Use environment variables (optional)**
```bash
   export TELEGRAM_TOKEN="..."
   export TWILIO_TOKEN="..."
```

3. **Restrict config file permissions**
```bash
   chmod 600 /etc/panicmode/config.yaml
```

4. **Use unique Ntfy topics**
   - Don't use common names
   - Add random suffix

5. **Rotate credentials regularly**
   - Regenerate bot tokens yearly
   - Update app passwords

---

## Next Steps

- ✅ Set up all integrations
- ✅ Test each channel
- ✅ Adjust thresholds for your server
- ✅ Install as systemd service
- ✅ Monitor PanicMode logs
- ✅ Review `examples/advanced.yaml` for more features