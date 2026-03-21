# SKYLINE — Authentication & Licensing System

A self-hosted, KeyAuth-compatible authentication and licensing backend built with Python/Flask and MongoDB.  
Drop in any official KeyAuth SDK (Python, C#, C++, Java) and it works without modification.

---

## Features

- **Full KeyAuth API compatibility** — every SDK action works out of the box
- **License system** — create, activate, and expire license keys
- **User registration** — username + password + license key
- **HWID locking** — bind a license to a specific machine
- **Session management** — secure per-session tokens with configurable TTL
- **HMAC-SHA256 response signing** — tamper-proof responses
- **Discord webhooks** — per-app event notifications (login, register, license, errors)
- **Real-time chat** — internal admin/reseller messaging via WebSockets
- **Multi-role dashboard** — superadmin → admin → reseller hierarchy
- **Reseller system** — resellers buy credits and generate license keys
- **Announcements** — pinned and regular staff announcements

---

## Requirements

- Python 3.10+
- MongoDB Atlas (free tier works) or self-hosted MongoDB
- Replit, a VPS, or any server that can run Python

---

## Quick Start (Replit)

1. Fork or import this repo into Replit
2. Set the following secrets in the Replit Secrets panel:

| Secret | Description |
|--------|-------------|
| `MONGO_URI` | Your MongoDB connection string |
| `SECRET_KEY` | Any long random string for Flask sessions |

3. Click **Run** — the dashboard will be available on port 5000
4. Visit the app and register your superadmin account on first launch

---

## Local Setup

```bash
git clone https://github.com/srirevanthnu18/SKYLINEAUTHV3.git
cd SKYLINEAUTHV3

# Copy the example environment file
cp .env.example .env
# Edit .env and fill in your MONGO_URI and SECRET_KEY

pip install -r requirements.txt
python app.py
```

---

## Environment Variables

Copy `.env.example` to `.env` and fill in the values.

| Variable | Required | Description |
|----------|----------|-------------|
| `MONGO_URI` | Yes | MongoDB connection string |
| `SECRET_KEY` | Yes | Flask session secret key |
| `DATABASE_NAME` | No | MongoDB database name (default: `skyline`) |
| `DISCORD_WEBHOOK_URL` | No | Global system log Discord webhook |
| `DISCORD_BOT_TOKEN` | No | Discord management bot token |
| `DISCORD_OWNER_ID` | No | Discord user ID of the bot owner |
| `MGMT_SECRET` | No | Shared secret for bot↔panel API |

---

## API Endpoint

```
POST /api/1.2/
```

All SDK actions are sent to this single endpoint via `type=` parameter.

### Supported Actions

| `type` | Description |
|--------|-------------|
| `init` | Initialize session, check app version |
| `login` | Authenticate with username + password |
| `register` | Create account using a license key |
| `license` | Authenticate with a license key directly |
| `upgrade` | Add time to an existing subscription |
| `check` | Verify session is still valid |
| `log` | Send a log entry to the dashboard |
| `var` | Retrieve a server-side variable |
| `checkblacklist` | Check if HWID/IP is banned |
| `fetchOnline` | Get list of currently online users |
| `fetchStats` | Get app statistics |
| `ban` | Self-ban (kick from session) |
| `logout` | Invalidate the current session |
| `chatget` | Fetch chat messages from a channel |
| `chatsend` | Send a chat message to a channel |

### Response Format

Every response is JSON with an HMAC-SHA256 `signature` header:

```json
{
  "success": true,
  "message": "Logged in!",
  "sessionid": "abc123...",
  "info": {
    "username": "john",
    "ip": "1.2.3.4",
    "hwid": "123456789",
    "createdate": "1700000000",
    "lastlogin": "1700001000",
    "subscriptions": [
      {
        "subscription": "Premium",
        "expiry": "1732000000",
        "timeleft": "86400"
      }
    ]
  }
}
```

---

## SDK Examples

Pre-configured SDK files are generated automatically from the dashboard  
(**Apps → Manage → Download SDK**). The examples below use placeholder values.

### Python

```python
import sdk as KeyAuthApp

if not KeyAuthApp.init():
    print("Init failed:", KeyAuthApp.response.message)
    exit()

# Login with username + password
if KeyAuthApp.login("john", "mypassword"):
    print("Welcome,", KeyAuthApp.user_data.username)
    subs = KeyAuthApp.user_data.subscriptions
    if subs:
        print("Plan:", subs[0]["subscription"], "| Expires:", subs[0]["expiry"])
else:
    print("Login failed:", KeyAuthApp.response.message)

# --- OR ---

# Register a new account using a license key
if KeyAuthApp.register("john", "mypassword", "SKYLINE-XXXX-XXXX-XXXX"):
    print("Registered and logged in!")

# --- OR ---

# License-only authentication (no username/password)
if KeyAuthApp.license("SKYLINE-XXXX-XXXX-XXXX"):
    print("License accepted!")
```

### C#

```csharp
using System;

class Program
{
    static void Main()
    {
        var api = new KeyAuth.api(
            name: "MyApp",
            ownerid: "your_ownerid",
            secret: "your_secret",
            version: "1.0",
            url: "https://your-app.replit.app/api/1.2"
        );

        api.init();
        if (!api.response.success)
        {
            Console.WriteLine("Init failed: " + api.response.message);
            return;
        }

        // Login
        api.login("john", "mypassword");
        if (api.response.success)
        {
            Console.WriteLine("Welcome, " + api.user_data.username);
            foreach (var sub in api.user_data.subscriptions)
                Console.WriteLine("Plan: " + sub.subscription + " expires " + sub.expiry);
        }
        else
        {
            Console.WriteLine("Login failed: " + api.response.message);
        }
    }
}
```

### C++

```cpp
#include "KeyAuth.hpp"
#include <iostream>

int main() {
    KeyAuth::api api(
        "MyApp",          // name
        "your_ownerid",   // ownerid
        "your_secret",    // secret
        "1.0",            // version
        "https://your-app.replit.app/api/1.2"
    );

    api.init();
    if (!api.response.success) {
        std::cout << "Init failed: " << api.response.message << std::endl;
        return 1;
    }

    // Login
    api.login("john", "mypassword");
    if (api.response.success) {
        std::cout << "Welcome, " << api.user_data.username << std::endl;
    } else {
        std::cout << "Login failed: " << api.response.message << std::endl;
    }
    return 0;
}
```

### Java

```java
import java.net.*;
import java.net.http.*;
import java.util.*;
import com.google.gson.*;

public class SkylineExample {

    static final String API_URL  = "https://your-app.replit.app/api/1.2/";
    static final String APP_NAME = "MyApp";
    static final String OWNER_ID = "your_ownerid";
    static final String SECRET   = "your_secret";
    static final String VERSION  = "1.0";

    static String sessionId = null;

    public static void main(String[] args) throws Exception {
        if (!init()) { System.out.println("Init failed"); return; }

        // Login
        JsonObject result = post(Map.of(
            "type", "login",
            "username", "john",
            "pass", "mypassword",
            "hwid", getHwid(),
            "sessionid", sessionId,
            "name", APP_NAME,
            "ownerid", OWNER_ID
        ));

        if (result.get("success").getAsBoolean()) {
            JsonObject info = result.getAsJsonObject("info");
            System.out.println("Welcome, " + info.get("username").getAsString());
            JsonArray subs = info.getAsJsonArray("subscriptions");
            if (subs.size() > 0) {
                JsonObject sub = subs.get(0).getAsJsonObject();
                System.out.println("Plan: " + sub.get("subscription").getAsString());
            }
        } else {
            System.out.println("Login failed: " + result.get("message").getAsString());
        }
    }

    static boolean init() throws Exception {
        String hwid = getHwid();
        JsonObject res = post(Map.of(
            "type", "init",
            "name", APP_NAME,
            "ownerid", OWNER_ID,
            "ver", VERSION,
            "enckey", hwid
        ));
        if (res.get("success").getAsBoolean()) {
            sessionId = res.get("sessionid").getAsString();
            return true;
        }
        return false;
    }

    static String getHwid() {
        try {
            return NetworkInterface.getNetworkInterfaces()
                .nextElement().getHardwareAddress() != null
                ? Arrays.toString(NetworkInterface.getNetworkInterfaces()
                    .nextElement().getHardwareAddress())
                : "unknown";
        } catch (Exception e) { return "unknown"; }
    }

    static JsonObject post(Map<String, String> params) throws Exception {
        StringBuilder body = new StringBuilder();
        for (var e : params.entrySet()) {
            if (body.length() > 0) body.append("&");
            body.append(URLEncoder.encode(e.getKey(), "UTF-8"))
                .append("=")
                .append(URLEncoder.encode(e.getValue(), "UTF-8"));
        }
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(API_URL))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
            .build();
        HttpResponse<String> res = HttpClient.newHttpClient()
            .send(req, HttpResponse.BodyHandlers.ofString());
        return JsonParser.parseString(res.body()).getAsJsonObject();
    }
}
```

> **Java dependency:** add `com.google.code.gson:gson:2.10.1` to your `pom.xml` or Gradle build.

---

## Dashboard Guide

### First Login

On first launch, visit the app and register a **superadmin** account.

### Creating an App

1. Go to **Apps** → **Create Application**
2. Copy the **Name**, **Secret**, and **Owner ID** shown
3. Use these in your SDK initializer

### Creating Licenses

1. Go to **Users** → select your app → **Create**
2. Choose a **package** (sets how long the license lasts)
3. Leave username blank to generate a bare license key, or fill it in to pre-create a user account

### Resellers

1. Create a reseller account under **Admins**
2. Assign packages and credits to the reseller
3. The reseller logs in and can create licenses using their credits

---

## Security Notes

- All API responses are signed with HMAC-SHA256 using the app's secret key
- Sessions expire automatically (configurable per-app, default 1 hour)
- HWID locking prevents license sharing between machines
- Passwords are hashed with Werkzeug's `generate_password_hash` (PBKDF2-SHA256)
- License keys and user accounts are stored in separate logical roles (`is_license` flag)

---

## Production Deployment

```bash
gunicorn --worker-class=eventlet -w 1 --bind=0.0.0.0:5000 --timeout=120 app:application
```

Or use the Replit **Deploy** button for a one-click production URL.

---

## License

This project is open source and provided as-is for educational and personal use.  
Do not resell this software as a service.
