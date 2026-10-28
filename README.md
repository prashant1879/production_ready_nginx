# A Hardened, Production-Ready Nginx Setup for Node.js APIs and Single-Page Apps

The moment you spin up a VPS, assign a public IP address, and open ports 80 and 443, automated bot networks start probing. They aren't specifically targeting *you*; they are running script scans across subnets looking for exposed `.env` files, open `.git` folders, legacy PHP endpoints, and unthrottled login routes to brute-force.

Default Nginx configurations are designed for speed and generic web serving out of the box. They are not built to defend your backend. If you're proxying traffic to a Node.js API alongside a single-page application (React, Vue, Svelte, Vite, etc.), relying on basic `proxy_pass` blocks leaves your infrastructure vulnerable to unnecessary compute load, credential stuffing, and secret leaks.

Here is a battle-tested, hardened Nginx virtual host template that seals common attack vectors, enforces rate limits, and optimizes connection reuse for Node.js backends.

---

## The Hardened Nginx Virtual Host Template

Replace `<project_name>` and `<yourdomain.com>` with your actual project details. Place this configuration inside `/etc/nginx/sites-available/<project_name>.conf` and symlink it to `/etc/nginx/sites-enabled/`.

```nginx
# ----------------------------------------------------------------------
# Rate Limiting Memory Zones
# Defined in the http context (or at the top of your server block file)
# ----------------------------------------------------------------------
limit_req_zone $binary_remote_addr zone=api_general_ip:10m rate=15r/s;
limit_req_zone $binary_remote_addr zone=auth_burst_ip:10m rate=2r/s;

# ----------------------------------------------------------------------
# Upstream Node.js Backend Definition
# ----------------------------------------------------------------------
upstream backend_api {
    server 127.0.0.1:5000; # Adjust to your internal Node.js backend port
    keepalive 32;          # Persistent connections reduce TCP handshake overhead
}

server {
    listen 80;
    listen 443 ssl http2;
    server_name admin.<yourdomain.com> api.<yourdomain.com> <yourdomain.com>;

    # SSL Certificates (Certbot / Cloudflare Origin CA)
    # ssl_certificate /etc/letsencrypt/live/<yourdomain.com>/fullchain.pem;
    # ssl_certificate_key /etc/letsencrypt/live/<yourdomain.com>/privkey.pem;

    # ------------------------------------------------------------------
    # 1. Drop Invalid Host Headers & Direct IP Scans
    # ------------------------------------------------------------------
    if ($host !~ ^(admin\.<yourdomain\.com>|api\.<yourdomain\.com>|<yourdomain\.com>)$ ) {
        return 444; # Drops connection instantly without sending response headers
    }

    # ------------------------------------------------------------------
    # 2. Allow Only Standard REST HTTP Methods
    # ------------------------------------------------------------------
    if ($request_method !~ ^(GET|POST|PUT|PATCH|DELETE|OPTIONS)$ ) {
        return 405; # Method Not Allowed
    }

    # ------------------------------------------------------------------
    # 3. Block Sensitive Dotfiles (.env, .git, .aws, etc.)
    # ------------------------------------------------------------------
    # Prevents SPA fallback rules from serving index.html for hidden file probes
    location ~ /\.(?!well-known).* {
        deny all;
        access_log off;
        log_not_found off;
        return 404;
    }

    # ------------------------------------------------------------------
    # 4. Block Web Exploit & Foreign Script Extensions
    # ------------------------------------------------------------------
    location ~* \.(php|sh|pl|cgi|py|asp|aspx|jsp|action)$ {
        deny all;
        access_log off;
        log_not_found off;
        return 404;
    }

    # ------------------------------------------------------------------
    # 5. Block Archive & Database Dump Access
    # ------------------------------------------------------------------
    location ~* \.(tar|tar\.gz|zip|rar|bak|7z|sql|old|backup)$ {
        deny all;
        access_log off;
        log_not_found off;
        return 404;
    }

    # ------------------------------------------------------------------
    # 6. Sensitive Authentication Endpoints (Strict Throttling)
    # ------------------------------------------------------------------
    location ~* ^/v1/(driver|customer|admin)/auth/(login|verify-otp|send-otp) {
        limit_req zone=auth_burst_ip burst=5 nodelay;
        limit_req_status 429;

        proxy_pass http://backend_api;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # ------------------------------------------------------------------
    # 7. General API Endpoints
    # ------------------------------------------------------------------
    location /v1/ {
        limit_req zone=api_general_ip burst=20 nodelay;
        limit_req_status 429;

        proxy_pass http://backend_api;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # ------------------------------------------------------------------
    # 8. Real-Time WebSockets / Socket.io Proxying
    # ------------------------------------------------------------------
    location /socket.io/ {
        proxy_pass http://backend_api;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
    }

    # ------------------------------------------------------------------
    # 9. Static Frontend Assets (Immutable Browser Cache)
    # ------------------------------------------------------------------
    location /assets/ {
        root /var/www/<project_name>/frontend/dist;
        expires 1y;
        add_header Cache-Control "public, immutable";
        try_files $uri =404;
    }

    # ------------------------------------------------------------------
    # 10. SPA Routing Catch-All
    # ------------------------------------------------------------------
    location / {
        root /var/www/<project_name>/frontend/dist;
        try_files $uri $uri/ /index.html;
    }
}

```

---

## Why These Specific Rules Matter in Production

### 1. The Power of Response Code `444`

When an attacker scans an IP range using raw IP addresses or mismatched host headers (e.g., `[http://192.0.2.1/](http://192.0.2.1/)`), standard web servers return a `404 Not Found` or `403 Forbidden` response. That still leaks header metadata, telling the attacker what software and web server version you are running.

Using `return 444;` forces Nginx to immediately close the connection without sending any response data back. To the scanner, the request times out or appears non-responsive, draining their resources and masking your server stack.

### 2. Fixing SPA Route Traps for Sensitive Files

When hosting client-side applications (like React or Vue), Nginx configs commonly use a catch-all route:

```nginx
try_files $uri $uri/ /index.html;

```

Without explicit block rules preceding it, requesting `https://<yourdomain.com>/.env` or `https://<yourdomain.com>/backup.sql` matches no static file on disk. Nginx then silently falls back to serving `index.html` with an HTTP status `200 OK`.

While your `.env` isn't leaked directly, automated security tools flag this as an anomaly, log false positives, and obscure actual attack attempts. The explicit regex rules for dotfiles (`/\.(?!well-known).*`), dangerous scripts (`.php`, `.py`), and database dumps (`.sql`, `.tar.gz`) force hard `404` responses long before the SPA fallback gets evaluated.

### 3. Semantically Correct Rate Limiting (`429` over `503`)

By default, Nginx throws an `HTTP 503 Service Unavailable` when rate limits are exceeded. A 503 error implies server failure or downtime, causing monitoring systems to trigger false alarms.

By setting `limit_req_status 429;`, Nginx sends an explicit `429 Too Many Requests` code back to the client. This allows frontends and mobile SDKs to handle throttling correctly (e.g., triggering back-off timers) while differentiating server outages from rate enforcement.

* **Auth Endpoints (`auth_burst_ip`):** Throttled down to `2r/s` with a burst threshold of `5`. This stops brute-force OTP attempts, login credential stuffing, and SMS gateway drain on routes like `/v1/customer/auth/send-otp`.
* **General API Endpoints (`api_general_ip`):** Capped at `15r/s` with a burst of `20`, ensuring standard user navigation remains smooth while preventing aggressive scraping scripts.

### 4. Eliminating the Node.js TCP Bottleneck

Every HTTP request proxied to Node.js usually requires opening a temporary socket. Under high request volume, this creates TCP connection churn and consumes ephemeral ports unnecessarily.

By setting `upstream backend_api` with `keepalive 32;` alongside `proxy_http_version 1.1;` and clearing the connection header (`proxy_set_header Connection "";`), Nginx keeps a persistent pool of open TCP sockets to your Node server. This reduces latency by eliminating constant socket handshakes.

### 5. WebSocket Header Upgrades

Real-time layers like Socket.io start as HTTP polling before attempting a protocol upgrade. Without explicit `Upgrade` and `Connection "Upgrade"` headers, Nginx drops the handshake, forcing your application to fall back to inefficient HTTP long-polling.

Setting `proxy_read_timeout 60s;` and `proxy_send_timeout 60s;` ensures idle connections aren't dropped prematurely while preventing dead connections from consuming system resources indefinitely.

---

## Safe Reload Workflow

Never reload Nginx on a live host without validating the syntax first. A single missing semicolon will take down all hosted virtual servers.

```bash
# Step 1: Check configuration syntax
sudo nginx -t

```

Look for confirmation:

```text
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful

```

Once validated, perform a zero-downtime reload:

```bash
# Step 2: Reload worker processes without dropping active connections
sudo systemctl reload nginx

```

Using `reload` instead of `restart` gracefully transitions active worker threads to the new configuration without dropping existing active connections.

---
