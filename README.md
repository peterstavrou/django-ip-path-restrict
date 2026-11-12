# Django IP Path Restrict

[![Tests](https://github.com/peterstavrou/django-ip-path-restrict/actions/workflows/release.yml/badge.svg)](https://github.com/peterstavrou/django-ip-path-restrict/actions/workflows/release.yml) [![PyPI](https://img.shields.io/pypi/v/django-ip-path-restrict)](https://pypi.org/project/django-ip-path-restrict/) [![MIT License](https://img.shields.io/badge/license-MIT-9d9d9d)](https://github.com/peterstavrou/django-ip-path-restrict/blob/main/LICENSE)

Restrict access to specific URLs so that only users with whitelisted IP addresses can access them.

Supports IPv4 and IPv6 addresses, IP ranges, and optional Cloudflare support.

Restrict access to specific URLs so that only users with whitelisted IP addresses can access them.

Supports IPv4 and IPv6 addresses, IP ranges, and optional Cloudflare support.

## Requirements

- Python 3.11+
- Django 5.2+

## Installation

```bash
pip install django-ip-path-restrict
```

In the `settings.py` file, add the middleware near the top of `MIDDLEWARE`, preferably immediately after `SecurityMiddleware`:

```python
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django_ip_path_restrict.middleware.RestrictPathsByIPMiddleware',
    # Other middleware...
]
```

Placing the middleware near the top allows unauthorised requests to be blocked early, before other middleware processes them.

## Configuration

Add `PROTECTED_PATHS` to `settings.py` to specify which URLs to restrict based on IP addresses.

```python
PROTECTED_PATHS = [
    '/admin/*',  # * matches /admin/ and all paths under it
    '/login/',   # Only matches /login/
]
```

Add `ALLOWED_IPS` to specify which IP addresses are allowed to access the protected URLs.

IPv4, IPv6 and CIDR IP ranges are supported:

```python
ALLOWED_IPS = [
    '203.0.113.10',    # IPv4 address
    '2001:db8::10',    # IPv6 address
    '198.51.100.0/24', # IPv4 address range
]
```

Replace these example IP addresses with the addresses you want to allow.

Users who try to access protected URLs from an IP address that is not in `ALLOWED_IPS` will receive a 404 Not Found response.

All other URLs remain accessible as normal.

If your project already uses django-environ or another settings library, you can load `ALLOWED_IPS` from an environment variable instead.

### Local development

IP restrictions apply regardless of `DEBUG`. To access protected URLs locally, add the localhost IP addresses to `ALLOWED_IPS` in your development settings:

```python
ALLOWED_IPS = [
    '127.0.0.1',  # IPv4 localhost
    '::1',        # IPv6 localhost
]
```

Keep these addresses in your development settings rather than adding them to your production allowlist.

## Path matching


| Pattern | Paths matched |
| --- | --- |
| `/admin` | `/admin` only |
| `/admin/` | `/admin/` only |
| `/admin/*` | `/admin/` and all paths under it, but not `/admin` |
| `/admin*` | All paths starting with `/admin`, including `/administration` |


For a standard Django admin installation, use `/admin/*`.

The only supported wildcard is `*`, which must appear at the end of a path.

## Use with a reverse proxy

When Nginx, Apache, LiteSpeed, or another reverse proxy sits in front of Django, `REMOTE_ADDR` may contain the proxy's IP address instead of the visitor's IP address.

Add the IP addresses of trusted reverse proxies to `IP_RESTRICT_TRUSTED_PROXY_IPS` in `settings.py`:

```python
IP_RESTRICT_TRUSTED_PROXY_IPS = [
    '127.0.0.1',  # IPv4 localhost
    '::1',        # IPv6 localhost
]
```

These addresses are for reverse proxies running on the same server as Django. If your proxy runs on another server, use its IP address instead.

The middleware only trusts `X-Real-IP` when `REMOTE_ADDR` belongs to a trusted proxy. Otherwise, the header is ignored. If a trusted proxy does not provide a valid `X-Real-IP`, access to protected URLs is denied.

For Nginx, add the following line to the location block that forwards requests to Django:

```nginx
proxy_set_header X-Real-IP $remote_addr;
```

Do not add `0.0.0.0/0` or `::/0` to `IP_RESTRICT_TRUSTED_PROXY_IPS`. Ensure the Django application server is not directly accessible from untrusted networks.

This feature supports TCP-connected proxies, not Unix sockets.

## Use with Cloudflare

Without Cloudflare or another reverse proxy, Django normally receives the visitor's IP address directly.

When your domain's DNS record is set to **Proxied** (orange cloud) in Cloudflare, your server receives a Cloudflare IP address instead of the visitor's IP address.

Cloudflare includes the visitor's original IP address in the `CF-Connecting-IP` request header.

Without the Cloudflare configuration, `ALLOWED_IPS` cannot match the real visitor because Django only sees Cloudflare's IP address.

The middleware uses Cloudflare's IP ranges to verify that the connecting IP address belongs to Cloudflare before trusting `CF-Connecting-IP`. It never trusts `X-Forwarded-For` and ignores spoofed `CF-Connecting-IP` headers from other sources.

If Cloudflare sits in front of Nginx or another reverse proxy, configure `IP_RESTRICT_TRUSTED_PROXY_IPS` first. The middleware verifies the Cloudflare IP received through that trusted proxy before reading `CF-Connecting-IP`.

To use the Cloudflare IP update command, add `django_ip_path_restrict` to `INSTALLED_APPS` in `settings.py`:

```python
INSTALLED_APPS = [
    # Existing apps...
    'django_ip_path_restrict',
]
```

Adding the package to `INSTALLED_APPS` is not required if you only use the middleware.

### Configure the cache file

Set a location where the package can save Cloudflare's IP ranges. This should be outside publicly accessible directories such as `static` and `media`.

If the directory doesn't exist, the package will create it automatically.

```python
CLOUDFLARE_IPS_FILE = BASE_DIR / 'private' / 'cloudflare_ips.json'
```

### Download Cloudflare IP ranges

The package does not include Cloudflare's IP ranges. Run the following command after installation to download them:

```bash
python manage.py update_cloudflare_ips
```

### Schedule daily updates

You can use a cron job to update Cloudflare's IP ranges automatically once per day.

**Linux (crontab)**

```cron
0 4 * * * cd /home/USER/project && /home/USER/project/.venv/bin/python manage.py update_cloudflare_ips >> /home/USER/cloudflare_update.log 2>&1
```

**cPanel**

In cPanel, go to **Advanced > Cron Jobs** and set the schedule to run daily at 4:00 AM.

Enter the following in the Command field:

```bash
cd /home/USER/project && /home/USER/virtualenv/project/3.12/bin/python manage.py update_cloudflare_ips >> /home/USER/cloudflare_update.log 2>&1
```

Replace the example paths with your actual project and virtual environment paths.

### Automatic updates (optional)

If you cannot schedule updates using a cron job, you can enable automatic updates when a protected URL is accessed:

```python
CLOUDFLARE_IPS_AUTO_UPDATE = True
```

With this setting enabled, the next request to a protected URL attempts to download Cloudflare's IP ranges if the cache file is missing, invalid, or more than 24 hours old. The request may take longer due to the download, which has a five-second timeout.

If the download fails and no valid cache file is available, requests relying on Cloudflare IP detection will be blocked.

### Share Cloudflare IP ranges between sites on the same server

Set each site's `CLOUDFLARE_IPS_FILE` to the same shared cache file, outside directories publicly accessible by your websites. Each site reads the file directly and automatically detects when it has been updated.

```python
CLOUDFLARE_IPS_FILE = '/home/USER/private/cloudflare_ips.json'
```

Run `update_cloudflare_ips` once per day from one site's virtual environment. It safely updates the shared file, preventing other sites from reading incomplete data.

## Author

Created by [Peter Stavrou](https://peterstavrou.com/).