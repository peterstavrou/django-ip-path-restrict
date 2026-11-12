"""Cloudflare IP range caching and on-request updates."""

import json
import os
import time
from ipaddress import ip_network
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.request import Request, urlopen

API_URL = 'https://api.cloudflare.com/client/v4/ips'
UPDATE_INTERVAL_SECONDS = 86400 # Default: 24 hours
IP_VERSIONS = {
    'ipv4_cidrs': 4,
    'ipv6_cidrs': 6,
}


def validate_ip_ranges(ip_range_data):
    """Validate IPv4 and IPv6 ranges and normalize them for storage."""
    if not isinstance(ip_range_data, dict):
        raise ValueError('Expected a dictionary containing Cloudflare IP ranges')

    validated_ip_ranges = {}

    for ip_range_key, expected_ip_version in IP_VERSIONS.items():
        ip_ranges = ip_range_data.get(ip_range_key)

        if not isinstance(ip_ranges, list) or not ip_ranges:
            raise ValueError(
                f'Cloudflare response has no valid {ip_range_key}'
            )

        ip_networks = [
            ip_network(ip_range, strict=True)
            for ip_range in ip_ranges
        ]

        if any(
            network.version != expected_ip_version
            for network in ip_networks
        ):
            raise ValueError(f'Invalid address family in {ip_range_key}')

        validated_ip_ranges[ip_range_key] = [str(network) for network in ip_networks]

    return validated_ip_ranges


def fetch_cloudflare_ranges():
    """Fetch IP ranges from Cloudflare's public API."""
    request_headers = {'User-Agent': 'django-ip-path-restrict/1.0.0'}

    with urlopen(
        Request(API_URL, headers=request_headers), timeout=5
    ) as api_response:
        api_response_data = json.load(api_response)

    if not api_response_data.get('success'):
        raise ValueError('Cloudflare API returned an unsuccessful response')

    return validate_ip_ranges(api_response_data.get('result'))


def save_cloudflare_ranges(cache_file_path, ip_ranges):
    """Save validated IP ranges without leaving an incomplete cache file."""
    validated_ip_ranges = validate_ip_ranges(ip_ranges)
    cache_file_path = Path(cache_file_path)
    cache_file_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_file_path = None

    try:
        with NamedTemporaryFile(
            mode='w',
            encoding='utf-8',
            dir=cache_file_path.parent,
            prefix='.cloudflare_ips_',
            suffix='.tmp',
            delete=False,
        ) as temporary_file:
            temporary_file_path = Path(temporary_file.name)
            json.dump(validated_ip_ranges, temporary_file, indent=2)
            temporary_file.write('\n')

        os.replace(temporary_file_path, cache_file_path)
    finally:
        if temporary_file_path is not None:
            temporary_file_path.unlink(missing_ok=True)


def download_and_save(cache_file_path):
    """Download Cloudflare ranges and safely replace the cache file."""
    cloudflare_ip_ranges = fetch_cloudflare_ranges()
    save_cloudflare_ranges(cache_file_path, cloudflare_ip_ranges)
    return (
        len(cloudflare_ip_ranges['ipv4_cidrs'])
        + len(cloudflare_ip_ranges['ipv6_cidrs'])
    )


class CloudflareIPStore:
    """Load cached Cloudflare ranges and refresh them once every 24 hours."""

    def __init__(self, cache_file_path):
        self.cache_file_path = Path(cache_file_path)
        self._cached_networks = ()
        self._cache_file_modified_time_nanoseconds = None
        self._last_update_attempt = 0

    @staticmethod
    def _load_file(cache_file_path):
        with Path(cache_file_path).open(encoding='utf-8') as cache_file:
            return validate_ip_ranges(json.load(cache_file))

    @staticmethod
    def _to_networks(ip_ranges):
        ip_range_strings = ip_ranges['ipv4_cidrs'] + ip_ranges['ipv6_cidrs']
        return tuple(ip_network(ip_range) for ip_range in ip_range_strings)

    def get_networks(self):
        """Reload a changed cache file and fail closed when it is unavailable."""
        try:
            cache_file_modified_time_nanoseconds = self.cache_file_path.stat().st_mtime_ns
        except OSError:
            self._cached_networks = ()
            self._cache_file_modified_time_nanoseconds = None
            return self._cached_networks

        if cache_file_modified_time_nanoseconds != self._cache_file_modified_time_nanoseconds:
            try:
                cached_ip_ranges = self._load_file(self.cache_file_path)
            except (OSError, TypeError, ValueError):
                self._cached_networks = ()
            else:
                self._cached_networks = self._to_networks(cached_ip_ranges)

            self._cache_file_modified_time_nanoseconds = cache_file_modified_time_nanoseconds

        return self._cached_networks

    def refresh_if_stale(self):
        """Refresh a missing, invalid, or 24-hour-old cache on the next request."""
        cached_networks = self.get_networks()
        try:
            cache_age = time.time() - self.cache_file_path.stat().st_mtime
        except OSError:
            cache_age = UPDATE_INTERVAL_SECONDS

        if cached_networks and cache_age < UPDATE_INTERVAL_SECONDS:
            return

        current_time = time.time()
        if current_time - self._last_update_attempt < UPDATE_INTERVAL_SECONDS:
            return

        self._last_update_attempt = current_time

        try:
            download_and_save(self.cache_file_path)
        except Exception:
            return

        self.get_networks()