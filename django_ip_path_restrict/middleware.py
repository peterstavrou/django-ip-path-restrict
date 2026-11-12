from ipaddress import ip_address, ip_network

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http import Http404

from .cloudflare import CloudflareIPStore


class RestrictPathsByIPMiddleware:
    """Restrict configured Django URL paths to an IP allowlist."""

    def __init__(self, get_response):
        self.get_response = get_response
        self.protected_paths = tuple(getattr(settings, 'PROTECTED_PATHS', []))
        self._validate_protected_paths()

        allowed_ip_ranges = getattr(settings, 'ALLOWED_IPS', [])

        try:
            self.allowed_networks = tuple(
                ip_network(allowed_ip_range, strict=False)
                for allowed_ip_range in allowed_ip_ranges
            )
        except (TypeError, ValueError) as configuration_error:
            raise ImproperlyConfigured(
                'ALLOWED_IPS must contain valid IPv4 or IPv6 addresses or CIDR ranges.'
            ) from configuration_error

        trusted_proxy_ip_ranges = getattr(settings, 'IP_RESTRICT_TRUSTED_PROXY_IPS', [])
        try:
            self.trusted_proxy_networks = tuple(
                ip_network(trusted_proxy_ip_range, strict=False)
                for trusted_proxy_ip_range in trusted_proxy_ip_ranges
            )
        except (TypeError, ValueError) as configuration_error:
            raise ImproperlyConfigured(
                'IP_RESTRICT_TRUSTED_PROXY_IPS must contain valid IPv4 or IPv6 addresses or CIDR ranges.'
            ) from configuration_error

        if any(network.prefixlen == 0 for network in self.trusted_proxy_networks):
            raise ImproperlyConfigured(
                'IP_RESTRICT_TRUSTED_PROXY_IPS cannot contain 0.0.0.0/0 or ::/0.'
            )

        cache_file_path = getattr(settings, 'CLOUDFLARE_IPS_FILE', None)
        self.cloudflare_ips_auto_update = getattr(settings, 'CLOUDFLARE_IPS_AUTO_UPDATE', False)
        self.cloudflare_ip_store = None

        if cache_file_path:
            self.cloudflare_ip_store = CloudflareIPStore(cache_file_path)

    def _validate_protected_paths(self):
        for protected_path in self.protected_paths:
            if not isinstance(protected_path, str) or not protected_path.startswith('/'):
                raise ImproperlyConfigured(
                    'PROTECTED_PATHS must contain paths beginning with "/".'
                )
            if '*' in protected_path and not protected_path.endswith('*'):
                raise ImproperlyConfigured(
                    'PROTECTED_PATHS only supports "*" as the final character.'
                )

    def is_protected_path(self, request_path):
        """Return whether a request path matches a configured protected path."""
        for protected_path in self.protected_paths:
            if protected_path.endswith('*'):
                if request_path.startswith(protected_path[:-1]):
                    return True
            elif request_path == protected_path:
                return True
        return False

    def get_client_ip(self, request):
        """Return a verified client address, or None when it is invalid."""
        try:
            remote_ip = ip_address(request.META.get('REMOTE_ADDR', ''))
        except (TypeError, ValueError):
            return None

        # Only trust X-Real-IP when the connecting peer is an approved proxy.
        if any(remote_ip in network for network in self.trusted_proxy_networks):
            try:
                remote_ip = ip_address(request.META.get('HTTP_X_REAL_IP', ''))
            except (TypeError, ValueError):
                return None

        if self.cloudflare_ip_store:
            cloudflare_networks = self.cloudflare_ip_store.get_networks()
            # Only trust Cloudflare's CF-Connecting-IP header when the request came from Cloudflare.
            if any(remote_ip in network for network in cloudflare_networks):
                try:
                    return ip_address(request.META.get('HTTP_CF_CONNECTING_IP', ''))
                except (TypeError, ValueError):
                    return None

        return remote_ip

    def __call__(self, request):
        if not self.is_protected_path(request.path):
            return self.get_response(request)

        if self.cloudflare_ip_store and self.cloudflare_ips_auto_update:
            self.cloudflare_ip_store.refresh_if_stale()

        client_ip = self.get_client_ip(request)
        if client_ip is None or not any(
            client_ip in network for network in self.allowed_networks
        ):
            raise Http404('Page not found')

        return self.get_response(request)