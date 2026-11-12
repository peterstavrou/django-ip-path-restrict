import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import django
from django.conf import settings

if not settings.configured:
    settings.configure(
        DEBUG=False,
        DEFAULT_CHARSET='utf-8',
        INSTALLED_APPS=['django_ip_path_restrict'],
        SECRET_KEY='test',
    )
    django.setup()

from django.core.exceptions import ImproperlyConfigured
from django.http import Http404, HttpResponse
from django.test import RequestFactory, override_settings

from django_ip_path_restrict.cloudflare import (
    CloudflareIPStore,
    save_cloudflare_ranges,
    validate_ip_ranges,
)
from django_ip_path_restrict.middleware import RestrictPathsByIPMiddleware


class RestrictPathsByIPMiddlewareTests(unittest.TestCase):
    def setUp(self):
        self.request_factory = RequestFactory()
        self.get_response = Mock(return_value=HttpResponse('OK'))

    def request(
        self,
        request_path,
        remote_ip,
        cloudflare_client_ip=None,
        real_ip=None,
    ):
        request = self.request_factory.get(request_path)
        request.META['REMOTE_ADDR'] = remote_ip
        if cloudflare_client_ip is not None:
            request.META['HTTP_CF_CONNECTING_IP'] = cloudflare_client_ip
        if real_ip is not None:
            request.META['HTTP_X_REAL_IP'] = real_ip
        return request

    @override_settings(
        DEBUG=False,
        PROTECTED_PATHS=['/admin', '/login/', '/private*'],
        ALLOWED_IPS=['203.0.113.10'],
    )
    def test_path_matching_uses_exact_paths_and_an_explicit_wildcard(self):
        middleware = RestrictPathsByIPMiddleware(self.get_response)
        expected_matches = {
            '/admin': True,
            '/admin/': False,
            '/admin/users/': False,
            '/administration/': False,
            '/login/': True,
            '/login/reset/': False,
            '/login': False,
            '/private': True,
            '/private-area': True,
        }

        for request_path, is_protected in expected_matches.items():
            with self.subTest(path=request_path):
                self.assertEqual(
                    middleware.is_protected_path(request_path),
                    is_protected,
                )

    @override_settings(
        DEBUG=False,
        PROTECTED_PATHS=['/admin/*'],
        ALLOWED_IPS=['203.0.113.10'],
    )
    def test_trailing_wildcard_can_exclude_the_base_path(self):
        middleware = RestrictPathsByIPMiddleware(self.get_response)
        self.assertFalse(middleware.is_protected_path('/admin'))
        self.assertTrue(middleware.is_protected_path('/admin/'))
        self.assertTrue(middleware.is_protected_path('/admin/users/'))

    @override_settings(
        DEBUG=False,
        PROTECTED_PATHS=['/admin'],
        ALLOWED_IPS=['203.0.113.10'],
    )
    def test_allows_an_allowed_ip_on_a_protected_path(self):
        response = RestrictPathsByIPMiddleware(self.get_response)(
            self.request('/admin', '203.0.113.10')
        )

        self.assertEqual(response.status_code, 200)

    @override_settings(
        DEBUG=False,
        PROTECTED_PATHS=['/admin'],
        ALLOWED_IPS=['203.0.113.0/24', '2001:db8::/32'],
    )
    def test_supports_ipv4_and_ipv6_cidr_allowlists(self):
        middleware = RestrictPathsByIPMiddleware(self.get_response)
        self.assertEqual(
            middleware(self.request('/admin', '203.0.113.77')).status_code,
            200,
        )
        self.assertEqual(
            middleware(self.request('/admin', '2001:db8::42')).status_code,
            200,
        )

        with self.assertRaises(Http404):
            middleware(self.request('/admin', '192.0.2.9'))

    @override_settings(
        DEBUG=False,
        PROTECTED_PATHS=['/admin'],
        ALLOWED_IPS=['203.0.113.10'],
    )
    def test_hides_a_protected_path_from_an_unallowed_ip(self):
        middleware = RestrictPathsByIPMiddleware(self.get_response)

        with self.assertRaises(Http404):
            middleware(self.request('/admin', '198.51.100.20'))

    @override_settings(
        DEBUG=False,
        PROTECTED_PATHS=['/admin'],
        ALLOWED_IPS=['203.0.113.10'],
    )
    def test_ignores_a_spoofed_cloudflare_header_from_a_direct_request(self):
        middleware = RestrictPathsByIPMiddleware(self.get_response)

        with self.assertRaises(Http404):
            middleware(
                self.request('/admin', '192.0.2.9', '203.0.113.10')
            )

    @override_settings(
        DEBUG=False,
        PROTECTED_PATHS=['/admin'],
        ALLOWED_IPS=['203.0.113.10'],
        IP_RESTRICT_TRUSTED_PROXY_IPS=['127.0.0.1', '::1'],
    )
    def test_trusted_proxy_can_supply_x_real_ip(self):
        middleware = RestrictPathsByIPMiddleware(self.get_response)

        response = middleware(
            self.request('/admin', '127.0.0.1', real_ip='203.0.113.10')
        )

        self.assertEqual(response.status_code, 200)

    @override_settings(
        DEBUG=False,
        PROTECTED_PATHS=['/admin'],
        ALLOWED_IPS=['203.0.113.10'],
        IP_RESTRICT_TRUSTED_PROXY_IPS=['127.0.0.1'],
    )
    def test_untrusted_peer_cannot_supply_x_real_ip(self):
        middleware = RestrictPathsByIPMiddleware(self.get_response)

        with self.assertRaises(Http404):
            middleware(
                self.request('/admin', '192.0.2.9', real_ip='203.0.113.10')
            )

    @override_settings(
        DEBUG=False,
        PROTECTED_PATHS=['/admin'],
        ALLOWED_IPS=['203.0.113.10'],
        IP_RESTRICT_TRUSTED_PROXY_IPS=['127.0.0.1'],
    )
    def test_trusted_proxy_without_x_real_ip_is_denied(self):
        middleware = RestrictPathsByIPMiddleware(self.get_response)

        with self.assertRaises(Http404):
            middleware(self.request('/admin', '127.0.0.1'))

    @override_settings(
        DEBUG=False,
        PROTECTED_PATHS=['/admin'],
        ALLOWED_IPS=['203.0.113.10'],
    )
    def test_unprotected_path_returns_the_response_without_checking_the_client_ip(self):
        middleware = RestrictPathsByIPMiddleware(self.get_response)
        request = self.request('/public/', '198.51.100.20')

        with patch.object(middleware, 'get_client_ip') as mock_get_client_ip:
            response = middleware(request)

        self.assertEqual(response.status_code, 200)
        self.get_response.assert_called_once_with(request)
        mock_get_client_ip.assert_not_called()

    @override_settings(
        DEBUG=False,
        PROTECTED_PATHS=['/admin'],
        ALLOWED_IPS=['203.0.113.10'],
        CLOUDFLARE_IPS_FILE='/tmp/cloudflare_ips.json',
    )
    def test_unprotected_paths_do_not_refresh_cloudflare_ranges(self):
        middleware = RestrictPathsByIPMiddleware(self.get_response)
        with patch.object(
            middleware.cloudflare_ip_store,
            'refresh_if_stale',
        ) as mock_refresh:
            response = middleware(self.request('/public/', '198.51.100.20'))

        self.assertEqual(response.status_code, 200)
        mock_refresh.assert_not_called()

    @override_settings(
        DEBUG=False,
        PROTECTED_PATHS=['/admin'],
        ALLOWED_IPS=['203.0.113.10'],
        CLOUDFLARE_IPS_FILE='/tmp/cloudflare_ips.json',
    )
    def test_protected_paths_do_not_auto_update_cloudflare_ranges_by_default(self):
        middleware = RestrictPathsByIPMiddleware(self.get_response)
        with patch.object(
            middleware.cloudflare_ip_store,
            'refresh_if_stale',
        ) as mock_refresh:
            response = middleware(self.request('/admin', '203.0.113.10'))

        self.assertEqual(response.status_code, 200)
        mock_refresh.assert_not_called()

    @override_settings(
        DEBUG=False,
        PROTECTED_PATHS=['/admin'],
        ALLOWED_IPS=['203.0.113.10'],
        CLOUDFLARE_IPS_FILE='/tmp/cloudflare_ips.json',
        CLOUDFLARE_IPS_AUTO_UPDATE=True,
    )
    def test_protected_paths_auto_update_cloudflare_ranges_when_enabled(self):
        middleware = RestrictPathsByIPMiddleware(self.get_response)
        with patch.object(
            middleware.cloudflare_ip_store,
            'refresh_if_stale',
        ) as mock_refresh:
            response = middleware(self.request('/admin', '203.0.113.10'))

        self.assertEqual(response.status_code, 200)
        mock_refresh.assert_called_once()

    @override_settings(
        DEBUG=True,
        PROTECTED_PATHS=['/admin'],
        ALLOWED_IPS=[],
    )
    def test_debug_mode_keeps_the_restriction(self):
        middleware = RestrictPathsByIPMiddleware(self.get_response)

        with self.assertRaises(Http404):
            middleware(self.request('/admin', '198.51.100.20'))

    @override_settings(
        DEBUG=False,
        PROTECTED_PATHS=['/admin*private'],
        ALLOWED_IPS=['203.0.113.10'],
    )
    def test_invalid_protected_path_pattern_is_rejected(self):
        with self.assertRaises(ImproperlyConfigured):
            RestrictPathsByIPMiddleware(self.get_response)

    @override_settings(
        DEBUG=False,
        PROTECTED_PATHS=['/admin'],
        ALLOWED_IPS=['not-an-ip'],
    )
    def test_invalid_allowlist_entry_is_rejected(self):
        with self.assertRaises(ImproperlyConfigured):
            RestrictPathsByIPMiddleware(self.get_response)

    @override_settings(
        DEBUG=False,
        PROTECTED_PATHS=['/admin'],
        ALLOWED_IPS=['203.0.113.10'],
        IP_RESTRICT_TRUSTED_PROXY_IPS=['not-an-ip'],
    )
    def test_invalid_trusted_proxy_entry_is_rejected(self):
        with self.assertRaises(ImproperlyConfigured):
            RestrictPathsByIPMiddleware(self.get_response)

    @override_settings(
        DEBUG=False,
        PROTECTED_PATHS=['/admin'],
        ALLOWED_IPS=['203.0.113.10'],
        IP_RESTRICT_TRUSTED_PROXY_IPS=['0.0.0.0/0'],
    )
    def test_all_network_trusted_proxy_entry_is_rejected(self):
        with self.assertRaises(ImproperlyConfigured):
            RestrictPathsByIPMiddleware(self.get_response)

    def test_cloudflare_proxy_ip_can_use_a_verified_header(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache_file_path = Path(temporary_directory) / 'ips.json'
            save_cloudflare_ranges(cache_file_path, {
                'ipv4_cidrs': ['173.245.48.0/20'],
                'ipv6_cidrs': ['2400:cb00::/32'],
            })
            with override_settings(
                DEBUG=False,
                PROTECTED_PATHS=['/admin'],
                ALLOWED_IPS=['203.0.113.10'],
                CLOUDFLARE_IPS_FILE=cache_file_path,
            ):
                middleware = RestrictPathsByIPMiddleware(self.get_response)
                response = middleware(
                    self.request('/admin', '173.245.48.10', '203.0.113.10')
                )

                self.assertEqual(response.status_code, 200)

                with self.assertRaises(Http404):
                    middleware(
                        self.request('/admin', '173.245.48.10', '192.0.2.9')
                    )

                with self.assertRaises(Http404):
                    middleware(self.request('/admin', '173.245.48.10'))

    def test_cloudflare_behind_a_trusted_proxy_can_use_a_verified_header(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache_file_path = Path(temporary_directory) / 'ips.json'
            save_cloudflare_ranges(cache_file_path, {
                'ipv4_cidrs': ['173.245.48.0/20'],
                'ipv6_cidrs': ['2400:cb00::/32'],
            })
            with override_settings(
                DEBUG=False,
                PROTECTED_PATHS=['/admin'],
                ALLOWED_IPS=['203.0.113.10'],
                IP_RESTRICT_TRUSTED_PROXY_IPS=['127.0.0.1'],
                CLOUDFLARE_IPS_FILE=cache_file_path,
            ):
                middleware = RestrictPathsByIPMiddleware(self.get_response)
                response = middleware(
                    self.request(
                        '/admin',
                        '127.0.0.1',
                        '203.0.113.10',
                        real_ip='173.245.48.10',
                    )
                )

                self.assertEqual(response.status_code, 200)

    def test_cloudflare_ipv6_proxy_ip_can_use_a_verified_header(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache_file_path = Path(temporary_directory) / 'ips.json'
            save_cloudflare_ranges(cache_file_path, {
                'ipv4_cidrs': ['173.245.48.0/20'],
                'ipv6_cidrs': ['2400:cb00::/32'],
            })
            with override_settings(
                DEBUG=False,
                PROTECTED_PATHS=['/admin'],
                ALLOWED_IPS=['2001:db8::123'],
                CLOUDFLARE_IPS_FILE=cache_file_path,
            ):
                middleware = RestrictPathsByIPMiddleware(self.get_response)
                response = middleware(
                    self.request('/admin', '2400:cb00::1', '2001:db8::123')
                )

                self.assertEqual(response.status_code, 200)


class CloudflareCacheTests(unittest.TestCase):
    def test_invalid_ranges_are_rejected(self):
        with self.assertRaises(ValueError):
            validate_ip_ranges({
                'ipv4_cidrs': ['192.0.2.0/24'],
                'ipv6_cidrs': [],
            })

    def test_cache_reloads_an_updated_file(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache_file_path = Path(temporary_directory) / 'ips.json'
            initial_ip_ranges = {
                'ipv4_cidrs': ['192.0.2.0/24'],
                'ipv6_cidrs': ['2001:db8::/32'],
            }
            save_cloudflare_ranges(cache_file_path, initial_ip_ranges)
            ip_store = CloudflareIPStore(cache_file_path)
            self.assertEqual(len(ip_store.get_networks()), 2)

            updated_ip_ranges = {
                'ipv4_cidrs': ['198.51.100.0/24', '203.0.113.0/24'],
                'ipv6_cidrs': ['2001:db8::/32'],
            }
            save_cloudflare_ranges(cache_file_path, updated_ip_ranges)
            self.assertEqual(len(ip_store.get_networks()), 3)

    def test_multiple_stores_share_and_reload_one_cache_file(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache_file_path = Path(temporary_directory) / 'ips.json'
            initial_ip_ranges = {
                'ipv4_cidrs': ['192.0.2.0/24'],
                'ipv6_cidrs': ['2001:db8::/32'],
            }
            updated_ip_ranges = {
                'ipv4_cidrs': ['198.51.100.0/24'],
                'ipv6_cidrs': ['2400:cb00::/32'],
            }
            save_cloudflare_ranges(cache_file_path, initial_ip_ranges)
            first_site_store = CloudflareIPStore(cache_file_path)
            second_site_store = CloudflareIPStore(cache_file_path)

            self.assertEqual(len(first_site_store.get_networks()), 2)
            self.assertEqual(len(second_site_store.get_networks()), 2)

            save_cloudflare_ranges(cache_file_path, updated_ip_ranges)

            self.assertEqual(
                [str(network) for network in first_site_store.get_networks()],
                ['198.51.100.0/24', '2400:cb00::/32'],
            )
            self.assertEqual(
                [str(network) for network in second_site_store.get_networks()],
                ['198.51.100.0/24', '2400:cb00::/32'],
            )

    def test_corrupt_cache_fails_closed_without_a_downloaded_list(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache_file_path = Path(temporary_directory) / 'ips.json'
            cache_file_path.write_text('not json', encoding='utf-8')
            ip_store = CloudflareIPStore(cache_file_path)

            self.assertEqual(ip_store.get_networks(), ())

    def test_missing_cache_is_downloaded_on_request(self):
        cloudflare_ip_ranges = {
            'ipv4_cidrs': ['192.0.2.0/24'],
            'ipv6_cidrs': ['2001:db8::/32'],
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache_file_path = Path(temporary_directory) / 'ips.json'
            ip_store = CloudflareIPStore(cache_file_path)
            with patch(
                'django_ip_path_restrict.cloudflare.download_and_save',
                side_effect=lambda target: save_cloudflare_ranges(
                    target,
                    cloudflare_ip_ranges,
                ),
            ) as mock_download:
                ip_store.refresh_if_stale()

            mock_download.assert_called_once_with(cache_file_path)
            self.assertEqual(len(ip_store.get_networks()), 2)

    def test_missing_cache_fails_closed_when_download_fails(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache_file_path = Path(temporary_directory) / 'ips.json'
            ip_store = CloudflareIPStore(cache_file_path)
            with patch(
                'django_ip_path_restrict.cloudflare.download_and_save',
                side_effect=OSError,
            ):
                ip_store.refresh_if_stale()

            self.assertEqual(ip_store.get_networks(), ())

    def test_stale_cache_is_refreshed_on_request(self):
        initial_ip_ranges = {
            'ipv4_cidrs': ['192.0.2.0/24'],
            'ipv6_cidrs': ['2001:db8::/32'],
        }
        updated_ip_ranges = {
            'ipv4_cidrs': ['198.51.100.0/24', '203.0.113.0/24'],
            'ipv6_cidrs': ['2001:db8::/32'],
        }

        with tempfile.TemporaryDirectory() as temporary_directory:
            cache_file_path = Path(temporary_directory) / 'ips.json'
            save_cloudflare_ranges(cache_file_path, initial_ip_ranges)
            ip_store = CloudflareIPStore(cache_file_path)

            with patch(
                'django_ip_path_restrict.cloudflare.time.time',
                return_value=cache_file_path.stat().st_mtime + 86401,
            ):
                with patch(
                    'django_ip_path_restrict.cloudflare.download_and_save',
                    side_effect=lambda target: save_cloudflare_ranges(
                        target,
                        updated_ip_ranges,
                    ),
                ) as mock_download:
                    ip_store.refresh_if_stale()

            mock_download.assert_called_once_with(cache_file_path)
            self.assertEqual(len(ip_store.get_networks()), 3)