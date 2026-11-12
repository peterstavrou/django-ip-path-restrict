import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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

from django.core.management import call_command
from django.test import override_settings

CLOUDFLARE_IP_RANGES = {
    'ipv4_cidrs': ['173.245.48.0/20'],
    'ipv6_cidrs': ['2400:cb00::/32'],
}


class UpdateCloudflareIPsCommandTests(unittest.TestCase):
    def test_api_fetch_and_save(self):
        api_response_payload = json.dumps({
            'success': True,
            'result': CLOUDFLARE_IP_RANGES,
        }).encode('utf-8')

        with tempfile.TemporaryDirectory() as temporary_directory:
            cache_file_path = Path(temporary_directory) / 'cloudflare_ips.json'
            with override_settings(CLOUDFLARE_IPS_FILE=cache_file_path):
                with patch(
                    'django_ip_path_restrict.cloudflare.urlopen',
                    return_value=io.BytesIO(api_response_payload),
                ):
                    call_command('update_cloudflare_ips', stdout=io.StringIO())

            self.assertEqual(
                json.loads(cache_file_path.read_text(encoding='utf-8')),
                CLOUDFLARE_IP_RANGES,
            )

    def test_failed_update_keeps_the_previous_list(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache_file_path = Path(temporary_directory) / 'cloudflare_ips.json'
            cache_file_path.write_text(
                json.dumps(CLOUDFLARE_IP_RANGES),
                encoding='utf-8',
            )

            with override_settings(CLOUDFLARE_IPS_FILE=cache_file_path):
                with patch(
                    'django_ip_path_restrict.cloudflare.urlopen',
                    return_value=io.BytesIO(b'{"success": false}'),
                ):
                    with self.assertRaises(Exception):
                        call_command(
                            'update_cloudflare_ips',
                            stdout=io.StringIO(),
                        )

            self.assertEqual(
                json.loads(cache_file_path.read_text(encoding='utf-8')),
                CLOUDFLARE_IP_RANGES,
            )