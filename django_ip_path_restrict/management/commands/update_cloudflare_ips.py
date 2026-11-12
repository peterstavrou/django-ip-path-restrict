"""Manually refresh the Cloudflare IP range cache."""

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from ...cloudflare import download_and_save


class Command(BaseCommand):
    help = 'Download Cloudflare IP ranges to CLOUDFLARE_IPS_FILE.'

    def handle(self, *args, **options):
        cache_file_path = getattr(settings, 'CLOUDFLARE_IPS_FILE', None)
        if not cache_file_path:
            raise CommandError('Set CLOUDFLARE_IPS_FILE in Django settings first.')

        try:
            total_range_count = download_and_save(cache_file_path)
        except Exception as update_error:
            raise CommandError(
                f'Cloudflare IP update failed: {update_error}'
            ) from update_error

        self.stdout.write(
            self.style.SUCCESS(
                f'Updated {total_range_count} Cloudflare IP ranges in '
                f'{cache_file_path}'
            )
        )