"""Dump command implementation."""

import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import octorules.commands._helpers as _helpers_mod
import octorules.commands._providers as _providers_mod
from octorules.commands._helpers import (
    _FUTURE_TIMEOUT,
    _format_api_error,
    _phase_filter_to_provider_ids,
)
from octorules.commands._providers import _get_zone_provider
from octorules.config import Config, slugify
from octorules.dumper import dump_zone_rules
from octorules.extensions import call_dump_extensions
from octorules.provider.base import (
    SUPPORTS_CUSTOM_RULESETS,
    SUPPORTS_LISTS,
    BaseProvider,
    Scope,
    provider_supports,
)
from octorules.provider.exceptions import (
    ProviderAuthError,
    ProviderError,
)

log = logging.getLogger(__name__)


def cmd_dump(
    config: Config,
    zone_filter: list[str] | None,
    output_dir: str | None,
    scope_filter: str = "all",
    phase_filter: list[str] | None = None,
) -> int:
    """Run the dump command. Returns exit code."""
    config.resolve_secrets()
    providers = _providers_mod._init_providers(config)
    out_dir = Path(output_dir) if output_dir else config.rules_dir
    lists_dir = out_dir / "custom_lists" if output_dir else config.lists_dir
    provider_ids = _phase_filter_to_provider_ids(phase_filter)
    had_errors = False
    do_zones = scope_filter in ("all", "zones")

    # Collect providers that have account info
    acct_providers = [
        prov
        for prov in providers.values()
        if isinstance(prov.account_id, str) and isinstance(prov.account_name, str)
    ]
    do_account = scope_filter in ("all", "account") and bool(acct_providers)

    def _fetch_and_dump(zone_name: str) -> tuple[str, Path | None, str | None]:
        zone_cfg = config.zones[zone_name]
        provider = _get_zone_provider(zone_cfg, providers)
        scope = Scope(zone_id=zone_cfg.zone_id, label=zone_name)

        try:
            rules = provider.get_all_phase_rules(scope, provider_ids=provider_ids)
        except ProviderAuthError:
            raise
        except ProviderError as e:
            return zone_name, None, _format_api_error(e)

        # Call extension dump hooks (e.g. Page Shield)
        ext_data = call_dump_extensions(scope, provider, out_dir)

        result = dump_zone_rules(
            zone_name,
            rules,
            out_dir,
            lists_dir=lists_dir,
            **ext_data,
        )
        return zone_name, result, None

    def _dump_account(provider: BaseProvider) -> tuple[bool, str | None]:
        account_label = slugify(provider.account_name)
        scope = Scope(account_id=provider.account_id, label=provider.account_name)

        supports_cr = provider_supports(provider, SUPPORTS_CUSTOM_RULESETS)
        supports_lists = provider_supports(provider, SUPPORTS_LISTS)

        # Start secondary fetches concurrently with phase rules
        bg_workers = (1 if supports_cr else 0) + (1 if supports_lists else 0)
        cr_future = None
        lists_future = None
        bg = ThreadPoolExecutor(max_workers=max(bg_workers, 1))

        try:
            if supports_cr:
                cr_future = bg.submit(provider.get_all_custom_rulesets, scope)
            if supports_lists:
                lists_future = bg.submit(provider.get_all_lists, scope)

            try:
                rules = provider.get_all_phase_rules(scope, provider_ids=provider_ids)
            except ProviderAuthError:
                raise
            except ProviderError as e:
                log.error(
                    "Failed to dump account %s: %s",
                    provider.account_name,
                    _format_api_error(e),
                )
                return True, None

            # Fetch custom rulesets
            custom_rulesets: dict[str, dict] | None = None
            if cr_future is not None:
                try:
                    custom_rulesets = cr_future.result(timeout=_FUTURE_TIMEOUT) or None
                except ProviderAuthError:
                    raise
                except ProviderError as e:
                    log.warning(
                        "Failed to fetch custom rulesets for account %s: %s",
                        provider.account_name,
                        _format_api_error(e),
                    )

            # Fetch lists
            lists: dict[str, dict] | None = None
            if lists_future is not None:
                try:
                    lists = lists_future.result(timeout=_FUTURE_TIMEOUT) or None
                except ProviderAuthError:
                    raise
                except ProviderError as e:
                    log.warning(
                        "Failed to fetch lists for account %s: %s",
                        provider.account_name,
                        _format_api_error(e),
                    )

            # Call extension dump hooks (e.g. Page Shield)
            ext_data = call_dump_extensions(scope, provider, out_dir)

            result = dump_zone_rules(
                account_label,
                rules,
                out_dir,
                custom_rulesets=custom_rulesets,
                lists=lists,
                lists_dir=lists_dir,
                **ext_data,
            )
            if result:
                log.info("Dumped account %s -> %s", provider.account_name, result)
            return False, result
        finally:
            bg.shutdown(wait=True)

    if do_zones and do_account:
        # Run account dumps concurrently with zone dumps
        with ThreadPoolExecutor(max_workers=len(acct_providers)) as acct_executor:
            acct_futures = [acct_executor.submit(_dump_account, prov) for prov in acct_providers]
            zone_names = _helpers_mod._get_zones(config, zone_filter)
            results = _helpers_mod._map_ordered(_fetch_and_dump, zone_names, config.max_workers)
            for zone_name, result, error in results:
                if error:
                    log.error("Failed to dump %s: %s", zone_name, error)
                    had_errors = True
                elif result:
                    log.info("Dumped %s -> %s", zone_name, result)
            for future in acct_futures:
                acct_error, _ = future.result()
                if acct_error:
                    had_errors = True
    else:
        if do_zones:
            zone_names = _helpers_mod._get_zones(config, zone_filter)
            results = _helpers_mod._map_ordered(_fetch_and_dump, zone_names, config.max_workers)
            for zone_name, result, error in results:
                if error:
                    log.error("Failed to dump %s: %s", zone_name, error)
                    had_errors = True
                elif result:
                    log.info("Dumped %s -> %s", zone_name, result)
        if do_account:
            for prov in acct_providers:
                acct_error, _ = _dump_account(prov)
                if acct_error:
                    had_errors = True

    return 1 if had_errors else 0
