"""Config flow: uid-only sign-in."""
from __future__ import annotations

import logging
from typing import Any

import homeassistant.helpers.config_validation as cv
from homeassistant import config_entries
from homeassistant.config_entries import ConfigFlowResult
import voluptuous as vol

from .api import WebTunnelAuthError, WebTunnelCloud, WebTunnelCloudError
from .const import (
    CONF_BASE_URL,
    CONF_MODE,
    CONF_UID,
    DEFAULT_BASE_URL,
    DOMAIN,
    MODE_UID,
)

_LOGGER = logging.getLogger(__name__)

UID_SCHEMA = vol.Schema({vol.Required(CONF_UID): cv.string})


class WebTunnelUIDConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle the uid-only config flow (one account per entry)."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            uid = (user_input.get(CONF_UID) or "").strip()
            if not uid:
                errors["base"] = "missing_uid"
            else:
                cloud = WebTunnelCloud(base_url=DEFAULT_BASE_URL, uid=uid)
                try:
                    await cloud.verify_uid()
                    await cloud.aclose()
                    return await self._finish(uid)
                except WebTunnelAuthError as err:
                    errors["base"] = "invalid_auth"
                    _LOGGER.warning("webtunnel uid verification failed: %s", err)
                except (WebTunnelCloudError, Exception) as err:  # noqa: BLE001
                    errors["base"] = "cannot_connect"
                    _LOGGER.warning("webtunnel connection failed: %s", err)
                await cloud.aclose()
        return self.async_show_form(step_id="user", data_schema=UID_SCHEMA, errors=errors)

    async def _finish(self, uid: str) -> ConfigFlowResult:
        await self.async_set_unique_id(uid)
        self._abort_if_unique_id_configured()
        return self.async_create_entry(
            title=uid,
            data={
                CONF_MODE: MODE_UID,
                CONF_BASE_URL: DEFAULT_BASE_URL,
                CONF_UID: uid,
            },
        )
