import asyncio
import logging
from typing import Optional
from .heweather.heweather_cert import HeWeatherCert
from .heweather.const import (
    DOMAIN,
    CONF_STORAGE_PATH,
    CONF_LOCATION,
)


from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform

SUPPORTED_PLATFORMS = [Platform.WEATHER, Platform.SENSOR]

_LOGGER = logging.getLogger(__name__)


async def async_setup(hass: HomeAssistant, hass_config: dict) -> bool:
    # pylint: disable=unused-argument
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    # Get running loop
    loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
    if not loop:
        raise Exception("loop is None")
    # HeWeather Certification
    cert: Optional[HeWeatherCert] = hass.data[DOMAIN].get("heweather_cert", None)
    if not cert:
        cert = HeWeatherCert(
            root_path=config_entry.data.get(CONF_STORAGE_PATH), loop=loop
        )
        hass.data[DOMAIN]["heweather_cert"] = cert
        _LOGGER.info("create heweather cert instance")

    await hass.config_entries.async_forward_entry_setups(
        config_entry, SUPPORTED_PLATFORMS
    )

    return True


async def async_unload_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(
        config_entry, SUPPORTED_PLATFORMS
    )

    return unload_ok


async def async_remove_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    heweather_cert: HeWeatherCert = hass.data[DOMAIN]["heweather_cert"]

    await heweather_cert.del_key_async()

    hass.data.pop(DOMAIN, None)

    return True


async def async_migrate_entry(hass: HomeAssistant, config_entry: ConfigEntry):
    version = config_entry.version
    data = config_entry.data

    if version == 1:
        # Migrate from version 1 to 2
        _LOGGER.info(
            "Migrated config entry %s to version %s",
            config_entry.entry_id,
            config_entry.version,
        )
        data[CONF_LOCATION] = {data[CONF_LOCATION]: None}
        hass.config_entries.async_update_entry(
            config_entry, data=data, minor_version=1, version=2
        )

    return True
