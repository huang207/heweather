import logging

import asyncio
import time
from typing import Optional

import aiohttp
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_LATITUDE, CONF_LOCATION, CONF_LONGITUDE
from homeassistant.helpers.selector import (
    LocationSelector,
    LocationSelectorConfig,
)

from .heweather.const import (
    DOMAIN,
    DEFAULT_NAME,
    CURRENT_CONF_VERSION,
    CURRENT_CONF_MINOR_VERSION,
    CONF_AUTH_METHOD,
    CONF_LOCATION as CONF_LOCATION_HEWEATHER,
    CONF_HOST,
    CONF_KEY,
    CONF_STORAGE_PATH,
    CONF_JWT_SUB,
    CONF_JWT_KID,
    CONF_DISASTERLEVEL,
    CONF_DISASTERMSG,
    DEFAULT_HOST,
    DEFAULT_AUTH_METHOD,
    AUTH_METHOD,
    DEFAULT_DISASTER_LEVEL_CONF,
    DISASTER_LEVEL_CONF,
    DEFAULT_DISASTER_MSG,
    DISASTER_MSG
)

from .heweather.heweather_cert import HeWeatherCert

_LOGGER = logging.getLogger(__name__)

class HeWeatherConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = CURRENT_CONF_VERSION
    MINOR_VERSION = CURRENT_CONF_MINOR_VERSION
    _main_loop: asyncio.AbstractEventLoop
    _heweather_cert: HeWeatherCert

    _storage_path: str
    _auth_method: str
    _host: str
    _key: str
    _jwt_pubkey: str
    _jwt_sub: str
    _jwt_kid: str
    _location: dict[str, dict[str, str] | None]

    _disasterlevel: str
    _disastermsg: str

    def __init__(self):
        self._main_loop = asyncio.get_running_loop()
        self._storage_path = ''
        self._auth_method = DEFAULT_AUTH_METHOD
        self._host = DEFAULT_HOST
        self._key = ''
        self._jwt_pubkey = ''
        self._jwt_sub = ''
        self._jwt_kid = ''

        self._location = {}

        self._disasterlevel = DEFAULT_DISASTER_LEVEL_CONF
        self._disastermsg = DEFAULT_DISASTER_MSG

    async def async_step_user(
        self, user_input: Optional[dict] = None
    ):
        if self._async_current_entries():
            return self.async_abort(reason="single_instance_allowed")

        self.hass.data.setdefault(DOMAIN, {})
        if not self._storage_path:
            self._storage_path = self.hass.config.path('.storage', DOMAIN)
        # HeWeather Certification
        self._heweather_cert = self.hass.data[DOMAIN].get('heweather_cert', None)
        if not self._heweather_cert:
            self._heweather_cert = HeWeatherCert(
                root_path=self._storage_path,
                loop=self._main_loop)
            self.hass.data[DOMAIN]['heweather_cert'] = self._heweather_cert
            _LOGGER.info(
                'async_step_user, create heweather cert, %s', self._storage_path)
            
        return await self.async_step_auth_method_config(user_input)

    async def async_step_auth_method_config(
        self, user_input: Optional[dict] = None
    ):
        if user_input:
            self._auth_method = user_input.get("auth_method", self._auth_method)
            if self._auth_method == "key":
                return await self.async_step_auth_apikey_config()
            else:
                return await self.async_step_auth_jwt_config()
        return await self.__show_auth_method_config_form("")

    async def __show_auth_method_config_form(self, reason: str):
        return self.async_show_form(
            step_id="auth_method_config",
            data_schema=vol.Schema({
                vol.Required(
                    "auth_method",
                    default=self._auth_method
                ): vol.In(AUTH_METHOD)
            }),
            errors={'base': reason},
            last_step=False
        )

    async def async_step_auth_apikey_config(
        self, user_input: Optional[dict] = None
    ):
        if user_input:
            if user_input.get("key", self._key) == "":
                return await self.__show_auth_apikey_config_form("key is empty")
            elif user_input.get("host", None) == "":
                return await self.__show_auth_apikey_config_form("host is empty")
            else:
                self._key = user_input.get("key", self._key)
                self._host = user_input.get("host", self._host)
                return await self.async_step_location_config()
        return await self.__show_auth_apikey_config_form("")

    async def __show_auth_apikey_config_form(self, reason: str):
        return self.async_show_form(
            step_id="auth_apikey_config",
            data_schema=vol.Schema({
                vol.Required(
                    "key",
                    default=self._key
                ): str,
                vol.Required(
                    "host",
                    default=self._host
                ): str
            }),
            errors={'base': reason},
            last_step=False
        )

    async def async_step_auth_jwt_config(
        self, user_input: Optional[dict] = None
    ):
        if user_input:
            if user_input.get("jwt_sub", self._key) == "":
                return await self.__show_auth_apikey_config_form("jwt_sub is empty")
            elif user_input.get("jwt_kid", None) == "":
                return await self.__show_auth_apikey_config_form("jwt_kid is empty")
            elif user_input.get("host", None) == "":
                return await self.__show_auth_apikey_config_form("host is empty")
            else:
                self._jwt_sub = user_input.get("jwt_sub", self._jwt_sub)
                self._jwt_kid = user_input.get("jwt_kid", self._jwt_kid)
                self._host = user_input.get("host", self._host)
                return await self.async_step_location_config()
        await self._heweather_cert.gen_key_async()
        self._jwt_pubkey = await self._heweather_cert.get_pub_key_async()
        return await self.__show_auth_jwt_config_form("")

    async def __show_auth_jwt_config_form(self, reason: str):
        return self.async_show_form(
            step_id="auth_jwt_config",
            data_schema=vol.Schema({
                vol.Required(
                    "jwt_sub",
                    default=self._jwt_sub
                ): str,
                vol.Required(
                    "jwt_kid",
                    default=self._jwt_kid
                ): str,
                vol.Required(
                    "host",
                    default=self._host
                ): str
            }),
            description_placeholders={
                "jwt_pubkey": self._jwt_pubkey,
            },
            errors={'base': reason},
            last_step=False
        )

    async def async_step_location_config(
        self, user_input: Optional[dict] = None
    ):
        if user_input:
            location_id, location_detail = await self.__get_location_detail(user_input.get("location"))
            self._location.update({location_id: location_detail})
            return await self.async_step_disaster_config()
        return await self.__show_location_config_form("")

    async def __show_location_config_form(self, reason: str):
        return self.async_show_form(
            step_id="location_config",
            data_schema=vol.Schema({
                vol.Required(
                    CONF_LOCATION,
                    description={
                        "suggested_value": {
                            CONF_LATITUDE: self.hass.config.latitude,
                            CONF_LONGITUDE: self.hass.config.longitude,
                        }
                    }
                ): LocationSelector(
                    LocationSelectorConfig(
                        radius=False,
                        icon=""
                    )
                ),
            }),
            errors={'base': reason},
            last_step=False
        )

    async def __get_location_detail(self, location: dict) -> tuple[str, dict[str, str] | None]:
        location_str = f"{location[CONF_LONGITUDE]:.2f},{location[CONF_LATITUDE]:.2f}"
        if self._auth_method == "key":
            url = f"https://{self._host}/geo/v2/city/lookup?location={location_str}&key={self._key}"
            headers = None
        else:
            url = f"https://{self._host}/geo/v2/city/lookup?location={location_str}"
            jwt_token = await self._heweather_cert.get_jwt_token_heweather_async(self._jwt_sub, self._jwt_kid, int(time.time()) - 30, int(time.time()) + 180)
            headers = {'Authorization': f'Bearer {jwt_token}'}

        try:
            timeout = aiohttp.ClientTimeout(total=20)
            connector = aiohttp.TCPConnector(limit=10)
            async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
                async with session.get(url) as response:
                    json_data = await response.json()
                    _id: str = json_data["location"][0]["id"]
                    _detail: dict[str, str] = {"name": json_data["location"][0]["name"],
                               "country": json_data["location"][0]["country"],
                               "adm1": json_data["location"][0]["adm1"],
                               "adm2": json_data["location"][0]["adm2"],}
            return _id, _detail
        except(asyncio.TimeoutError, aiohttp.ClientError):
            _LOGGER.error("Error while accessing: %s", url)
            return location_str, None

    async def async_step_disaster_config(
        self, user_input: Optional[dict] = None
    ):
        if user_input:
            self._disasterlevel = user_input.get("disasterlevel", self._disasterlevel)
            self._disastermsg = user_input.get("disastermsg", self._disastermsg)
            return await self.config_flow_done()
        return await self.__show_disaster_config_form("")
    
    async def __show_disaster_config_form(self, reason: str):
        return self.async_show_form(
            step_id="disaster_config",
            data_schema=vol.Schema({
                vol.Required(
                    "disasterlevel",
                    default=self._disasterlevel
                ): vol.In(DISASTER_LEVEL_CONF),
                vol.Required(
                    "disastermsg",
                    default=self._disastermsg
                ): vol.In(DISASTER_MSG),
            }),
            errors={'base': reason},
            last_step=False
        )

    async def config_flow_done(self):
        return self.async_create_entry(
            title=DEFAULT_NAME,
            data={
                CONF_AUTH_METHOD: self._auth_method,
                CONF_KEY: self._key,
                CONF_STORAGE_PATH: self._storage_path,
                CONF_JWT_SUB: self._jwt_sub,
                CONF_JWT_KID: self._jwt_kid,
                CONF_HOST: self._host,
                CONF_LOCATION_HEWEATHER: self._location,
                CONF_DISASTERLEVEL: self._disasterlevel,
                CONF_DISASTERMSG: self._disastermsg,
            })
