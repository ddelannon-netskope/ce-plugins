"""
BSD 3-Clause License
Copyright (c) 2021, Netskope OSS
All rights reserved.
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""
"""HarfangLab Plugin providing implementation for pull and validate methods from PluginBase."""
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult
)
from netskope.integrations.cte.models import Indicator, IndicatorType
from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams
)
from typing import List, Dict
import requests
import json
MAX_PAGE_SIZE = 50
LIMIT = 2500
PLUGIN_NAME = "HarfangLab CTE Plugin"
class HarfangLabException(Exception):
    """HarfangLab Exception class."""
    pass
class HarfangLab(PluginBase):
    """HarfangLab class template implementation."""
    def handle_error(self, indicatorvalue, resp: requests.models.Response):
        """Handle the different HTTP response code.
        Args:
            resp (requests.models.Response): Response object returned from API
            call.
        Returns:
            dict: Returns the dictionary of response JSON when the response
            code is 200.
        Raises:
            HTTPError: When the response code is not 200.
        """
        err_msg = f"Response code {resp.status_code} received."
        if resp.status_code == 200 or resp.status_code == 201:
            try:
                return resp.json()
            except ValueError:
                err_msg = "Error occurred while parsing response to json."
                self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
                raise HarfangLabException(f"{PLUGIN_NAME}: {err_msg}")
        elif resp.status_code == 401:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise HarfangLabException(
                f"{PLUGIN_NAME}: Received exit code 401, Authentication Error"
            )
        elif resp.status_code == 403:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise HarfangLabException(
                f"{PLUGIN_NAME}: Received exit code 403, Forbidden User"
            )
        elif resp.status_code == 404:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise HarfangLabException(
                f"{PLUGIN_NAME}: Received exit code 404, Not Found"
            )
        elif resp.status_code == 400 and resp.text.find("Ioc rule with this Type, Value and Source already exists."):
            err_msg = f"Duplicated IoC found: {indicatorvalue}. Not synchronized."
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            return resp.json()
        elif 400 <= resp.status_code < 500:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise HarfangLabException(
                f"{PLUGIN_NAME}: Received exit code {resp.status_code}, HTTP Client Error"
            )
        elif 500 <= resp.status_code < 600:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise HarfangLabException(
                f"{PLUGIN_NAME}: Received exit code {resp.status_code}, HTTP server Error"
            )
        else:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise HarfangLabException(
                f"{PLUGIN_NAME}: Received exit code {resp.status_code}, HTTP Error"
            )
    def get_iocsource_id(self):
        """Get IOC id"""
        headers = {
            'Authorization': self.configuration.get('apikey'),
            'Content-Type': 'application/json'
        }
        payload = {}
        ioc_url = self.configuration['fqdn'].strip().strip('/') + "/api/data/threat_intelligence/IOCSource/?search=" + self.configuration['iocsourcename']
        response = requests.request("GET", ioc_url, headers=headers, data=payload, proxies=self.proxy)
        if response.status_code == 200:
            try:
                iocsourceid = response.json()["results"][0]["id"]
                return iocsourceid
            except Exception as err:
                self.logger.error(
                    message=f"{PLUGIN_NAME}: Validation error occurred.",
                    details=f"Error Details: {err}",
                )
                raise HarfangLabException(
                    f"{PLUGIN_NAME}: Validation error occurred. Error: {err}."
                )
        elif response.status_code == 401 or response.status_code == 400:
            err_msg = "Invalid Client ID or Client Secret provided."
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise requests.HTTPError(err_msg)
        else:
            self.logger.error(
                message=f"{PLUGIN_NAME}: Validation error occurred.",
                details=f"Error Details: {response.json()}",
            )
            raise requests.HTTPError(
                f"{PLUGIN_NAME}: Validation error occurred with response {response.json()}"
            )
    def pull(self):
        """Pull indicators from HarfangLab."""
        Offset1 = 0
        Offset2 = 100
        payload = json.dumps({
            "request_data": {},
            "search_from": Offset1,
            "search_to": Offset2,
            "sort": {
                "field": "creation_time",
                "keyword": "asc"
            }
        })
        headers = {
            'Authorization': self.configuration.get('apikey'),
            'Content-Type': 'application/json'
        }
        url = f"{self.configuration['fqdn'].strip().strip('/')}/api/data/alert/alert/Alert/"
        response = requests.request("GET", url, headers=headers, data=payload, proxies=self.proxy)
        data = response.json()
        indicators = []
        if data["count"] > 0:
            while data["count"] > Offset2:
                for i in range(0, data["count"]):
                    if data["results"][i]["details_library"]["hashes"]["sha256"] is not None:
                        indicators.append(
                            Indicator(
                                value=data["results"][i]["details_library"]["hashes"]["sha256"],
                                type=IndicatorType.SHA256
                            )
                        )
                Offset1 = Offset1 + 101
                Offset2 = Offset2 + 100
                payload = json.dumps({
                    "request_data": {},
                    "search_from": Offset1,
                    "search_to": Offset2,
                    "sort": {
                        "field": "creation_time",
                        "keyword": "asc"
                    }
                })
            response = requests.request("GET", url, headers=headers, data=payload, proxies=self.proxy)
            data = response.json()
        return indicators
    def push(self, indicators: List[Indicator], action_dict: Dict) -> PushResult:
        """Push indicators to the HarfangLab.
        Args:
            indicators (List[Indicator]): List of Indicators
            action_dict (dict): Action dictionary
        Returns:
            PushResult : return PushResult with success and message parameters.
        """
        iocsourceid = self.get_iocsource_id()
        headers = {
            'accept': 'application/json',
            'Authorization': self.configuration.get('apikey'),
            'Content-Type': 'application/json'
        }
        error_occur = False
        ioc_url = self.configuration['fqdn'].strip().strip('/') + "/api/data/threat_intelligence/IOCRule/"
        if action_dict["value"] == "create_iocs":
            # Threat IoCs
            for indicator in indicators:
                if indicator.type.upper() == "SHA256":
                    type = "hash"
                else:
                    type = "url"
                payload = json.dumps({
                    "value": indicator.value,
                    "source_id": iocsourceid,
                    "type": type
                })
                response = requests.request("POST", ioc_url, headers=headers, data=payload, proxies=self.proxy, verify=self.ssl_validation)
                indicatorvalue = indicator.value
                if not self.handle_error(indicatorvalue,response):
                    error_occur = True
                    break
            if not error_occur:
                return PushResult(
                    success=True,
                    message="Indicators pushed successfully to HarfangLab.",
                )
            else:
                return PushResult(
                    success=False,
                    message="Indicators failed to push to HarfangLab.",
                )
    def validate(self, configuration):
        """Validate the configuration."""
        if (
            "fqdn" not in configuration
            or not configuration.get("fqdn")
            or type(configuration.get("fqdn")) != str
        ):
            err_msg = "Base URL is Required Field."
            self.logger.error(
                f"{PLUGIN_NAME}: Validation error occurred, Error: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        if (
            "apikey" not in configuration
            or not configuration.get("apikey")
            or type(configuration.get("apikey")) != str
        ):
            err_msg = "API Token is Required Field."
            self.logger.error(
                f"{PLUGIN_NAME}: Validation error occurred, Error: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        if (
            "iocsourcename" not in configuration
            or not configuration.get("iocsourcename")
            or type(configuration.get("iocsourcename")) != str
        ):
            err_msg = "IOC Source list is Required Field."
            self.logger.error(
                f"{PLUGIN_NAME}: Validation error occurred, Error: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        return self.validate_params(configuration)
    def validate_params(self, configuration):
        """Validate API key by making REST API call."""
        try:
            headers = {
                'Authorization': configuration.get("apikey"),
                'Content-Type': 'application/json'
            }
            payload = {}
            ioc_url = configuration.get("fqdn").strip().strip('/') + "/api/data/threat_intelligence/IOCSource/?search=" + configuration.get("iocsourcename")
            response = requests.request("GET", ioc_url, headers=headers, data=payload, verify=self.ssl_validation, proxies=self.proxy)
            data = response.json()
            if response.status_code == 200 and data["count"] == 0:
                return ValidationResult(
                    success=False,
                    message=f"{PLUGIN_NAME}: IOC Source list not found.",
                )
            elif response.status_code == 200:
                return ValidationResult(
                    success=True,
                    message=f"Validation successful for {PLUGIN_NAME}.",
                )
            else:
                self.logger.error(
                    f"{PLUGIN_NAME}: Invalid API Key or Base URL provided."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid API Key or Base URL provided.",
                )
        except requests.exceptions.ProxyError:
            self.logger.error(
                f"{PLUGIN_NAME}: Validation Error, "
                "Invalid proxy configuration."
            )
            return ValidationResult(
                success=False,
                message="Validation Error, Invalid proxy configuration.",
            )
        except requests.exceptions.ConnectionError:
            err_msg = " ".join(
                [
                    "Validation Error, Unable to establish",
                    "connection with HarfangLab tenant URL.",
                ]
            )
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        except requests.HTTPError as err:
            err_msg = (
                "Validation error occurred. Invalid Credentials provided."
            )
            self.logger.error(
                message=f"{PLUGIN_NAME}: {err_msg}",
                details=str(err),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg}: {str(err)}",
            )
        except Exception as exp:
            err_msg = (
                "Validation error occurred. Invalid Credentials provided."
            )
            self.logger.error(message=err_msg, details=f"{exp}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(
                label="Create IoCs",
                value="create_iocs",
            ),
        ]
    def validate_action(self, action: Action):
        """Validate HarfangLab Action Configuration."""
        if action.value not in ["create_iocs"]:
            return ValidationResult(success=False, message="Invalid action.")
        return ValidationResult(success=True, message="Validation successful.")
    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []
