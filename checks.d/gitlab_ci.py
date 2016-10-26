# (C) Datadog, Inc. 2010-2016
# All rights reserved
# Licensed under Simplified BSD License (see LICENSE)

# project
from checks import AgentCheck

# stdlib
from collections import Counter
from datetime import datetime

# api calls
import requests

DEFAULT_API_REQUEST_TIMEOUT = 5 # seconds

class IncompleteConfig(Exception):
    pass

class GitlabCI(AgentCheck):
    def __init__(self, name, init_config, agentConfig, instances=None):
        AgentCheck.__init__(self, name, init_config, agentConfig, instances)

        self._ssl_verify = init_config.get("ssl_verify", True)
        self.gitlab_master_url = init_config.get("gitlab_master_url")
        self.gitlab_api_version = init_config.get("gitlab_api_version")
        self.gitlab_auth_token = init_config.get("gitlab_auth_token")
        if not self.gitlab_master_url:
            raise IncompleteConfig()
        if not self.gitlab_auth_token:
            raise IncompleteConfig()

    def check(self, instance):
        pass
