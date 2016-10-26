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

    def _make_request_with_auth_fallback(self, url, verify=True, params=None):
        """
        Generic request handler for Gitlab API requests
        Raises specialized Exceptions for commonly encountered error codes
        """
        try:
            headers = {'PRIVATE-TOKEN': self.gitlab_auth_token}
            resp = requests.get(url, headers=headers, verify=verify, params=params, timeout=DEFAULT_API_REQUEST_TIMEOUT)
            resp.raise_for_status()
        except requests.exceptions.HTTPError:
            if resp.status_code == 401:
                self.log.info('Unable to authenticate to gitlab')
                return
            else:
                raise

        return resp.json()

    def get_gitlab_endpoint(self):
        return '{0}/api/{1}'.format(self.gitlab_master_url, self.gitlab_api_version)

    def _get_runner_tags(self, runner):
        runner_tags = []

        runner_tags.append('runner-name:{}'.format(runner['description']))
        runner_tags.append('runner-token:{}'.format(runner['token']))
        return runner_tags

    def _get_runner(self, runner_id):
        """ Get information about a runner given its id """
        get_runner_endpoint = '{0}/runners/{1}'.format(self.get_gitlab_endpoint(), runner_id)
        return self._make_request_with_auth_fallback(get_runner_endpoint, verify=self._ssl_verify)

    def get_runners(self):
        """ Get the list of runners and get detailled information about all of them """
        get_runners_endpoint = '{0}/runners/all'.format(self.get_gitlab_endpoint())
        list_runners = self._make_request_with_auth_fallback(get_runners_endpoint, verify=self._ssl_verify)

        runners = []
        for runner in list_runners:
            runners.append(self._get_runner(runner['id']))
        return runners

    def get_and_count_runners(self):
        """ List all the runners from the API and count them """
        runners = self.get_runners()

        runners_count = Counter()
        active_runners_count = Counter()

        for runner in runners:
            runner_tags = self._get_runner_tags(runner)
            runners_count[tuple(sorted(runner_tags))] += 1
            if runner['active']:
                active_runners_count[tuple(sorted(runner_tags))] += 1

        for tags, count in active_runners_count.iteritems():
            self.gauge("gitlab.runners.active", count, tags=list(tags))

        for tags, count in runners_count.iteritems():
            inactive_count = count - active_runners_count[tags]
            self.gauge("gitlab.runners.inactive", inactive_count, tags=list(tags))


    def check(self, instance):
        self.get_and_count_runners()
