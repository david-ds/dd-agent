# (C) Datadog, Inc. 2010-2016
# All rights reserved
# Licensed under Simplified BSD License (see LICENSE)

# project
from checks import AgentCheck

# stdlib
from collections import Counter
from dateutil import parser as date_parser
import dateutil.tz
from datetime import datetime, tzinfo

# api calls
import requests

DEFAULT_API_REQUEST_TIMEOUT = 5 # seconds

# The build status and the metric type associated
BUILD_STATUS = {
    'success': 'count',
    'failed': 'count',
    'running': 'gauge',
    'pending': 'gauge'
}

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

        # Used to track only the new builds status from the last check
        self.last_check_date = datetime.now(dateutil.tz.tzutc())

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


    # Runners metrics and events
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

            if not runner['contacted_at'] == None:
                # Send seconds since last contact between the runner and gitlab master
                last_contact_date = date_parser.parse(runner['contacted_at'])
                seconds_since_last_contact = (datetime.now(dateutil.tz.tzutc()) - last_contact_date).total_seconds()

                self.gauge("gitlab.runner.last_contact", seconds_since_last_contact, tags=runner_tags)
            else:
                self.log.info("{0} never contacted the master node".format(runner['token']))

        for tags, count in active_runners_count.iteritems():
            self.gauge("gitlab.runners.active", count, tags=list(tags))

        for tags, count in runners_count.iteritems():
            inactive_count = count - active_runners_count[tags]
            self.gauge("gitlab.runners.inactive", inactive_count, tags=list(tags))


    def _ci_object_finished_after_last_check(self, ci_object):
        """ Return true if the ci object has finished since last check
        The ci object can be a pipeline or a build """
        if ci_object['finished_at'] == None:
            return True

        date_finished_at = date_parser.parse(ci_object['finished_at'])
        return date_finished_at > self.last_check_date

    # Builds metrics and events
    def _get_projects(self):
        """ Return the list of the project ids to get its builds or pipelines """

        get_projects_url = '{0}/projects'.format(self.get_gitlab_endpoint())
        return self._make_request_with_auth_fallback(get_projects_url, verify=self._ssl_verify)

    def _get_build_tags(self, project, build):
        build_tags = []
        build_tags.append('project:{0}'.format(project['name']))

        return build_tags

    def check_builds(self, projects):
        """ Return the list of the builds for all projects with detailled information about them """

        # Inialize empty counter for each status
        builds_count = {}
        for status in BUILD_STATUS:
            builds_count[status] = Counter()

        for project in projects:
            get_builds_url = '{0}/projects/{1}/builds'.format(self.get_gitlab_endpoint(), project['id'])

            # list of the builds for the given project
            project_builds = self._make_request_with_auth_fallback(get_builds_url, verify=self._ssl_verify)
            for build in project_builds:
                # if the build finished before the last check, ignore it
                if not self._ci_object_finished_after_last_check(build):
                    continue

                # If the status build is not monitored, skip the build
                if not build['status'] in BUILD_STATUS:
                    continue

                build_tags = self._get_build_tags(project, build)

                builds_count[build['status']][tuple(sorted(build_tags))] += 1

        for status, metric_type in BUILD_STATUS.iteritems():
            for tags, count in builds_count[status].iteritems():
                if metric_type == 'count':
                    self.count("gitlab.builds." + status, count, tags=list(tags))
                elif metric_type == 'gauge':
                    self.gauge("gitlab.builds." + status, count, tags=list(tags))
                else:
                    raise

    def check(self, instance):
        self.get_and_count_runners()

        projects = self._get_projects()
        self.check_builds(projects)

        self.last_check_date = datetime.now(dateutil.tz.tzutc())
