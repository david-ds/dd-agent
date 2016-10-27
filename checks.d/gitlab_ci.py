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
import re
import time

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
# The pipeline status and the metric type associated
PIPELINE_STATUS = {
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
        self.gitlab_ref_pattern = init_config.get("gitlab_ref_pattern")

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


    def _ci_object_relevant(self, ci_object):
        """ The ci object is relevant if:
        - its status is running or pending
        - it is a failure or a success finished since the last check
        The ci object must be a build or a pipeline
         """
        if ci_object['status'] in ['running', 'pending']:
            return True
        if ci_object['finished_at'] == None:
            # Some pipelines may fail without being finished (yaml syntax error in gitlab-ci.yml)
            # We keep the pipeline only if it was created since the last check
            date_created_at = date_parser.parse(ci_object['created_at'])
            return date_created_at > self.last_check_date

        date_finished_at = date_parser.parse(ci_object['finished_at'])
        return date_finished_at > self.last_check_date

    def _get_projects(self):
        """ Return the list of the project ids to get its builds or pipelines """

        get_projects_url = '{0}/projects'.format(self.get_gitlab_endpoint())
        return self._make_request_with_auth_fallback(get_projects_url, verify=self._ssl_verify)

    def _get_ci_object_tags(self, project, ci_object):
        """ return the tags of the ci object (pipeline or build) """
        ci_tags = []
        ci_tags.append('project:{0}'.format(project['name']))

        # Add the ref tag (branch name or git tag name) if it maches the pattern defined in the config file
        if self.gitlab_ref_pattern and 'ref' in ci_object:
            if re.match(self.gitlab_ref_pattern, ci_object['ref']):
                ci_tags.append('gitlab-ref:{0}'.format(ci_object['ref']))

        return ci_tags

    # Builds metrics and events
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
                if not self._ci_object_relevant(build):
                    continue

                # If the status build is not monitored, skip the build
                if not build['status'] in BUILD_STATUS:
                    continue

                build_tags = self._get_ci_object_tags(project, build)

                builds_count[build['status']][tuple(sorted(build_tags))] += 1

        for status, metric_type in BUILD_STATUS.iteritems():
            for tags, count in builds_count[status].iteritems():
                if metric_type == 'count':
                    self.count("gitlab.builds." + status, count, tags=list(tags))
                elif metric_type == 'gauge':
                    self.gauge("gitlab.builds." + status, count, tags=list(tags))
                else:
                    raise

    # Pipelines metrics
    def send_pipeline_event(self, project, pipeline):
        msg_verb = {'success': 'succeed', 'failed': 'failed'}
        alert_type = {'success': 'success', 'failed': 'error'}
        pipeline_url = '{0}/pipelines/{1}'.format(project['web_url'], pipeline['id'])

        msg_title = 'The pipeline for {0}:{1} {2} in {3} seconds'.format(project['name'], pipeline['ref'], msg_verb[pipeline['status']], pipeline['duration'])

        self.event({
            'timestamp': int(time.time()),
            'event_type': 'gitlab.pipeline.{}'.format(pipeline['status']),
            'msg_title': msg_title,
            'msg_text': 'Pipeline url : {}'.format(pipeline_url),
            'alert_type': alert_type[pipeline['status']],
            'tags': self._get_ci_object_tags(project, pipeline)
        })

    def check_pipelines(self, projects):
        """ Return the list of the pipelines for all projects with detailled information about them """

        # Inialize empty counter for each status
        pipelines_count = {}
        for status in PIPELINE_STATUS:
            pipelines_count[status] = Counter()

        for project in projects:
            get_pipelines_url = '{0}/projects/{1}/pipelines'.format(self.get_gitlab_endpoint(), project['id'])

            # list of the pipelines for the given project
            project_pipelines = self._make_request_with_auth_fallback(get_pipelines_url, verify=self._ssl_verify)
            for pipeline in project_pipelines:
                # if the pipeline finished before the last check, ignore it
                if not self._ci_object_relevant(pipeline):
                    continue

                # If the status pipeline is not monitored, skip the pipeline
                if not pipeline['status'] in PIPELINE_STATUS:
                    continue

                pipeline_tags = self._get_ci_object_tags(project, pipeline)

                pipelines_count[pipeline['status']][tuple(sorted(pipeline_tags))] += 1

                # Send metric about pipeline duration if it was successful
                if pipeline['status'] == "success":
                    self.gauge("gitlab.pipelines.duration", pipeline['duration'], tags=pipeline_tags)

                if pipeline['status'] in ['success', 'failed']:
                    self.send_pipeline_event(project, pipeline)

        for status, metric_type in PIPELINE_STATUS.iteritems():
            for tags, count in pipelines_count[status].iteritems():
                if metric_type == 'count':
                    self.count("gitlab.pipelines." + status, count, tags=list(tags))
                elif metric_type == 'gauge':
                    self.gauge("gitlab.pipelines." + status, count, tags=list(tags))
                else:
                    raise

    def check(self, instance):
        self.get_and_count_runners()

        projects = self._get_projects()
        self.check_builds(projects)
        self.check_pipelines(projects)

        self.last_check_date = datetime.now(dateutil.tz.tzutc())
