#!/usr/bin/env python

# log in with curl:
# curl -X POST https://jira.iscout.local/rest/auth/1/session
#      -d '{ "username": "", "password": "" }'
#      -H 'Content-Type: application/json'
# get issue details: with curl:
# curl -X GET https://jira.iscout.local/rest/api/latest/issue/ESB-9
#      -H 'Content-Type: application/json' --cookie 'JSESSIONID=XXX'

import httplib2
import json
import os
import ConfigParser
import argparse
import re
import logging

url = 'https://jira.iscout.local/rest/api/latest/issue/ESB-9'


class HttpException(Exception):
    def __init__(self, status, response):
        self.status = status
        self.response = response


class UnauthorizedException(HttpException):
    pass


class NotFoundException(Exception):
    pass


class JiraRestClient():
    json_headers = { 'Content-Type': 'application/json', 'Accept': 'application/json' }

    def __init__(self, jira_user, jira_password, jira_host, jira_port, api_version='latest', timeout=None):
        self.jira_user = jira_user
        self.jira_password = jira_password
        self.jira_host = jira_host
        self.jira_port = jira_port
        self.api_version = api_version
        self.timeout = timeout

    def get_issue_details(self, issue_key):
        return self.rest_call('issue/%s' % issue_key)

    def exists_issue(self, issue_key):
        try:
            self.rest_call('issue/%s' % issue_key, 'HEAD')
            return True
        except NotFoundException:
            return False

    def get_project_keys(self):
        # response is a list of dictionaries
        resp = self.rest_call('project')
        projects = json.loads(resp)
        return [p['key'] for p in projects]

    def login(self):
        print("Trying to log in...")
        body = json.dumps({'username': self.jira_user, 'password': self.jira_password}, indent=True)
        response = self.https_request('/rest/auth/1/session', 'POST', body)
        print(response)
        data = json.loads(response)
        session_id = data['session']['value']
        with open('cache.json', 'r+w') as f:
            cache = json.loads(f.read())
            cache['sessionId'] = session_id
            f.truncate(0)
            f.seek(0)
            f.write(json.dumps(cache))
        f.closed

    def rest_call(self, resource, method='GET'):
        path = '/rest/api/%s/%s' % (self.api_version, resource)
        try:
            return self.https_request(path, method)
        except UnauthorizedException:
            try:
                self.login()
                return self.rest_call(resource, method)
            except HttpException as e:
                print('%s: %s' % (e.status, e.response))

    def https_request(self, path, method='GET', body=None, headers=json_headers):

        with open('cache.json', 'r') as f:
            cache = json.loads(f.read())
            if 'sessionId' in cache:
                print('session id was cached')
                headers['Cookie'] = 'JSESSIONID=' + cache['sessionId'].encode('ascii')
                print(headers)
        f.closed

        print('%s request to URL: %s%s' % (method, self.jira_host, path))

        try:
            httpCon = httplib2.HTTPSConnectionWithTimeout(self.jira_host, self.jira_port, timeout=self.timeout)
            httpCon.connect()
            httpCon.request(method, path, body, headers=headers)
            print(body)

            response = httpCon.getresponse()
            if response.status == 200:
                print("Output from HTML request")
                return response.read()
            elif (response.status == 401):
                raise UnauthorizedException(response.status, response.read())
            elif (response.status == 404):
                raise NotFoundException()
            else:
                raise HttpException(response.status, response.read())
        except:
            raise
        finally:
            httpCon.close()


def get_commit_message(svnlook_path, repo_path, tx):
    cmd = "%s log %s --transaction %s" % (svnlook_path, repo_path, tx)
    try:
        f = os.popen(cmd)
        commit_message = f.read()
        if f.close():
            raise 1
        return commit_message.rstrip('\n\r')
    except:
        print >> sys.stderr, 'Unable to get commit message with svnlook.'
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('REPOS', help='repository path')
    parser.add_argument('TXN', help='transaction name')
    parser.add_argument('-r', '--revision', help='revision for test mode')
    args = parser.parse_args()
    repo_path = args.REPOS
    if args.revision:
        txn_or_rev = args.revision
    else:
        txn_or_rev = args.TXN

    config_file = 'check_commit.cfg'
    config = ConfigParser.ConfigParser()
    config.read(config_file)

    jira_user = config.get('JIRA', 'username')
    jira_password = config.get('JIRA', 'password')
    jira_host = config.get('JIRA', 'host')
    jira_port = config.getint('JIRA', 'port')
    jira_timeout = config.getint('JIRA', 'timeout')

    cache_filename = config.get('CACHE', 'file')

    try:
        with open(cache_filename, 'r') as f:
            content = f.read()
            json.loads(content)
        f.closed
    except IOError:
        with open(cache_filename, 'w+') as f:
            f.write('{}')
        f.closed

    client = JiraRestClient(jira_user, jira_password, jira_host, jira_port)
#    resp = client.get_issue_details('ESB-9')
#    resp = client.exists_issue('ESB-9')
    projects = client.get_project_keys()
    print("Projects: %s" % projects)
    regex = re.compile('((%s)-\d{1,})' % '|'.join(projects), re.IGNORECASE)
    print(regex.match('ESB-9: bla bla'))


if __name__ == '__main__':
    import sys
    sys.exit(main())
