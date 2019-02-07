import sys
import json

import datetime
import requests
import time

HELP_TXT = '  Usage:   check_mandark_errors.py <sandbox_id>\n\n' \
           '  Example: check_mandark_errors.py yhfqv2auq602c1\n\n' \
           '  Errors:\n' \
           '    10 - Too few arguments.\n' \
           '    20 - Failed to login to logzio with username and password.\n' \
           '    21 - Failed to get jwt cookie with token id.\n' \
           '    30 - Failed to execute search query.\n' \
           '\n'

LOGZIO_USERNAME = 'assaf.c@quali.com'
LOGZIO_PASSWORD = 'milena3!'


class LogzioClient:
    def __init__(self, username: str, password: str):
        self._session = requests.session()
        jwt_token_id = self._get_jwt_token_id(username=username, password=password)
        jwt_cookie_data = self._get_jwt_cookie(jwt_token_id=jwt_token_id)

        self._auth_token = jwt_cookie_data['sessionToken']
        self._logz_auth_token = self._session.cookies.get_dict()['Logzio-Csrf']

    def _get_jwt_token_id(self, username: str, password: str) -> str:
        response = self._session.post(
            url='https://logzio.auth0.com/oauth/ro',
            json={
                'scope': 'openid email connection',
                'response_type': 'token',
                'connection': 'Username-Password-Authentication',
                'username': username,
                'password': password,
                'callbackURL': 'https://app.logz.io/login/auth0code?baseUrl=https://app.logz.io',
                'responseType': 'token',
                'popup': 'false',
                'sso': 'false',
                'mfa_code': '',
                'client_id': 'kydHH8LqsLR6D6d2dlHTpPEdf0Bztz4c',
                'grant_type': 'password',
            })

        if not response.ok:
            masked_pw = password[:2] + ('*' * len(password[4:])) + password[-2:]
            sys.stderr.write(f'Failed to login to Logzio with username "{username}" and password "{masked_pw}"')
            exit(20)

        return response.json()['id_token']

    def _get_jwt_cookie(self, jwt_token_id: str) -> dict:
        response = self._session.post(
            url='https://app.logz.io/login/jwt',
            json={'jwt': jwt_token_id})

        if not response.ok:
            sys.stderr.write(f'Failed to get jwt cookie with token id {jwt_token_id}')
            exit(21)

        return response.json()

    def count_errors(self, sandbox_id: str) -> int:
        error_count = 0
        indices = self._get_last_two_days_indices()
        for daily_index in indices:
            metadata = {
                'index': 'logzioCustomerIndex'+daily_index,
                'ignore_unavailable': True,
                'timeout': 0,
                'preference': int(time.time())
            }
            query = {
                'version': True,
                'size': 1,
                'query': {
                    'bool': {
                        'must': [
                            {
                                'term': {'colony.sandbox_id': sandbox_id}
                            },
                            {
                                'terms': {'colony.level': ['ERROR', 'FATAL']}
                            }
                        ]
                    }
                }
            }
            response = self._session.post(
                url='https://app.logz.io/kibana/elasticsearch/_msearch',
                headers={
                    'content-type': 'application/x-ndjson',
                    'x-auth-token': self._auth_token,
                    'x-logz-csrf-token': self._logz_auth_token
                },
                data=f'{json.dumps(metadata)}\n{json.dumps(query)}')

            if not response.ok:
                sys.stderr.write(f'Failed to execute search query.\n'
                                 f'  Code: {response.status_code}\n '
                                 f'  Body: {response.text}')
                exit(30)

            for result in response.json()['responses']:
                error_count += result['hits']['total']
        return error_count

    def _get_last_two_days_indices(self):
        utc_now = datetime.datetime.utcnow()
        utc_yesterday = utc_now - datetime.timedelta(1)
        indices = [str(x.year)[2:4] + str(x.month).zfill(2) + str(x.day).zfill(2) for x in [utc_now, utc_yesterday]]
        return indices  # Example: 06.02.2019 -> '190206'


if len(sys.argv) < 2:
    sys.stderr.write("Too few arguments.\n"+HELP_TXT)
    exit(1)
sandbox_id = sys.argv[1]

print(f"##teamcity[progressMessage 'Checking errors in mandark {sandbox_id} logs']")
client = LogzioClient(username=LOGZIO_USERNAME,
                      password=LOGZIO_PASSWORD)
errors = client.count_errors(sandbox_id=sandbox_id)
if errors:
    link_url = f'https://app.logz.io/#/dashboard/kibana/discover?' \
               f'_g=(refreshInterval:(display:Off,pause:!f,value:0),time:(from:now-2d,mode:quick,to:now))&' \
               f'_a=(columns:!(message),filters:!((%27$state%27:(store:appState),meta:(alias:!n,disabled:!f,index:%5BlogzioCustomerIndex%5DYYMMDD,key:colony.sandbox_id,negate:!f,params:(query:{sandbox_id},type:phrase),type:phrase,value:{sandbox_id}),query:(match:(colony.sandbox_id:(query:{sandbox_id},type:phrase)))),(%27$state%27:(store:appState),meta:(alias:!n,disabled:!f,index:%5BlogzioCustomerIndex%5DYYMMDD,key:colony.level,negate:!f,params:!(ERROR,FATAL),type:phrases,value:%27ERROR,%20FATAL%27),query:(bool:(minimum_should_match:1,should:!((match_phrase:(colony.level:ERROR)),(match_phrase:(colony.level:FATAL))))))),index:%5BlogzioCustomerIndex%5DYYMMDD,interval:auto,query:(language:lucene,query:%27%27),sort:!(%27@timestamp%27,desc))&' \
               f'accountIds&' \
               f'switchToAccountId=27106'
    print(f"##teamcity[buildProblem description='Mandark {sandbox_id} has {errors} error(s)']")
    print(f"##teamcity[progressMessage 'View errors: {link_url}']")
else:
    print(f"##teamcity[message text='Mandark {sandbox_id} has no errors']")



