import requests
from .constants import HTTPS_API_URL, TOR_API_URL

class User:
    """User class"""

    def __init__(self, transport):
        self.access_token = None
        if transport == 'https':
            self.url = HTTPS_API_URL
        elif transport == 'tor':
            self.url = TOR_API_URL
        else:
            raise("Invalid trasnport option provided")
    
    def authenticate(self, opts):
        if opts:
            if 'username' in opts and 'password' in opts:
                payload = {'alias': opts['username'], 'pass': opts['password']}
                req = requests.post(self.url + 'auth/login', json  = payload)
                try:
                    return_val = req
                    self.access_token = return_val.json()['data']['access_token']
                    return "User has been authenticated"
                except Exception as error:
                    print(error)
                    raise('Error parsing JSON')
            elif 'username' in opts and 'password' not in opts:
                raise('Password is missing')
            elif 'username' not in opts and 'password' not in opts:
                raise('Username is missing')
        else:
            raise('Username and password is missing')
    
    def logout(self):
        if self.access_token:
            headers = {'Authorization': 'Token {access_token}'.format(access_token = self.access_token)}
            req = requests.delete(self.url + 'auth/me', headers=headers)
            if req.status_code == 204:
                self.access_token = None
                return "Successfully logged out"
            else:
                return (req.json()['error_msg'])
        else:
            raise('There is no access token available for this user')

    def retreive(self):
        if self.access_token:
            headers = {
                'Authorization': 'Token {access_token}'.format(access_token = self.access_token),
                'Content-Type': 'application/json'
            }
            req = requests.get(self.url + 'me', headers=headers)
            if req.status_code == 200:
                return req.json()['data']
            else:
                if req.headers['content-type'].split(';')[0] == 'application/json':
                    return(req.json()['error_msg'])
                else:
                    return(req.content)
        else:
            raise('There is no access token available for this user')

    def posts(self):
        if self.access_token:
            headers = {
                'Authorization': 'Token {access_token}'.format(access_token = self.access_token),
                'Content-Type': 'application/json'
            }
            req = requests.get(self.url + 'me/posts', headers=headers)
            if req.status_code == 200:
                return req.json()['data']
            else:
                if req.headers['content-type'].split(';')[0] == 'application/json':
                    return(req.json()['error_msg'])
                else:
                    return(req.content)
        else:
            raise('There is no access token available for this user')

    def collections(self):
        if self.access_token:
            headers = {
                'Authorization': 'Token {access_token}'.format(access_token = self.access_token),
                'Content-Type': 'application/json'
            }
            req = requests.get(self.url + 'me/collections', headers=headers)
            if req.status_code == 200:
                return req.json()['data']
            else:
                if req.headers['content-type'].split(';')[0] == 'application/json':
                    return(req.json()['error_msg'])
                else:
                    return(req.content)
        else:
            raise('There is no access token available for this user')

    def channels(self):
        if self.access_token:
            headers = {
                'Authorization': 'Token {access_token}'.format(access_token = self.access_token),
                'Content-Type': 'application/json'
            }
            req = requests.get(self.url + 'me/channels', headers=headers)
            if req.status_code == 200:
                return req.json()['data']
            else:
                if req.headers['content-type'].split(';')[0] == 'application/json':
                    return(req.json()['error_msg'])
                else:
                    return(req.content)
        else:
            raise('There is no access token available for this user')
