# A sample Clever Instant Login implementation.
# Uses the Bottle framework and raw HTTP requests to demonstrate the OAuth2 flow.

import base64
import json
import os
import requests
import urllib

from bottle import app, redirect, request, route, run, template
from beaker.middleware import SessionMiddleware

# Obtain your Client ID and secret from your Clever developer dashboard at https://account.clever.com/partner/applications
CLIENT_ID = os.environ['CLIENT_ID']
CLIENT_SECRET = os.environ['CLIENT_SECRET']

if 'PORT' in os.environ:
    PORT = os.environ['PORT']
else:
    PORT = 2587

# Clever redirect URIs must be preregistered on your developer dashboard.
# If using the default PORT set above, make sure to register "http://localhost:2587/oauth"
REDIRECT_URI = 'http://localhost:{port}/oauth'.format(port=PORT)
CLEVER_OAUTH_URL = 'https://clever.com/oauth/tokens'
CLEVER_API_BASE = 'https://api.clever.com'

# Use the bottle session middleware to store an object to represent a "logged in" state.
session_opts = {
    'session.type': 'memory',
    'session.cookie_expires': 300,
    'session.auto': True
}
myapp = SessionMiddleware(app(), session_opts)

# Our home page route will create a Clever Instant Login button.
@route('/')
def index():
    encoded_string = urllib.urlencode({
        'response_type': 'code',
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'scope': 'read:user_id read:sis'        
    })
    return template("<h1>Login!<br/><br/> \
        <a href='https://clever.com/oauth/authorize?" + encoded_string +
        "'><img src='http://assets.clever.com/sign-in-with-clever/sign-in-with-clever-small.png'/></a></h1>"
    )


# Our OAuth 2.0 redirect URI location corresponds to what we've set above as
# our REDIRECT_URI.  When this route is executed, we will retrieve the "code"
# parameter and exchange it for a Clever access token.
# After receiving the access token, we save it to the session state, and
# redirect our user to our application.
@route('/oauth')
def oauth():
    # Check to see if there is already a token we can use
    session = request.environ.get('beaker.session')
    token = session.get('token', None)

    if token is None:
        code = request.query.code

        # Redirect User to login screen if code parameter is missing
        if code == "":
            return redirect('/')

        payload = {
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': REDIRECT_URI
        }

        headers = {
            'Authorization': 'Basic {base64string}'.format(
                base64string=base64.b64encode(
                    CLIENT_ID + ':' + CLIENT_SECRET
                )
            ),
            'Content-Type': 'application/json',
        }

        response = requests.post(
            CLEVER_OAUTH_URL,
            data=json.dumps(payload),
            headers=headers
        )

        # Don't forget to handle 4xx and 5xx errors!
        if response.status_code != 200:
            return template(
                "Error authenticating your user." +
                "Please try again. {{message}}.",
                message=response.reason
            )

        json_response = response.json()
        token = json_response['access_token']

    if token is None or token == "":
        return template(
            "Authentication failed.  No Oauth token returned from Clever."
            )

    # Store the token to be used by multiple API queries
    session['token'] = token

    # Send users to app after successfully getting token
    return redirect('/app')


# Query the API endpoint with the token we acquired from oauth()
# This method will query the /me endpoint and use the path returned
# in the 'links' data to access the name information.  This means there
# will always be two API calls to Clever
def queryUserName(token):
    if token is None:
        return None

    bearer_headers = {
        'Authorization': 'Bearer {token}'.format(token=token)
    }

    response = requests.get(
        CLEVER_API_BASE + '/me',
        headers=bearer_headers
    )

    # Don't forget to handle 4xx and 5xx errors!
    if response.status_code != 200:
        return template("Oauth error using Authorization Token {{message}}.",
                        message=response.reason)

    result = response.json()

    if 'data' not in result and 'links' not in result:
        return "Clever endpoint /me missing \'type\' and \'links\'"

    data = result['data']
    links = result['links']

    # Only handle student logins for our app
    # (other types include teachers and districts)
    validTypes = {'student', 'teacher', 'school_admin', 'district_admin'}
    if data['type'] not in validTypes:
        return template("You must be a student to log in to this app " +
                        "but you are a {{type}}.", type=data['type'])
    else:
        if 'name' in data:  # SIS scope
            nameObject = data['name']
        else:
            userLink = None
            for link in links:
                if link['rel'] == "canonical":
                    userLink = link['uri']
                    break

            if userLink is None:
                return None

            response = requests.get(
                CLEVER_API_BASE + userLink,
                headers=bearer_headers
            )

            if response.status_code != 200:
                return None

            user = response.json()
            nameObject = user['data']['name']

        session = request.environ.get('beaker.session')
        session['nameObject'] = nameObject

        return nameObject


# Our application logic lives here and is reserved only for users we've authenticated and identified.
@route('/app')
def app():
    session = request.environ.get('beaker.session')
    nameObject = None
    if 'nameObject' in session:
        nameObject = session['nameObject']
    else:
        # if session has a token then get name
        # otherwise, user should be directed through oauth
        token = session.get('token', None)
        if token is None:
            return redirect('/oauth')

        nameObject = queryUserName(token)

    if nameObject is not None:
        return template(
            "You are now logged in as {{name}}." +
            "<p>Click <a href='/logout'>here</a> to log out.</p>",
            name=nameObject['first'] + ' ' + nameObject['last']
        )
    else:
        return "You must be logged in to see this page!" + \
            "Click <a href='/'>here</a> to log in."


@route('/logout')
def logOut():
    session = request.environ.get('beaker.session')
    session.delete
    return redirect('/')


if __name__ == '__main__':
    run(app=myapp, host='localhost', port=PORT)
