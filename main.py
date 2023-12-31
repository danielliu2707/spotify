import requests
import urllib.parse
from flask import Flask, redirect, jsonify, session, request
from datetime import datetime

app = Flask(__name__)   # Initialize Flask App

# Needed to access Flask Session (can store data accessed later between requests).
app.secret_key = '53d355f8-571a-4590-a310-1f9579440851' 

# Provided by spotify.
# NOTE: Client refers to the app requesting acess to user data
CLIENT_ID = '9f951db530d8462fbedfd75507b90cbf'
CLIENT_SECRET = '3f38813ebdb24d0caa8db79c5a169862'

# The URI we set on Spotify App
REDIRECT_URI = 'http://localhost:5000/callback'

# URL's to get the token from spotify, refresh token and API's base URL
AUTH_URL = 'https://accounts.spotify.com/authorize'
TOKEN_URL = 'https://accounts.spotify.com/api/token'  
API_BASE_URL = 'https://api.spotify.com/v1/'

# Give welcome message and link for directing to authentication page of spotify
@app.route('/')
def index():
    return "Welcome to my Spotify App <a href='/login'>Login with Spotify</a>"

@app.route('/login')
def login():
    """
     Makes request to Spotifies Auth URL, passing params to retrieve playlists and 
     redirect the user to this authentication URL.
    """
    scope = 'user-read-private user-read-email'  # Reading a users private playlists/songs AND email
    
    # spotify requires a few parameters for this:
    params = {
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'scope': scope,       # The scope of permissions needed from user
        'redirect_uri': REDIRECT_URI,       # Where spotify redirects to on successful/failed login
         # Force user to log in everytime (Debugging purposes) - Omit later.
         # Part of Spotify recognising we already have a non-expired access token 
        'show_dialog': True       
    }

    auth_url = f'{AUTH_URL}?{urllib.parse.urlencode(params)}'
    
    return redirect(auth_url)

""" 
 When logging in, either the user will login successfully - Spotify gives us a code to get an access token.
 The user may login unsuccessfully - We will get an error.
 
 callback endpoint: In an OAuth process, used to redirect the user back to the client application
 once they've been granted permission.
 * Once we get user info, Spotify will callback to this /callback endpoint.
"""

@app.route('/callback')
def callback():
    # If user login was unsuccessful: Return error
    # NOTE: request.args is a ImmutableMultiDict that will contain the key 'Code'
    # IF the authentication was successful.
    if 'error' in request.args:
        return jsonify({'error': request.args['error']})   # return error back
    
    # If user login was successful: Spotify returns code to get access token
    if 'code' in request.args:
        # Parameters needed for request to access token
        req_body = {
            'code': request.args['code'],
            'grant_type': 'authorization_code',
            'redirect_uri': REDIRECT_URI,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
        }
        
        # Send off the request for access token
        response = requests.post(TOKEN_URL, data=req_body)
        token_info = response.json()   # token_info comes back as a json object
        
        # The session is the interval over which the client logs on and out of the server.
        # A session obj is a dictionary which stores data needed within this session
        # temp data basically (i.e. the access,refresh key and expiry)
        session['refresh_token'] = token_info['refresh_token']
        session['access_token'] = token_info['access_token']
        session['expires_at'] = datetime.now().timestamp() + token_info['expires_in']   # a timestamp of when the token expires: number of seconds since epoch
        
        return redirect('/playlists')
    
@app.route('/playlists')
def get_playlists():
    # If no access token is not session, redirect them to login
    if 'access_token' not in session:
        return redirect('/login')
    
    # If access token has expired, refresh the token
    if datetime.now().timestamp() > session['expires_at']:
        print('Token Expired')
        return redirect('/refresh-token')
    
    # Retrieve user playlists
    headers = {
        'Authorization': f"Bearer {session['access_token']}",
    }
    
    response = requests.get(API_BASE_URL + 'me/playlists', headers=headers)
    playlists = response.json()
    
    # Returns the list of playlists you see in the end. 
    # Could just redirect this to another page like "It Worked!"
    return jsonify(playlists)

@app.route('/refresh-token')
def refresh_token():
    # If no refresh token, request a login
    if 'refresh_token' not in session:
        return redirect('/login')
    
    # If access token has expired, make a request for a fresh access token
    if datetime.now().timestamp() > session['expires_at']:
        req_body = {
            'grant_type': 'refresh_token',
            'refresh_token': session['refresh_token'],
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
        }
        
        response = requests.post(TOKEN_URL, data=req_body)
        new_token_info = response.json()  # extract the json info
        
        session['access_token'] = new_token_info['access_token']
        session['expires_at'] = datetime.now().timestamp() + new_token_info['expires_in']
        
        return redirect('/playlists')

if __name__ == '__main__':
    app.run(host = '0.0.0.0', debug = True)