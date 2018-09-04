import requests
import os
import httplib2
import json
import random
import string
from flask import (Flask, render_template, request, redirect, url_for, flash,
                   jsonify)

from flask import session as login_session
from flask import make_response

from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.exc import SQLAlchemyError
from database_setup import Base, Country, City, User

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

app = Flask(__name__)
app.secret_key = 'super_secret_key'


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


# Load the Google Sign-in API Client ID.
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
CLIENT_ID = json.loads(
    open(APP_ROOT + '/google_client_secret.json', 'r')
    .read())['web']['client_id']

APPLICATION_NAME = "catalog"

engine = create_engine(
    'postgresql://catalog:yourpassword@localhost/catalog')
Base.metadata.bind = engine

DBSession = scoped_session(sessionmaker(bind=engine))
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        oauth_flow = flow_from_clientsecrets(
                APP_ROOT + '/google_client_secret.json',
                scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # check if token in valid
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If error abort
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check if token in valid for a specific user
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check if token in valid for a this app
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
                'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token
    login_session['provider'] = 'google'
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 150px; \
            height: 150px; \
            border-radius: 150px; \
            -webkit-border-radius: 150px; \
            -moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url = 'https://accounts.google.com/o/ \
            oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return redirect(url_for('CountryList'))
    else:
        response = make_response(json.dumps(
                    'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token
    app_id = json.loads(open('fb_client_secret.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secret.json', 'r').read())['web']['app_secret']
    url = ("https://graph.facebook.com/oauth/access_token?grant_type="
           "fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token="
           "%s" % (app_id, app_secret, access_token))
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = ("https://graph.facebook.com/v2.8/me?access_token="
           "%s&fields=name,id,email" % token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # sotore token in loggin_session
    login_session['access_token'] = token

    # Get user picture
    url = ("https://graph.facebook.com/v2.8/me/picture?access_token="
           "%s&redirect=0&height=200&width=200" % token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 150px; \
                height: 150px; \
                border-radius: 150px; \
                -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/disconnect')
def disconnect():
    """ Deletes all user session values and redirect to the main page."""

    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
        if login_session['provider'] == 'facebook':
            del login_session['facebook_id']

        # Reset the user's session.
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('CountryList'))
    else:
        flash("You were not logged in")
        return redirect(url_for('CountryList'))


# Making an API endpoint (GET = request) for country list
@app.route('/countries/JSON')
def ContriesJSON():
    countries = session.query(Country).all()
    return jsonify(Countries=[country.serialize for country in countries])


# Making an API endpoint (GET = request) for city per country
@app.route('/country/<int:country_id>/JSON')
def CitiesJSON(country_id):
    country = session.query(Country).filter_by(id=country_id).one_or_none()
    cities = session.query(City).filter_by(country=country).all()
    return jsonify(Cities=[city.serialize for city in cities])


# Making an API endpoint (GET = request) for single city
@app.route('/country/<int:country_id>/city/<int:city_id>/JSON')
def SingleCityJSON(country_id, city_id):
    city = session.query(City).filter_by(id=city_id).one_or_none()
    return jsonify(city=city.serialize)


@app.route('/')
@app.route('/countries/')
def CountryList():
    countries = session.query(Country).all()
    if 'username' not in login_session:
        return render_template('countries-public.html', countries=countries)
    else:
        return render_template('countries.html', countries=countries)


# add new country
@app.route('/countries/new', methods=['GET', 'POST'])
def NewCountry():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newCountry = Country(
            name=request.form['name'],
            user_id=login_session['user_id'])
        session.add(newCountry)
        session.commit()
        flash('new country created!')
        return redirect(url_for('CountryList'))
    else:
        return render_template('new-country.html')


@app.route('/country/<int:country_id>')
def SingleCountry(country_id):
    country = session.query(Country).filter_by(id=country_id).one_or_none()
    cities = session.query(City).filter_by(country_id=country_id).all()
    creator = getUserInfo(country.user_id)

    if 'username' not in login_session or \
            creator.id != login_session['user_id']:
        return render_template(
            'country-cities-public.html',
            country=country,
            cities=cities,
            country_id=country_id)
    else:
        return render_template(
            'country-cities.html',
            country=country,
            cities=cities,
            country_id=country_id,
            creator=creator)


# delete country
@app.route('/country/<int:country_id>/delete', methods=['GET', 'POST'])
def DeleteCountry(country_id):
    countryToDelete = session.query(Country).filter_by(id=country_id).one()
    creator = getUserInfo(countryToDelete.user_id)
    if 'username' not in login_session or \
            creator.id != login_session['user_id']:
        return redirect('/login')
    if request.method == 'POST':
        session.delete(countryToDelete)
        session.commit()
        flash('country deleted!')
        return redirect(url_for('CountryList'))
    else:
        return render_template('delete-country.html', country=countryToDelete)


# edit country
@app.route('/country/<int:country_id>/edit', methods=['GET', 'POST'])
def EditCountry(country_id):
    editedCountry = session.query(Country).filter_by(
                                            id=country_id).one_or_none()
    creator = getUserInfo(editedCountry.user_id)
    if 'username' not in login_session or \
            creator.id != login_session['user_id']:
        return redirect('/login')
    if request.method == 'POST':
        if request.form['name']:
            editedCountry.name = request.form['name']
            session.add(editedCountry)
            session.commit()
            flash('country edited!')
            return redirect(url_for('CountryList'))
    else:
        return render_template('edit-country.html', country=editedCountry)


# add new City
@app.route('/country/<int:country_id>/new', methods=['GET', 'POST'])
def AddNewCity(country_id):
    country = session.query(Country).filter_by(id=country_id).one_or_none()
    creator = getUserInfo(country.user_id)
    if 'username' not in login_session or \
            creator.id != login_session['user_id']:
        return redirect('/login')
    if request.method == 'POST':
        newCity = City(
            name=request.form['name'],
            description=request.form['description'],
            country_id=country_id,
            user_id=login_session['user_id'])
        session.add(newCity)
        session.commit()
        flash('new city created!')
        return redirect(url_for('SingleCountry', country_id=country_id))
    else:
        return render_template('new-city.html', country_id=country_id)


# delete City
@app.route(
    '/country/<int:country_id>/city/<int:city_id>/delete',
    methods=['GET', 'POST'])
def DeleteCity(country_id, city_id):
    country = session.query(Country).filter_by(id=country_id).one_or_none()
    cityToDelete = session.query(City).filter_by(id=city_id).one_or_none()
    creator = getUserInfo(country.user_id)
    if 'username' not in login_session or \
            creator.id != login_session['user_id']:
        return redirect('/login')
    if request.method == 'POST':
        session.delete(cityToDelete)
        session.commit()
        flash('city deleted!')
        return redirect(url_for('SingleCountry', country_id=country_id))
    else:
        return render_template(
            'delete-city.html',
            country_id=country_id,
            city=cityToDelete)


# edit city
@app.route(
    '/country/<int:country_id>/city/<int:city_id>/edit',
    methods=['GET', 'POST'])
def EditCity(country_id, city_id):
    country = session.query(Country).filter_by(id=country_id).one_or_none()
    editedCity = session.query(City).filter_by(id=city_id).one_or_none()
    creator = getUserInfo(country.user_id)
    if 'username' not in login_session or \
            creator.id != login_session['user_id']:
        return redirect('/login')
    if request.method == 'POST':
        if request.form['name']:
            editedCity.name = request.form['name']
        if request.form['description']:
            editedCity.description = request.form['description']
        session.add(editedCity)
        session.commit()
        flash('city edited!')
        return redirect(url_for('SingleCountry', country_id=country_id))
    else:
        return render_template(
            'edit-city.html',
            country_id=country_id,
            city=editedCity)


# get user info functions
def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one_or_none()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one_or_none()
        return user.id
    except SQLAlchemyError:
        return None


def createUser(login_session):
    newUser = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(
        email=login_session['email']).one_or_none()
    # returns id of new Created user
    return user.id


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
