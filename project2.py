from flask import Flask, render_template, request, redirect,jsonify, url_for, flash

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User

#imports for login session
from flask import session as login_session
import random, string

#Serverside script

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
  open('client_secrets.json','r').read())['web']['client_id']
APPLICATION_NAME = "menupage"

#Connect to Database and create database session
engine = create_engine('sqlite:///restaurantmenuwithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()



#cerat a sate token to prevent request forgery
#store it in the session for later validation
@app.route('/login')
def showLogin():
    #randomized with each GEt request (url refresh) sent to localhost:5000/login
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    #return "The current session state is %s" %login_session['state']
    return render_template('login.html', STATE = state)

#serverside code to validate code and retrive user info
#accepts authorization code from client, exchange for access token
# uses it to make API call to the OAuth server and responds to the client
@app.route('/gconnect', methods=['POST'])
def gconnect():
    print ("State:"+ login_session['state'])
    print ("State:"+ request.args.get('state'))
    if request.args.get('state') != login_session['state']:
      response = make_response(json.dumps('Invalid state parameter'), 401)
      response.headers['Content-Type'] = 'application/json'
      return response
    code = request.data
    try:
      #upgrade the authorization code into a credentials object
      oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
      oauth_flow.redirect_uri = 'postmessage'
      credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
      response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
      response.headers['Content-Type'] = 'application/json'
      return response

    #Check that the access token is valid
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'%access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    #if there was an error in access token info, abort
    if result.get('error') is not None:
      response = make_response(json.dumps(result.get('error')), 500)
      response.headers['Content-Type'] = 'application/json'
      return response
    # Verify that the access token is used for intended user
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
      response = make_response(json.dumps("Token's user ID does not match given user ID"), 401)
      response.headers['Content-Type'] = 'application/json'
      return response
    if result['issued_to'] != CLIENT_ID:
      response = make_response(json.dumps("Token's client ID does match app's Client ID"), 401)
      print "Token's client ID does noat match app's"
      response.headers['Content-Type'] = 'application/json'
      return response
    #check to see if user is already logged in
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
      response = make_response(json.dumps('Current user is already connected.'), 200)
      response.headers['Content-Type'] = 'application/json'
      return response

    #store the access token in the session for later use
    login_session['credentials'] = credentials
    login_session['gplus_id'] = gplus_id

    #Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt':'json'}
    answer = requests.get(userinfo_url, params = params)
    data = json.loads(answer.text)

    login_session['username'] = data["name"]
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'

    user_id = getUserID(login_session['email'])
    if  user_id == None:
      user_id = createUser(login_session)

    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 200 px; border-radius: 150px; -webkit-border-radius: 150px; -moz-border-radius: 150px;"> '
    flash("you are now logged in as %s"%login_session['username'])
    print "done!"
    return output

@app.route('/gdisconnect')
def gdisconnect():
  #only disconnect a connected user
  credentials = login_session.get('credentials')
  if credentials is None:
    response = make_response(json.dumps('Current user is not connected'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response
  access_token = credentials.access_token
  url = "https://accounts.google.com/o/oauth2/revoke?token=%s" % access_token
  h = httplib2.Http()
  result = h.request(url, 'GET')[0]
  print result
  print "!!!!!!!!access_token:"+access_token

  if result['status'] == '200':
    #reset the user's session
    del login_session['credentials']
    del login_session['gplus_id']

    response = make_response(json.dumps('Successfully disconnected.'), 200)
    response.headers['Content-Type'] = 'application/json'
    return response
  else:
    response = make_response(json.dumps('Failed to revoke token for given user.'), 400)
    response.headers['Content-Type'] = 'application/json'
    return response

@app.route('/fbconnect', methods=['POST'])
def fbconnect():
  if request.args.get('state') != login_session['state']:
    response = make_response(json.dumps('Invalid state parameter.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response
  access_token = request.data

  #Exchange client token for long-lived server-side token with GET /oauth/access_token?grant_type=fb_exchange_token&client_id=
  #{app-id}&client_secret = {app-secret}&fb_exchange_token={short-lived-token}
  app_id = json.loads(open('fb_client_secrets.json','r').read()) ['web']['app_id']
  app_secret = json.loads(open('fb_client_secrets.json', 'r').read()) ['web']['app_secret']
  url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s'%(app_id, app_secret, access_token)
  h = httplib2.Http()
  result = h.request(url, 'GET')[1]

  #Use token to getuser info from API
  userinfo_url = "httlps://graph.facebook.com/v2.2/me"
  #strip expire tag from access token
  token = result.split('&')[0]
  login_session['access_token'] = token.split("=")[1]

  print "!!!!!!!" + result

  url = "https://graph.facebook.com/v2.2/me?%s"%token
  print url
  h=httplib2.Http()
  result = h.request(url,'GET')[1]
  data = json.loads(result)
  print "+++++++Got facebook data:" + data['name'] + "+++++" + data['id']

  login_session['provider'] = 'facebook'
  login_session['username'] = data['name']
  if 'email' in data:
    login_session['email'] = data['email']
  else:
    login_session['email'] = 'a1p9e86@gmail.com'
  login_session['facebook_id'] = data['id']

  #Seperate API call to retrieve picture
  url = "https://graph.facebook.com/v2.2/me/picture?%s&redirect=0&height-200&width=200"%token
  h = httplib2.Http();
  result = h.request(url, 'GET')[1]
  data = json.loads(result)
  if 'data' in data:
    if 'url' in data['data']:
      login_session['picture'] = data["data"]["url"]

  user_id = getUserID(login_session['email'])
  if not user_id:
    user_id = createUser(login_session)
  login_session['user_id'] = user_id

  output = ''
  output += '<h1>Welcome, '
  output += login_session['username']
  output += '!</h1>'
  if 'picture' in login_session:
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 200 px; border-radius: 150px; -webkit-border-radius: 150px; -moz-border-radius: 150px;"> '
  flash("you are now logged in as %s"%login_session['username'])
  print "done!"
  return output

@app.route('/fbdisconnect')
def fbdisconnect():
  facebook_id = login_session['facebook_id']
  access_token = login_session['access_token']

  url = "https://graph.facebook.com/%s/permissions?access_token=%s"%(facebook_id, access_token)
  h = httplib2.Http()
  result = h.request(url,'DELETE')[1]
  print result
  del login_session['facebook_id']
  return "you have been logged out"

@app.route('/disconnect')
def disconnect():
  if 'provider' in login_session:
    print "++++++++" + login_session['provider'] +"+++++++"
    if login_session['provider'] == 'google':
      gdisconnect()

    if login_session['provider'] == 'facebook':
      print "++++++++ calling fbdisconnect()! " + login_session['provider'] +"+++++++"
      fbdisconnect()

    del login_session['username']
    del login_session['email']
    del login_session['picture']
    del login_session['user_id']
    del login_session['provider']
    flash("You have successfully been logged out.")
  else:
    flash("you are not logged in to begin with!")
  return redirect(url_for('showRestaurants'))

#JSON APIs to view Restaurant Information
@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id = restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    Menu_Item = session.query(MenuItem).filter_by(id = menu_id).one()
    return jsonify(Menu_Item = Menu_Item.serialize)

@app.route('/restaurant/JSON')
def restaurantsJSON():
    restaurants = session.query(Restaurant).all()
    return jsonify(restaurants= [r.serialize for r in restaurants])


#Show all restaurants
@app.route('/')
@app.route('/restaurant/')
def showRestaurants():

  restaurants = session.query(Restaurant).order_by(asc(Restaurant.name))
  if 'username' not in login_session:
    return render_template('publicrestaurants.html', restaurants = restaurants)
  else:
    return render_template('restaurants.html', restaurants = restaurants)

#Create a new restaurant
@app.route('/restaurant/new/', methods=['GET','POST'])
def newRestaurant():
  print "!!!!!problem with login_session!!!!!!"
  print login_session
  if 'username' not in login_session:
    return redirect('/login')
  if request.method == 'POST':
      newRestaurant = Restaurant(name = request.form['name'], user_id = login_session['user_id'])
      session.add(newRestaurant)
      flash('New Restaurant %s Successfully Created' % newRestaurant.name)
      session.commit()
      return redirect(url_for('showRestaurants'))
  else:
      return render_template('newRestaurant.html')

#Edit a restaurant
@app.route('/restaurant/<int:restaurant_id>/edit/', methods = ['GET', 'POST'])
def editRestaurant(restaurant_id):
  if 'username' not in login_session:
    return redirect('/login')
  editedRestaurant = session.query(Restaurant).filter_by(id = restaurant_id, user_id = login_session['user_id']).one()
  print editedRestaurant
  if editedRestaurant == None:
    flash("You don't have permission to edit this restaurant. Return to main menu...")
    return render_template('publicmenu.html')

  if request.method == 'POST':
      if request.form['name']:
        editedRestaurant.name = request.form['name']
        flash('Restaurant Successfully Edited %s' % editedRestaurant.name)
        return redirect(url_for('showRestaurants'))
  else:
    return render_template('editRestaurant.html', restaurant = editedRestaurant)

#Delete a restaurant
@app.route('/restaurant/<int:restaurant_id>/delete/', methods = ['GET','POST'])
def deleteRestaurant(restaurant_id):
  if 'username' not in login_session:
    return redirect('/login')
  restaurantToDelete = session.query(Restaurant).filter_by(id = restaurant_id).one()
  if restaurantToDelete.user_id == login_session['user_id']:
    if request.method == 'POST':
      session.delete(restaurantToDelete)
      flash('%s Successfully Deleted' % restaurantToDelete.name)
      session.commit()
      return redirect(url_for('showRestaurants'))
    else:
      return render_template('deleteRestaurant.html',restaurant = restaurantToDelete)
  else:
    flash("You don't have permission to delete %s"%restaurantToDelete.name)
    return redirect(url_for('showRestaurants'))

#Show a restaurant menu
@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def showMenu(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id = restaurant_id).all()
    creator = getUserInfo(restaurant.user_id)
    if 'user_id' in login_session:
      user_id = login_session['user_id']
      if restaurant.user_id == user_id:
        return render_template('menu.html', items = items, restaurant = restaurant)
    return render_template('publicmenu.html', items = items, restaurant = restaurant, creator = creator)



#Create a new menu item
@app.route('/restaurant/<int:restaurant_id>/menu/new/',methods=['GET','POST'])
def newMenuItem(restaurant_id):
  if 'username' not in login_session:
    return redirect('/login')
  restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
  if restaurant.user_id == login_session['user_id']:
    if request.method == 'POST':
        newItem = MenuItem(name = request.form['name'], description = request.form['description'], price = request.form['price'],
          course = request.form['course'], restaurant_id = restaurant_id, user_id = login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash('New Menu %s Item Successfully Created' % (newItem.name))
        return redirect(url_for('showMenu', restaurant_id = restaurant_id))
    else:
        return render_template('newmenuitem.html', restaurant_id = restaurant_id)
  else:
    flash("You don't have permission to add menu to this restaurant.")
    return redirect(url_for('showMenu', restaurant_id = restaurant_id))

#Edit a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit', methods=['GET','POST'])
def editMenuItem(restaurant_id, menu_id):
    if 'username' not in login_session:
      return redirect('/login')
    editedItem = session.query(MenuItem).filter_by(id = menu_id).one()
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    if restaurant.user_id == login_session['user_id']:
      if request.method == 'POST':
          if request.form['name']:
              editedItem.name = request.form['name']
          if request.form['description']:
              editedItem.description = request.form['description']
          if request.form['price']:
              editedItem.price = request.form['price']
          if request.form['course']:
              editedItem.course = request.form['course']
          session.add(editedItem)
          session.commit()
          flash('Menu Item Successfully Edited')
          return redirect(url_for('showMenu', restaurant_id = restaurant_id))
      else:
          return render_template('editmenuitem.html', restaurant_id = restaurant_id, menu_id = menu_id, item = editedItem)
    else:
      flash("You don't have permission to edit menu of this restaurant %s"%restaurant.name)
      return redirect(url_for('showMenu', restaurant_id = restaurant_id))


#Delete a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete', methods = ['GET','POST'])
def deleteMenuItem(restaurant_id,menu_id):
    if 'username' not in login_session:
      return redirect('/login')
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    itemToDelete = session.query(MenuItem).filter_by(id = menu_id).one()
    if restaurant.user_id == login_session['user_id']:
      print "User _id is checked!!!!!!!!!!!"
      if request.method == 'POST':
          session.delete(itemToDelete)
          session.commit()
          flash('Menu Item Successfully Deleted')
          return redirect(url_for('showMenu', restaurant_id = restaurant_id))
      else:
          return render_template('deleteMenuItem.html', item = itemToDelete)
    else:
      return redirect(url_for('showMenu', restaurant_id = restaurant_id))


def createUser(login_session):
  newUser = User(name = login_session['username'], picture = login_session['picture'], email = login_session['email'])
  session.add(newUser)
  session.commit()
  user = session.query(User).filter_by(email = login_session['email']).one()
  return user.id

def getUserInfo(user_id):
  user = session.query(User).filter_by(id = user_id).one()
  return user

def getUserID(email):
  try:
    user = session.query(User).filter_by(email = email).one()
    return user.id
  except:
    return None

if __name__ == '__main__':
  app.secret_key = 'super_secret_key'
  app.debug = True
  app.run(host = '0.0.0.0', port = 5000)
