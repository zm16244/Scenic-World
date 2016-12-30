# -*- coding: utf-8 -*-
####THINGS TO DO#####

#. change it so we don't have duplicate functions
#. stop double submit when you upload a photo
#. Add sort filter to restaurant and scenic pages
#. parse any entered text to protect against XSS


import cgi
import urllib
import json
import urllib2
import urlparse
import webapp2
import logging
import time
import webapp2_extras.appengine.auth.models
import re

from google.appengine.ext import ndb
from google.appengine.api import mail
from google.appengine.api import images
from google.appengine.ext import blobstore
from google.appengine.ext.webapp import blobstore_handlers
from google.appengine.ext.webapp.util import run_wsgi_app

from webapp2_extras import auth
from webapp2_extras import sessions
from webapp2_extras import security
from webapp2_extras.auth import InvalidAuthIdError
from webapp2_extras.auth import InvalidPasswordError
# coding: utf-8

###################################
####### USER AUTHENTICATION #######
###################################

PASSWORD_RESET_EMAIL = """
Dear %s,
Your password can be reset by clicking the following link:

%s

Thanks,
The WikiEats Team
"""

ACCOUNT_CONFIRM = """
Dear %s,
Please confirm your account by clicking the following link:

%s

Thanks,
The WikiEats Team
"""

SIGNUP_TEMPLATE = """
	<div class="input_form">
		<h1>Register</h1>
		<form action="/signup" method="POST">
			<input type="text" name="username" placeholder="Username" required/>
			<input type="text" name="email" placeholder="Email address" required/>
			<input type="password" name="password" placeholder="Password" required/>
			<input type="submit" value="Register" />
		</form>
	</div>
"""

LOGIN_TEMPLATE = """
		<form action="/login" method="POST">
			<input type="text" value="%s" name="username" placeholder="Username"/>
			<input type="password" name="password" placeholder="Password"/>
			<input type="submit" value="Login" />
		</form> 
		<ul>
			<li><a href="/forgot">Forgotten your password?</a></li>
			<li><a href="/signup" id="register">Register</a></li>
		</ul>
	</div> 
"""

RESET_PASSWORD_TEMPLATE = """
	<div class="input_form">
		<h1>Reset password</h1>
		<form action="/password" method="post">
			<input type="password" name="password" placeholder="New Password"/>
			<input type="password" name="confirm_password" placeholder="Confirm Password"/>
			<input type="hidden" name="t" value="%s" />
			<input type="submit" value="Update Password" />
		</form>
	</div>
"""

FORGOT_TEMPLATE = """
	<form class="form" action= "/forgot" method="POST">
		<input type="text" value="%s" name="username" placeholder="Username"/>
		<input type="submit" value="Send password reset link"/>
	</form>
"""

class User(webapp2_extras.appengine.auth.models.User):
	def set_password(self, raw_password):
		self.password = security.generate_password_hash(raw_password, length=12)

	@classmethod
	def get_by_auth_token(cls, user_id, token, subject='auth'):
		token_key = cls.token_model.get_key(user_id, subject, token)
		user_key = ndb.Key(cls, user_id)
		# Use get_multi() to save a RPC call.
		valid_token, user = ndb.get_multi([token_key, user_key])
		if valid_token and user:
			timestamp = int(time.mktime(valid_token.created.timetuple()))
			return user, timestamp

		return None, None

def user_required(handler):
  """
    Decorator that checks if there's a user associated with the current session.
    Will also fail if there's no session present.
  """
  def check_login(self, *args, **kwargs):
    auth = self.auth
    if not auth.get_user_by_session():
      self.redirect('/login', abort=True)
    else:
      return handler(self, *args, **kwargs)

  return check_login

class BaseHandler(webapp2.RequestHandler):
  @webapp2.cached_property
  def auth(self):
    """Shortcut to access the auth instance as a property."""
    return auth.get_auth()

  @webapp2.cached_property
  def user_info(self):
    """Shortcut to access a subset of the user attributes that are stored
    in the session.

    The list of attributes to store in the session is specified in
      config['webapp2_extras.auth']['user_attributes'].
    :returns
      A dictionary with most user information
    """
    return self.auth.get_user_by_session()

  @webapp2.cached_property
  def user(self):
    """Shortcut to access the current logged in user.

    Unlike user_info, it fetches information from the persistence layer and
    returns an instance of the underlying model.

    :returns
      The instance of the user model associated to the logged in user.
    """
    u = self.user_info
    return self.user_model.get_by_id(u['user_id']) if u else None

  @webapp2.cached_property
  def user_model(self):
    """Returns the implementation of the user model.

    It is consistent with config['webapp2_extras.auth']['user_model'], if set.
    """    
    return self.auth.store.user_model

  @webapp2.cached_property
  def session(self):
      """Shortcut to access the current session."""
      return self.session_store.get_session(backend="datastore")
      
      
  def display_message(self, message):
    """Utility function to display a template with a simple message."""
    self.response.write(message)

  # this is needed for webapp2 sessions to work
  def dispatch(self):
      # Get a session store for this request.
      self.session_store = sessions.get_store(request=self.request)

      try:
          # Dispatch the request.
          webapp2.RequestHandler.dispatch(self)
      finally:
          # Save all sessions.
          self.session_store.save_sessions(self.response)

class MainHandler(BaseHandler):
  def get(self):
    user = self.auth.get_user_by_session()
    self.response.write('<ul>')
    if user:
      self.response.write('<a href="/logout">Logout</a>')
    else:
      self.response.write('<li><a href="/signup">Register</a></li><li><a href="/login">Login</a></li>')
    self.response.write('<li><a href="/authenticated">Authenticated</a></li></ul>')

class SignupHandler(BaseHandler):
	def get(self):
		active = "register"
		writeNav(self, active)
		self.response.write(SIGNUP_TEMPLATE)
		pathway = '<a href="/">HOME</a> &gt Register'
		self.response.write(FOOTER_TEMPLATE.format(pathway))
		
	def post(self):
		user_name = self.request.get('username')
		email = self.request.get('email')
		password = self.request.get('password')

		unique_properties = ['email_address']
		user_data = self.user_model.create_user(user_name,
			unique_properties,
			email_address=email, name=user_name, password_raw=password,
			verified=False)
		if not user_data[0]: #user_data is a tuple
			self.display_message('Unable to create user for user %s because of duplicate keys %s' % (user_name, user_data[1]))
			return
		
		user = user_data[1]
		user_id = user.get_id()

		token = self.user_model.create_signup_token(user_id)

		verification_url = self.uri_for('verification', type='v', user_id=user_id, signup_token=token, _full=True)
		  
		message = mail.EmailMessage(sender="WikiEats Admin<wiki-eats@appspot.gserviceaccount.com>",subject="Account Confirmation Email",to="%s <%s>"% (user.name,user.email_address))
		message.body = ACCOUNT_CONFIRM % (user.name,verification_url)
		message.send()
		
		self.redirect('/confirmemailsent')
    
class ConfirmEmailSent(BaseHandler):
	def get(self):
		active = "emailsent"
		writeNav(self, active)
		self.response.write('<div style="margin-top:50px; font-family: Arial; font-size: 30px; text-align:center;"><p>A Confirmation email has been sent to your email address.</p><p>Please follow the attached link to validate your account.</p></div>')
		self.response.write(FOOTER_TEMPLATE.format(""))
	
class ForgotPasswordHandler(BaseHandler):
	def get(self):
		self._serve_page()

	def post(self):
		username = self.request.get('username')

		user = self.user_model.get_by_auth_id(username)
		if not user:
			logging.info('Could not find any user entry for username %s', username)
			self._serve_page(not_found=True)
			return

		user_id = user.get_id()
		token = self.user_model.create_signup_token(user_id)

		verification_url = self.uri_for('verification', type='p', user_id=user_id,
			signup_token=token, _full=True)

		message = mail.EmailMessage(sender="WikiEats Admin<wiki-eats@appspot.gserviceaccount.com>",subject="Password Reset Email",to="%s <%s>"% (user.name,user.email_address))
		message.body = PASSWORD_RESET_EMAIL % (user.name,verification_url)
		message.send()
		
		self.redirect('/forgotemailsent')
	  
	def _serve_page(self, not_found=False):
		username = self.request.get('username')
		active = "forgot"
		writeNav(self, active)
		self.response.write('<div class="input_form"><h1>Reset password</h1><p>Forgot your password? Click the link below to receive a link to reset your password.</p>')
		if not_found:
			self.response.write('<p style="color:red"><strong>Not found!</strong> We could not find any user with the given username.</p>')
		self.response.write(FORGOT_TEMPLATE % username)
		self.response.write('</div>')
		pathway = '<a href="/">HOME</a> &gt <a href="/">Login</a> &gt Forgot Password'
		self.response.write(FOOTER_TEMPLATE.format(pathway))

class ForgotEmailSent(BaseHandler):
	def get(self):
		active = "emailsent"
		writeNav(self, active)
		self.response.write('<div style="margin-top:50px; font-family: Arial; font-size: 30px; text-align:center;"><p>A Verification email has been sent to your email address.</p><p>Please follow the attached link to reset your password.</p></div>')
		self.response.write(FOOTER_TEMPLATE.format(""))

class VerificationHandler(BaseHandler):
  def get(self, *args, **kwargs):
    user = None
    user_id = kwargs['user_id']
    signup_token = kwargs['signup_token']
    verification_type = kwargs['type']

    # it should be something more concise like
    # self.auth.get_user_by_token(user_id, signup_token)
    # unfortunately the auth interface does not (yet) allow to manipulate
    # signup tokens concisely
    user, ts = self.user_model.get_by_auth_token(int(user_id), signup_token, 'signup')

    if not user:
      logging.info('Could not find any user with id "%s" signup token "%s"',
        user_id, signup_token)
      self.abort(404)
    
    # store user data in the session
    self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)

    if verification_type == 'v':
      # remove signup token, we don't want users to come back with an old link
      self.user_model.delete_signup_token(user.get_id(), signup_token)

      if not user.verified:
        user.verified = True
        user.put()
      
      active = "emailverified"
      writeNav(self, active)
      self.response.write('<div style="margin-top:50px; font-family: Arial; font-size: 30px; text-align:center;"><p>Your email address has been verified.</p></div>')
      self.response.write(FOOTER_TEMPLATE.format(""))
      return
    elif verification_type == 'p':
      # supply user to the page
      active = "verify"
      writeNav(self, active)
      self.response.write(RESET_PASSWORD_TEMPLATE %(signup_token))
      self.response.write(FOOTER_TEMPLATE.format(""))
    else:
      logging.info('verification type not supported')
      self.abort(404)

class SetPasswordHandler(BaseHandler):
  @user_required
  def post(self):
    password = self.request.get('password')
    old_token = self.request.get('t')

    if not password or password != self.request.get('confirm_password'):
      self.display_message('passwords do not match')
      return

    user = self.user
    user.set_password(password)
    user.put()

    # remove signup token, we don't want users to come back with an old link
    self.user_model.delete_signup_token(user.get_id(), old_token)
    
    self.redirect('/passwordupdated')
	
class PasswordUpdated(BaseHandler):
	def get(self):
		active = "passwordupdated"
		writeNav(self, active)
		self.response.write('<div style="margin-top:50px; font-family: Arial; font-size: 30px; text-align:center;"><p>Your password has been successfully updated!</p></div>')
		self.response.write(FOOTER_TEMPLATE.format(""))

class LoginHandler(BaseHandler):
  def get(self):
    self._serve_page()

  def post(self):
    username = self.request.get('username')
    password = self.request.get('password')
    try:
      u = self.auth.get_user_by_password(username, password, remember=True,
        save_session=True)
      self.redirect('/browse')
    except (InvalidAuthIdError, InvalidPasswordError) as e:
      logging.info('Login failed for user %s because of %s', username, type(e))
      self._serve_page(True)

  def _serve_page(self, failed=False):
    username = self.request.get('username')
    active = "login"
    writeNav(self, active)
    self.response.write('<div class="input_form"><h1>Login</h1>')

    if failed:
      self.response.write('<p><strong>Login failed!</strong> Check your credentials and try again.</p>')

    self.response.write(LOGIN_TEMPLATE % (username))
	
    pathway = '<a href="/browse">HOME2</a> &gt Login'
    self.response.write(FOOTER_TEMPLATE.format(pathway))

class LogoutHandler(BaseHandler):
  def get(self):
    self.auth.unset_session()
    self.redirect('/browse')

class AuthenticatedHandler(BaseHandler):
  @user_required
  def get(self):
    self.response.write('<h1>Congratulations %s!</h1><p>If you see this page, it means that you managed to log in successfully.</p>' % self.user.name)

config = {
  'webapp2_extras.auth': {
    'user_model': 'wikieats.User',
    'user_attributes': ['name','email_address']
  },
  'webapp2_extras.sessions': {
    'secret_key': 'YOUR_SECRET_KEY'
  }
}

HEADER_TEMPLATE = """
<html>
	<head>
		<link rel="stylesheet" type="text/css" href="/styles/image_grid.css">
		<link rel="stylesheet" type="text/css" href="/styles/star_rating.css">
		<link rel="stylesheet" type="text/css" href="/styles/navbar.css">
		<link rel="stylesheet" type="text/css" href="/styles/login.css">
		<link rel="stylesheet" type="text/css" href="/styles/list.css">
        <link rel="stylesheet" type="text/css" href="/styles/advanced.css">
    <script src="http://ajax.googleapis.com/ajax/libs/jquery/1.9.1/jquery.min.js"></script>
	</head>
	<body>

		<div style="position:fixed; left:0px; top:0px; height:110px; width:100%; opacity:0.7; background-image:url(../style/headpic.jpg); background-repeat: no-repeat; background-size: cover; z-index:100;">
			<div style="padding:5px;">
				<a href="/"><img src="/images/wikieats_logo.png" width="99px" height="99px"></a>
			</div>	
		</div>
"""
HEADER_TEMPLATE2 = """
<html>
    <head>
        <link type="text/css" rel="stylesheet" href="/styles/main.css" />
        <link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons">
        <link rel="stylesheet" href="https://code.getmdl.io/1.2.1/material.indigo-pink.min.css">
        <script defer src="https://code.getmdl.io/1.2.1/material.min.js"></script>
        <link href="https://fonts.googleapis.com/css?family=Source+Sans+Pro" rel="stylesheet">
        <title>SecnicWorld</title>
    </head>
    
    <body>
        <a href="/" class="main-title">
            SecnicWorld
        </a>
        
        <div class="control-area">
 
        </div>
        
        <div class="login-area">
            
                <a class="login-link" href="/login">login</a>
                |
                <a class="login-link" href="/signup">sign up</a>
            
             
        </div>    
        
        <div id="content">
        
    
    Welcome!

 
        </div>
		<div class="footer">
            <div class="credits">
                A APPLICATION from <strong>ANQI WANG ZHENGYANG MAO YUANZHOU LI</strong> • v2016.12.31 • Made with Code, Material Design, and Passion.
            </div>
            <div class="photocreds">
                Background Image: 
            </div>
        </div>
        
    </body>

</html>
"""

FOOTER_TEMPLATE = """
			</div>
			<div style="position:fixed; left:0px; bottom:0px; height:60px; width:100%; background:#15967E; z-index:100; ">
				<div class="pathway">
					{0}
				</div>
				
			</div>
		</body>
	</html>
"""
FOOTER_TEMPLATE2 = """
			</div>
			<div style="position:fixed; left:0px; bottom:0px; height:0px; width:0%; background:#15967E; z-index:-9999; ">
				<div class="pathway">
					{0}
				</div>
				
			</div>
		</body>
	</html>
"""
ADVANCED_TEMPLATE_1 = """
  <div class="input_form">
    <h1>Advanced Search</h1>
    <form action="/advancedSearch" method="post">
          <select name="city_link_adv"> 
          <option value="none" class="noselect">Select Location</option>
  """

ADVANCED_TEMPLATE_2 = """
        </select>
        <input type="text" name="scenic_name" placeholder="Name of scenic" class="required" required/>  
        <select name="price_select" id="price_select"> 
          <option value="anyPrice">Any Price</option>
          <option value="lessThan">Less Than</option>
        </select>
        <input type="text" name="price" id="price" placeholder="&pound">
        <select name="distance_select" id="distance_select"> 
          <option value="anyDistance">Any Distance</option>
          <option value="0.1"> &lt5 KM </option>
          <option value="1"> &lt20 KM </option>
          <option value="3"> &lt80 KM </option>
          <option value="5"> &lt200 KM </option>
          <option value="10"> &lt500 KM </option>
        </select>
        <input type="text" name="postcode" id="postcode" placeholder="Your Postcode">
      <input type="submit" value="Search" />
    </form>
    </div>
    <script type="text/javascript">



        $('#price').hide();
        $('#postcode').hide();
        $('#price_select').on('change', function (e) {
          var optionSelected = $("option:selected", this);
          var text = optionSelected.text();
          if(text == "Any Price"){
            $('#price').hide();
            $('#price').val('');
          }else{
           $('#price').show();
         }
        });

        $('#distance_select').on('change', function (e) {
          var optionSelected = $("option:selected", this);
          var text = optionSelected.text();
          if(text == "Any Distance"){
            $('#postcode').hide();
            $('#price').val('');
          }else{
           $('#postcode').show();
         }
        });

      
      </script>

"""


NAV_1 = """
	<div id='cssmenu'>
		<form action="/selectcity" method="post">
			<span class="dropdown">
				<select name="city_link" id="city_link">
					<option value="none" class="noselect">Select Location</option>
	"""

NAV_2 = """
				</select>
			</span>
			<span class="dropdown">
			<select name="rest_type" id="rest_type"> <option value="all">All landscapes</option>
				<option value="Human">Human</option>
				<option value="Natural">Natural</option>
			</select>
			</span>
			<input type="submit" value="GO" id="goButton">
			<a href="/advancedSearch"><div>ADVANCED SEARCH</div></a>
      <script type="text/javascript">
        var optionSelected = $("#city_link option:selected").text()
       
        if(optionSelected == "SelectCity"){
           $('#goButton').hide();
        }
         
        $("#goButton").click(function(event){
          var optionSelected = $("#city_link option:selected").text()
          if(optionSelected == "Select City"){
            alert('Please select a City');
            event.preventDefault();
          }
        });
      </script>
		</form>
		
		<ul>
"""

ADD_NEW_RESTAURANT_TEMPLATE = """
		<div class="input_form">
			<h1>Add Scenic Spots</h1>
			<form action="/postrestaurant2/%s?landscape=%s" method="POST">
				<input type="text" name="rest_name" placeholder="The Name of Scenic Spots" required/>
				<select name="rest_type">
					<option value="Human">Human</option>
					<option value="Natural">Natural</option>
				</select>
				<input type="text" name="rest_postcode" placeholder="Postcode"/>
				<input type="text" name="rest_phone" placeholder="Phone Number"/>
				<input type="submit" value="Submit" />
			</form>
		</div>
	</div>
"""



ADD_NEW_SCENIC_TEMPLATE = """
		<div class="input_form">
			<h1>Add Scenic</h1>
			{3}
			<form action="/addnewscenic/{0}/{1}?landscape={2}" method="POST">
				<input type="text" name="scenic_name" placeholder="Name of Scenic" required/>
				<input type="text" name="scenic_price" placeholder="Price (&pound)"/>
				<input type="submit" value="Submit" />
			</form>
		</div>
	</div>
"""

ENTER_POSTCODE_TEMPLATE = """
	<form action="/getPostcodeDistance" method="post">
		Postcode1:<div><input name="postcode1" value = "RH2 7BS"></div>
		Postcode2:<div><input name="postcode2" value = "BS6 5DQ"></div>
		</p>
		<div><input type="submit" value="Get Distance"></div>
	</form>
"""

#####################################
############### ADMIN ###############
#####################################
class admin(webapp2.RequestHandler):
	def get(self):
		#self.response.write(HEADER_TEMPLATE)
		self.response.write('<form action="/addAllCities" method="post">')
		self.response.write('<input type = "submit" value = "Add All Cities From File"></form>')
		self.response.write('<form action="/clearDatabase" method="post">')
		self.response.write('<input type = "submit" value = "Clear Database"></form>')
		self.response.write(FOOTER_TEMPLATE.format(""))

class addAllCities(webapp2.RequestHandler):
	def post(self):
		lines = [line.strip() for line in open('cities.text')]
		for line in lines:
			r = City()
			r.city = line
			r.put()
		self.redirect('/')

class clearDatabase(webapp2.RequestHandler):
	def post(self):
		ndb.delete_multi(
			City.query().fetch(keys_only=True)
			)
		ndb.delete_multi(
			Restaurant.query().fetch(keys_only=True)
			)
		ndb.delete_multi(
			Scenic.query().fetch(keys_only=True)
			)
		ndb.delete_multi(
			Photo.query().fetch(keys_only=True)
			)
		self.redirect('/')


class postcode(webapp2.RequestHandler):
	def get(self):
		self.response.write(ENTER_POSTCODE_TEMPLATE)
		self.response.write(FOOTER_TEMPLATE.format(""))


class getPostcodeDistance(webapp2.RequestHandler):
	def post(self):
		post1 = urllib.quote_plus(self.request.get('postcode1'))
		post2 = urllib.quote_plus(self.request.get('postcode2'))
		data = json.load(urllib2.urlopen('http://maps.googleapis.com/maps/api/distancematrix/json?origins='+post1+'&destinations='+post2+'&mode=driving&language=en-EN&sensor=false"'))
		if(data["rows"][0]["elements"][0]["status"] == 'OK'):
		#self.response.write(data)
			self.response.write(data["rows"][0]["elements"][0]["distance"]["value"] * 0.001)
		else:
			self.response.write('invalid postcode')
		self.response.write(FOOTER_TEMPLATE.format(""))



#####################################
########## DATABASE MODELS ##########
#####################################
class City(ndb.Model):
    city = ndb.StringProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)

class Restaurant(ndb.Model):
	name = ndb.StringProperty(required=True)
	landscape = ndb.StringProperty(required=True)
	postcode = ndb.StringProperty(required=True)
	phone = ndb.StringProperty(required=False)
	created = ndb.DateTimeProperty(auto_now_add=True)

class Scenic(ndb.Model):
	name = ndb.StringProperty(required=True)
	price = ndb.FloatProperty(required=True)
	averageRating = ndb.FloatProperty(required=True)
	numberOfPhotos = ndb.IntegerProperty(required=True)

class Photo(ndb.Model):
    rating = ndb.IntegerProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    review = ndb.StringProperty(required=False)
    blob_key = ndb.BlobKeyProperty(required=False)

######################################
############# FUNCTIONS ##############
######################################

def starRating(self, rating):
	if rating == 1:
		self.response.write('<img src="/images/1_star.png" style="display:inline;" height="40px" width="200px">')
	elif  rating == 1.5:
		self.response.write('<img src="/images/1-5_star.png" style="display:inline;" height="40px" width="200px">')
	elif  rating == 2:
		self.response.write('<img src="/images/2_star.png" style="display:inline;" height="40px" width="200px">')
	elif  rating == 2.5:
		self.response.write('<img src="/images/2-5_star.png" style="display:inline;" height="40px" width="200px">')
	elif  rating == 3:
		self.response.write('<img src="/images/3_star.png" style="display:inline;" height="40px" width="200px">')
	elif  rating == 3.5:
		self.response.write('<img src="/images/3-5_star.png" style="display:inline;" height="40px" width="200px">')
	elif  rating == 4:
		self.response.write('<img src="/images/4_star.png" style="display:inline;" height="40px" width="200px">')
	elif  rating == 4.5:
		self.response.write('<img src="/images/4-5_star.png" style="display:inline;" height="40px" width="200px">')
	elif  rating == 5:
		self.response.write('<img src="/images/5_star.png" style="display:inline;" height="40px" width="200px">')

def writeAdvanced(self):
  self.response.write(ADVANCED_TEMPLATE_1)
  cities = City.query().order(City.city)
  for c in cities:
      self.response.write('<option value="%s">%s</option>' % (c.key.id(), c.city))
  self.response.write(ADVANCED_TEMPLATE_2)


def writeNav(self, active):
		self.response.write(HEADER_TEMPLATE)
		self.response.write(NAV_1)
		cities = City.query().order(City.city)
		for c in cities:
			#self.response.write('<a href="/browse/%s">%s</a></p>' % (c.key.id(),c.city))
			self.response.write('<option value="%s">%s</option>' % (c.key.id(), c.city))
		self.response.write(NAV_2)
		
		u = self.auth.get_user_by_session()
		if u:
			greeting = ('<li class="last"><a href="/logout"><span>Logout</span></a></li>')
		elif active == "login":
			greeting = ('<li class="active"><a href="/login"><span>Login</span></a></li><li class="last"><a href="/signup"><span>Register</span></a></li>')
		elif active == "register":
			greeting = ('<li><a href="/login"><span>Login</span></a></li><li class="active last"><a href="/signup"><span>Register</span></a></li>')
		else:
			greeting = ('<li><a href="/login"><span>Login</span></a></li><li class="last"><a href="/signup"><span>Register</span></a></li>')
		self.response.write(greeting)
		
		self.response.write('</ul></div>')
		
		self.response.write('<div style="position:relative; top:175px; margin-bottom:80px;">')
		
def writeNav2(self, active):
		self.response.write(HEADER_TEMPLATE2)
		#self.response.write(NAV_1)
		#cities = City.query().order(City.city)
		#for c in cities:
			#self.response.write('<a href="/browse/%s">%s</a></p>' % (c.key.id(),c.city))
			#self.response.write('<option value="%s">%s</option>' % (c.key.id(), c.city))
		#self.response.write(NAV_2)
		
		#u = self.auth.get_user_by_session()
		#if u:
			#greeting = ('<li class="last"><a href="/logout"><span>Logout</span></a></li>')
		#elif active == "login":
			#greeting = ('<li class="active"><a href="/login"><span>Login</span></a></li><li class="last"><a href="/signup"><span>Register</span></a></li>')
		#elif active == "register":
			#greeting = ('<li><a href="/login"><span>Login</span></a></li><li class="active last"><a href="/signup"><span>Register</span></a></li>')
		#else:
			#greeting = ('<li><a href="/login"><span>Login</span></a></li><li class="last"><a href="/signup"><span>Register</span></a></li>')
		#self.response.write(greeting)
		
		#self.response.write('</ul></div>')
		
		#self.response.write('<div style="position:relative; top:175px; margin-bottom:80px;">')
		
##############################
########## BROWSING ##########
##############################	
class BrowseCities_firstpage(BaseHandler):
	def get(self):
		#result = Photo.query().order(-Photo.created).fetch(8)
		#check = False
		active = "browse1"
		writeNav2(self, active)
		self.response.write('<div style="display: inline-block; ">')
		#self.response.write('<p style="padding-left: 40px; font-size: 40px; font-family: \'Lucida Console\', \'Lucida Sans Typewriter\', monaco, \'Bitstream Vera Sans Mono\', monospace;"><b>Most Recent Uploads:</b></p></div>')

		self.response.write('<ul class="rig">')
		#for p in result:
			#check = True
			#d = p.key.parent().get()
			#scenic_name = d.name
			#r = d.key.parent().get()
			#rest_name = r.name
			#c = r.key.parent().get()
			#city = c.city
			#photo_url = images.get_serving_url(p.blob_key, size=None, crop=False, secure_url=None)
			#self.response.write('<li><a href="/browse/%s/%s/%s?landscape=all" style="text-decoration:none;"><div style="font-size:20px; font-family:Arial;"><p style="text-align:center;"><strong>%s (%s)</strong></p><p style="text-align:center;">%s</p></div><img src="%s" class="photo"/></br><div style="display: inline-block; "><div style="float:left; width: 100px; "><img src="/images/%s_star.png" style="display:inline;" height="20px" width="100px"></div></div></a></li>' % (c.key.id(), r.key.id(), d.key.id(), rest_name, city, scenic_name, photo_url, p.rating))
		self.response.write('</ul>')

		self.response.write('</div>')
		pathway = "HOME"
		self.response.write(FOOTER_TEMPLATE2.format(pathway))	
		
class BrowseCities(BaseHandler):
	def get(self):
		result = Photo.query().order(-Photo.created).fetch(8)
		check = False
		active = "browse"
		writeNav(self, active)
		self.response.write('<div style="display: inline-block; ">')
		self.response.write('<p style="padding-left: 40px; font-size: 40px; font-family: \'Bradley Hand ITC\', \'Bradley Hand ITC\', monaco, \'Bradley Hand ITC\', monospace;"><b>Most Recent Uploads:</b></p></div>')

		self.response.write('<ul class="rig">')
		for p in result:
			check = True
			d = p.key.parent().get()
			scenic_name = d.name
			r = d.key.parent().get()
			rest_name = r.name
			c = r.key.parent().get()
			city = c.city
			photo_url = images.get_serving_url(p.blob_key, size=None, crop=False, secure_url=None)
			self.response.write('<li><a href="/browse/%s/%s/%s?landscape=all" style="text-decoration:none;"><div style="font-size:20px; font-family:Arial;"><p style="text-align:center;"><strong>%s (%s)</strong></p><p style="text-align:center;">%s</p></div><img src="%s" class="photo"/></br><div style="display: inline-block; "><div style="float:left; width: 100px; "><img src="/images/%s_star.png" style="display:inline;" height="20px" width="100px"></div></div></a></li>' % (c.key.id(), r.key.id(), d.key.id(), rest_name, city, scenic_name, photo_url, p.rating))
		self.response.write('</ul>')

		self.response.write('</div>')
		pathway = "HOME"
		self.response.write(FOOTER_TEMPLATE.format(pathway))


class SelectCity(webapp2.RequestHandler):
  def post(self):
		city_link = self.request.get('city_link')
		landscape = self.request.get('rest_type')
		if(city_link == "none"):
			self.redirect('/browse')
		else:
			self.redirect('/browse/%s?landscape=%s' % (city_link, landscape))

class advancedSearch(BaseHandler):
	def get (self):
		writeNav(self, "browse")
		writeAdvanced(self)
		pathway = '<a href="/browse">HOME2</a> &gt Advanced Search'
		self.response.write(FOOTER_TEMPLATE.format(pathway))

	def post(self):
		city = self.request.get("city_link_adv")
		scenic = self.request.get("scenic_name")
		price = self.request.get("price") 
		postcode = self.request.get("postcode")
		distance = self.request.get("distance_select")

		self.redirect('/advancedSearch/result?city=%s&scenic=%s&price=%s&postcode=%s&distance=%s' % (city, scenic, price, postcode, distance))


class advancedSearchResult(BaseHandler):
  def get(self, result):
    sorted = self.request.get('order')
    writeNav(self, "browse")
    city = self.request.get('city')
    scenic = self.request.get('scenic')
    price = self.request.get('price')
    postcode = self.request.get('postcode')
    distance = self.request.get('distance')
    city_key = ndb.Key('City', int(city))
    result = Scenic.query(ancestor=city_key)

    if sorted == "zyx":
      ordering = -Scenic.name
    elif sorted == "top":
      ordering = -Scenic.averageRating
    elif sorted == "bottom":
      ordering = Scenic.averageRating
    elif sorted == "high":
      ordering = -Scenic.price
    elif sorted == "low":
      ordering = Scenic.price
    else:
      ordering = -Scenic.averageRating

    result = result.order(ordering)
    check = False
    self.response.write('<div class="liststatus">Showing all "%s" scenices in %s' % (scenic, city_key.get().city))
    if price:
      self.response.write(' for under &pound%s' % price)
    if postcode:
      self.response.write(', within %s KM of %s' % (distance, postcode))
    self.response.write('<form action="/advancedSearch/result" method="GET" class="sortorder"><select name="order" onchange="this.form.submit()">')

    
    self.response.write('<option value="top"')
    if sorted == "top":
      self.response.write('selected')
    self.response.write('>Rating (High-Low)</option>')
    
    
    self.response.write('<option value="bottom"')
    if sorted == "bottom":
      self.response.write('selected')
    self.response.write('>Rating (Low-High)</option>')

    self.response.write('<option value="abc"')
    if sorted == "abc":
      self.response.write('selected')
    self.response.write('>Alphabetical (A-Z)</option>')
    
    
    self.response.write('<option value="zyx"')
    if sorted == "zyx":
      self.response.write('selected')
    self.response.write('>Alphabetical (Z-A)</option>')
    
    
    
    self.response.write('<option value="high"')
    if sorted == "high":
      self.response.write('selected')
    self.response.write('>Price (High-Low)</option>')
    
    
    self.response.write('<option value="low"')
    if sorted == "low":
      self.response.write('selected')
    self.response.write('>Price (Low-High)</option>')
    
    self.response.write('<input type="hidden" value="%s" name="city">' % (city))
    self.response.write('<input type="hidden" value="%s" name="scenic">' % (scenic))
    self.response.write('<input type="hidden" value="%s" name="price">' % (price))
    self.response.write('<input type="hidden" value="%s" name="postcode">' % (postcode))
    self.response.write('<input type="hidden" value="%s" name="distance">' % (distance))
    self.response.write('</select></form>')
    self.response.write('</div>')
    if result:
      anyScenicFound = False;
      self.response.write('<div class="listdisplay">')
      for r in result:
        scenicFound = False
        if scenic in r.name:
          restaurant = r.key.parent().get()
          if postcode:
            post1 = urllib.quote_plus(postcode)
            post2 = urllib.quote_plus(restaurant.postcode)
            data = json.load(urllib2.urlopen('http://maps.googleapis.com/maps/api/distancematrix/json?origins='+post1+'&destinations='+post2+'&mode=driving&language=en-EN&sensor=false"'))
            if data:
              if(data["rows"][0]["elements"][0]["status"] == 'OK'):
                postDifference = data["rows"][0]["elements"][0]["distance"]["value"] * 0.001
                if (float(postDifference)) < float(distance):
                  if price:
                    if(float(r.price) < float(price)):
                      scenicFound = True
                  else:
                    scenicFound = True
              else:
                self.response.write('invalid postcode')
          elif price:
            if(float(r.price) < float(price)):
              scenicFound = True
          else:
            scenicFound = True
        if scenicFound == True:
          self.response.write('<div><a href="/browse/%s/%s/%s?landscape=all"> <strong>%s</strong> - %s (&pound%.2f) <div style="display:inline-block; float:right"><div style="display:table-cell; vertical-align;">' % (city, r.key.parent().id(), r.key.id(), restaurant.name, r.name, r.price))
          avg_rating = r.averageRating
          if avg_rating:
            rounded = round(avg_rating * 2) / 2
            starRating(self, rounded)
          self.response.write('</div></div></a></div>')
          anyScenicFound = True
      if anyScenicFound == False:
        self.response.write("NO RESULTS")
      self.response.write('</div>')
    else:
      self.response.write("NO RESULTS")
    self.response.write('<a href="/advancedSearch?city=%s&scenic=%s&price=%s&postcode=%s&distance=%s"><input class="addtolist" value="Try again"></a></p>' % (city, scenic, price, postcode, distance))
    pathway = '<a href="/">HOME</a> &gt <a href="/advancedSearch">Advanced Search</a> &gt Results'
    self.response.write(FOOTER_TEMPLATE.format(pathway))



class BrowseRestaurants(BaseHandler):
	def get(self, city):
		landscape = self.request.get('landscape')
		sorted = self.request.get('order')
		#parsed = urlparse.urlparse(url) 
		#print urlparse.parse_qs(parsed.query)['param']
		city_key = ndb.Key('City', int(city))
		if sorted == "zyx":
			result = Restaurant.query(ancestor = city_key).order(-Restaurant.name)
		else:
			result = Restaurant.query(ancestor = city_key).order(Restaurant.name)
		check = False
		active = "browse"
		writeNav(self, active)
		self.response.write('<div class="liststatus">Showing ' + landscape + " scenic spots in " + city_key.get().city + ':')
		self.response.write('<form action="/browse/%s" method="GET" class="sortorder"><select name="order" onchange="this.form.submit()">'% (city))
		
		self.response.write('<option value="abc"')
		if sorted == "abc":
			self.response.write('selected')
		self.response.write('>Alphabetical (A-Z)</option>')
		
		
		self.response.write('<option value="zyx"')
		if sorted == "zyx":
			self.response.write('selected')
		self.response.write('>Alphabetical (Z-A)</option>')
		
		self.response.write('<input type="hidden" value="%s" name="landscape">' % (landscape))
		self.response.write('</select></div><div class="listdisplay">')
		for r in result:
			if(r.landscape == landscape or landscape == 'all'):
				check = True
				self.response.write('<a href="/browse/%s/%s?landscape=%s">%s</a>' % (city, r.key.id(), landscape, r.name))
			
		if check == False:
			self.response.write('<p class="noitems">No Scenic spots in this city.</p>')
		
		self.response.write('</div>')
		
		u = self.auth.get_user_by_session()
		if u:
			self.response.write('<a href="/addnewrestaurant/%s?landscape=%s"><input class="addtolist" value="ADD NEW SCENIC SPOTS"></a></p>' % (city, landscape))
		
		pathway = '<a href="/">HOME</a> &gt ' + city_key.get().city
		self.response.write(FOOTER_TEMPLATE.format(pathway))
		
class BrowseScenices(BaseHandler):
	def get(self, city, rest):
		landscape = self.request.get('landscape')
		sorted = self.request.get('order')
		rest_key = ndb.Key('City', int(city), 'Restaurant', int(rest))
		city_key = ndb.Key('City', int(city))
		
		if sorted == "zyx":
			ordering = -Scenic.name
		elif sorted == "top":
			ordering = -Scenic.averageRating
		elif sorted == "bottom":
			ordering = Scenic.averageRating
		elif sorted == "high":
			ordering = -Scenic.price
		elif sorted == "low":
			ordering = Scenic.price
		else:
			ordering = Scenic.name
		
		result = Scenic.query(ancestor = rest_key).order(ordering)
		check = False
		active = "browse"
		writeNav(self, active)
  
		self.response.write('<div class="liststatus">Showing senic spots from the ' + rest_key.get().name + ' menu:')
		self.response.write('<form action="/browse/%s/%s?landscape=%s" method="GET" class="sortorder"><select name="order" onchange="this.form.submit()">'% (city, rest, landscape))
		
		self.response.write('<option value="abc"')
		if sorted == "abc":
			self.response.write('selected')
		self.response.write('>Alphabetical (A-Z)</option>')
		
		
		self.response.write('<option value="zyx"')
		if sorted == "zyx":
			self.response.write('selected')
		self.response.write('>Alphabetical (Z-A)</option>')
		
		
		self.response.write('<option value="top"')
		if sorted == "top":
			self.response.write('selected')
		self.response.write('>Rating (High-Low)</option>')
		
		
		self.response.write('<option value="bottom"')
		if sorted == "bottom":
			self.response.write('selected')
		self.response.write('>Rating (Low-High)</option>')
		
		
		self.response.write('<option value="high"')
		if sorted == "high":
			self.response.write('selected')
		self.response.write('>Price (High-Low)</option>')
		
		
		self.response.write('<option value="low"')
		if sorted == "low":
			self.response.write('selected')
		self.response.write('>Price (Low-High)</option>')
		
		self.response.write('<input type="hidden" value="%s" name="landscape"' % (landscape))
		self.response.write('</select></form></div><div class="listdisplay">')
		for d in result:
			check = True
			d = Scenic.get_by_id(d.key.id(), d.key.parent())
			self.response.write('<a href="/browse/%s/%s/%s?landscape=%s">%s (&pound%.2f) <div style="display:inline-block; float:right"><div style="display:table-cell; vertical-align;">' % (city, rest, d.key.id(), landscape, d.name, d.price))
			
			avg_rating = d.averageRating
			if avg_rating:
				rounded = round(avg_rating* 2) / 2
				starRating(self, rounded)
				
			self.response.write('</div></div></a>')
		if check == False:
			self.response.write('<p class="noitems">No scenices in this scenic spots.</p>')
		
		self.response.write('</div>')
		
		u = self.auth.get_user_by_session()
		if u:
			self.response.write('<a  href="/addnewscenic/%s/%s?landscape=%s"><input class="addtolist" value="ADD NEW SCENIC"></a></p>' % (city, rest, landscape))
		
		pathway = '<a href="/">HOME</a> &gt <a href="/browse/%s?landscape=%s">%s</a> &gt %s' % (city, landscape, city_key.get().city, rest_key.get().name)
		self.response.write(FOOTER_TEMPLATE.format(pathway))
		
class DisplayScenic(BaseHandler):
	def get(self, city, rest, scenic):
		landscape = self.request.get('landscape')
		photo_key = ndb.Key('City', int(city), 'Restaurant', int(rest), 'Scenic' , int(scenic))
		rest_key = ndb.Key('City', int(city), 'Restaurant', int(rest))
		city_key = ndb.Key('City', int(city))
		result = Photo.query(ancestor = photo_key).order(-Photo.created).fetch(10)
		check = False
		active = "display"
		writeNav(self, active)
		d = Scenic.get_by_id(photo_key.id(), photo_key.parent())
		self.response.write('<div style="display: inline-block; ">')
		self.response.write('<div style="margin: auto; float: left; display: inline-block; width: 600px;"><p style=" padding-left: 40px; font-size: 40px; font-family: \'Lucida Console\', \'Lucida Sans Typewriter\', monaco, \'Bitstream Vera Sans Mono\', monospace;"><b>%s </b>&pound%.2f</p></div>' % (d.name, d.price))

		avg_rating = d.averageRating
		if avg_rating:
			rounded = round(avg_rating* 2) / 2
			self.response.write('<div style="float:left; display: inline-block; width: 430px; margin: auto; top: 0; bottom: 0; vertical-align: middle; padding:40px 0px; font-size:13px; font-family:Arial;">')
			starRating(self, rounded)
			self.response.write('(Rating of %.2f based on %d ratings)</div></div>' % (avg_rating,d.numberOfPhotos))
		
		self.response.write('<ul class="rig">')
		for p in result:
			check = True
			photo_url = images.get_serving_url(p.blob_key, size=None, crop=False, secure_url=None)
			self.response.write('<li><img src="%s" class="photo"/></br><div style="display: inline-block; "><div style="float:left; width: 100px; "><img src="/images/%s_star.png" style="display:inline;" height="20px" width="100px"></div></div><p>%s</p></li>' % (photo_url, p.rating, p.review))
		self.response.write('</ul>')
		
		if check == False:
			self.response.write('<p class="noitems">No photos of this scenic.</p>')
		
		
		u = self.auth.get_user_by_session()
		if u:
			self.response.write('<a href="/uploadPhotoPage/%s/%s/%s?landscape=%s"><input class="addtolist" value="Upload"></a></p>' % (city, rest, scenic, landscape))
			
		city_link = '<a href="/browse/%s?landscape=%s">%s</a>' % (city, landscape, city_key.get().city)
		rest_link = '<a href="/browse/%s/%s?landscape=%s">%s</a>' % (city, rest, landscape, rest_key.get().name)
		pathway = '<a href="/">HOME</a> &gt %s &gt %s &gt %s' % (city_link, rest_link, photo_key.get().name)
		self.response.write(FOOTER_TEMPLATE.format(pathway))

class AddNewRestaurant(BaseHandler):
	def get(self, city):
		landscape = self.request.get('landscape')
		city_key = ndb.Key('City', int(city))
		active = "restaurant"
		writeNav(self, active)
		self.response.out.write(ADD_NEW_RESTAURANT_TEMPLATE % (city, landscape))
		pathway = '<a href="/">HOME</a> &gt <a href="/browse/%s?landscape=%s">%s</a> &gt Add New Restaurant' % (city, landscape, city_key.get().city)
		self.response.write(FOOTER_TEMPLATE.format(pathway))
		
class PostRestaurant2(webapp2.RequestHandler):
    def post(self, city):
    	landscape = self.request.get('landscape')
        rkey = ndb.Key('City', int(city))
        if rkey.get() == None:
            self.redirect('/')
        else:
            r = Restaurant(parent= rkey)
            r.name = self.request.get('rest_name')
            rtype = self.request.get('rest_type')
            r.landscape = rtype
            r.postcode = self.request.get('rest_postcode')
            r.phone = self.request.get('rest_phone')
            r.put()
            check2 = False
            while check2 == False:
                result = Restaurant.query(ancestor = ndb.Key('City', int(city))).filter(Restaurant.name == r.name)
                for r in result:
                    check2 = True
                    self.redirect('/browse/%s?landscape=%s' % (city, rtype))
	


class AddNewScenic(BaseHandler, ):  
  def get(self, city, rest):
		self._serve_page(city, rest)

  def post(self, city, rest):
    pattern = "(?<!.)\d+([.]\d{2})?(?!.)"
    check = re.compile(pattern)
    if not check.search(self.request.get('scenic_price')):
      self._serve_page(city, rest, invalid_price=True)
      return

    landscape = self.request.get('landscape')
    rkey = ndb.Key('City', int(city), 'Restaurant', int(rest))
    if rkey.get() == None:
      self.redirect('/browse/%s/%s?landscape=%s' % (city, rest, landscape))
    else:
      r = Scenic(parent=rkey)
      r.name = self.request.get('scenic_name')
      r.price = float(self.request.get('scenic_price'))
      r.averageRating = 0.0
      r.numberOfPhotos = 0
      r.put()
      check = False
      while check == False:
        result = Scenic.query(ancestor = rkey).filter(Scenic.name == r.name)
        for r in result:
          check = True
          self.redirect('/browse/%s/%s?landscape=%s' % (city, rest,landscape))

  def _serve_page(self, city, rest, invalid_price=False):
    landscape = self.request.get('landscape')
    rest_key = ndb.Key('City', int(city), 'Restaurant', int(rest))
    city_key = ndb.Key('City', int(city))
    active = "scenic"
    writeNav(self, active)
    error = "<p></p>"
    if invalid_price:
      error = "<p style='color:red;'>Please enter a valid price (eg 10.00) </p>"
    self.response.out.write(ADD_NEW_SCENIC_TEMPLATE.format(city, rest, landscape, error))

    city_link = '<a href="/browse/%s?landscape=%s">%s</a>' % (city, landscape, city_key.get().city)
    rest_link = '<a href="/browse/%s/%s?landscape=%s">%s</a>' % (city, rest, landscape, rest_key.get().name)
    pathway = '<a href="/">HOME</a> &gt %s &gt %s &gt Add New Scenic' % (city_link, rest_link)
    self.response.write(FOOTER_TEMPLATE.format(pathway))

					
##################################
########## PHOTO UPLOAD ##########
##################################
class uploadPhotoPage(BaseHandler):
    def get(self, city, rest, scenic):
		landscape = self.request.get('landscape')
		photo_key = ndb.Key('City', int(city), 'Restaurant', int(rest), 'Scenic' , int(scenic))
		rest_key = ndb.Key('City', int(city), 'Restaurant', int(rest))
		city_key = ndb.Key('City', int(city))
		upload_url = blobstore.create_upload_url('/upload/%s/%s/%s?landscape=%s' % (city, rest, scenic, landscape))
		active = "upload"
		writeNav(self, active)
		self.response.out.write('<form action="%s" method="POST" enctype="multipart/form-data">' % upload_url)
		self.response.out.write("""
				<div class="input_form">
					<h1>Upload Image</h1>
					<form action="/postscenic2/%s/%s?landscape=%s" method="POST">
						<input type="file" name="file" placeholder="Browse..." required/>
						<textarea name="review" rows="3" cols="60" placeholder="Write a Review"></textarea>
									
						<div class="rating">     
							<input type="radio" name="stars" id="5_stars" value="5" >
							<label class="stars" for="5_stars">5</label>
							<input type="radio" name="stars" id="4_stars" value="4" >
							<label class="stars" for="4_stars">4</label>
							<input type="radio" name="stars" id="3_stars" value="3" >
							<label class="stars" for="3_stars"></label>
							<input type="radio" name="stars" id="2_stars" value="2" >
							<label class="stars" for="2_stars"></label>
							<input type="radio" name="stars" id="1_stars" value="1" >
							<label class="stars" for="1_stars"></label>
							<input type="radio" name="stars" id="0_stars" value="0" selected="selected">
						</div>
						<input type="submit"name="submit" value="Submit">
					</form>
				</div>
			</div>
                 
            """)
		city_link = '<a href="/browse/%s?landscape=%s">%s</a>' % (city, landscape, city_key.get().city)
		rest_link = '<a href="/browse/%s/%s?landscape=%s">%s</a>' % (city, rest, landscape, rest_key.get().name)
		photo_link = '<a href="/browse/%s/%s/%s?landscape=%s">%s</a>' % (city, rest, scenic, landscape, photo_key.get().name)
		pathway = '<a href="/">HOME</a> &gt %s &gt %s &gt %s &gt Upload Image' % (city_link, rest_link, photo_link)
		self.response.write(FOOTER_TEMPLATE.format(pathway))



class UploadHandler(blobstore_handlers.BlobstoreUploadHandler):
    def post(self, city, rest, scenic):
		try:
			landscape = self.request.get('landscape')
			upload_files = self.get_uploads()
			blob_info = upload_files[0]
			rkey = ndb.Key('City', int(city), 'Restaurant', int(rest), 'Scenic' , int(scenic))
			r = Photo(parent = rkey)
			r.review = self.request.get('review')
			r.blob_key = blob_info.key()
			r.rating = int(self.request.get('stars'))
			r.put()
			q = rkey.get()
			photos = Photo.query(ancestor=rkey)
			numberOfPhotos = 0
			n = 0.0
			avg_rating = 0
			for p in photos:
				if p.rating:
					numberOfPhotos += 1
					n = n + p.rating
			if photos.count() > 0:
				avg_rating = n / (photos.count())
			q.averageRating = avg_rating
			q.numberOfPhotos = numberOfPhotos
			q.put()
			self.redirect('/browse/%s/%s/%s?landscape=%s' % (city, rest, scenic, landscape))
		except:
			self.redirect('/uploadPhotoPage/%s/%s/%s?landscape=%s' % (city, rest, scenic, landscape))
			

class ServeHandler(blobstore_handlers.BlobstoreDownloadHandler):
	def get(self, resource):
		resource = str(urllib.unquote(resource))
		blob_info = blobstore.BlobInfo.get(resource)
		self.send_blob(blob_info)
		

application = webapp2.WSGIApplication([
    ('/',BrowseCities_firstpage),
	#('/b', BrowseCities),
	###### ADMIN#####
	('/admin', admin),
	('/addAllCities', addAllCities),
	('/clearDatabase', clearDatabase),
	('/postcode', postcode),
	('/getPostcodeDistance', getPostcodeDistance),

	##### BROWSING #####
	('/browse1', BrowseCities_firstpage),
    ('/browse', BrowseCities),
    ('/selectcity', SelectCity),
    ('/browse/([^/]+)?', BrowseRestaurants),
    ('/browse/([^/]+)?/([^/]+)?', BrowseScenices),
    ('/browse/([^/]+)?/([^/]+)?/([^/]+)?', DisplayScenic),
    ('/advancedSearch', advancedSearch),
    ('/advancedSearch/([^/]+)?', advancedSearchResult),

	##### ADD WHILST BROWSING #####
    ('/addnewrestaurant/([^/]+)?', AddNewRestaurant),
	('/postrestaurant2/([^/]+)?', PostRestaurant2),
    ('/addnewscenic/([^/]+)?/([^/]+)?', AddNewScenic),
	
	
	##### USER AUTHENTICATION #####
    ('/signup', SignupHandler),
	('/confirmemailsent', ConfirmEmailSent),
    webapp2.Route('/<type:v|p>/<user_id:\d+>-<signup_token:.+>',handler=VerificationHandler, name='verification'),
    ('/password', SetPasswordHandler),
    ('/passwordupdated', PasswordUpdated),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler),
    ('/forgot', ForgotPasswordHandler),
	('/forgotemailsent', ForgotEmailSent),
    ('/authenticated', AuthenticatedHandler),
	
    
	##### IMAGE UPLOAD AND SERVING #####
	('/uploadPhotoPage/([^/]+)?/([^/]+)?/([^/]+)?', uploadPhotoPage),
	('/upload/([^/]+)?/([^/]+)?/([^/]+)?', UploadHandler),
    ('/serve/([^/]+)?', ServeHandler),
	
], debug=True, config=config)

logging.getLogger().setLevel(logging.DEBUG)
