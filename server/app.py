#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from config import app, db, api, bcrypt
from models import User

class ClearSession(Resource):
    def delete(self):
        session.clear()  # Clear all session data
        return {}, 204

class Signup(Resource):
    def post(self):
        json = request.get_json()
        username = json.get('username')
        password = json.get('password')

        # Check if username already exists
        if User.query.filter_by(username=username).first():
            return {'error': 'Username already exists'}, 400

        # Create a new user instance and hash the password
        user = User(username=username)
        user.password_hash = password  # This will hash the password using bcrypt

        # Save user to the database
        db.session.add(user)
        db.session.commit()

        # Save user_id in the session
        session['user_id'] = user.id

        return user.to_dict(), 201

class CheckSession(Resource):
    def get(self):
        if 'user_id' not in session:
            return {}, 204  # No content if not authenticated
        
        user = User.query.get(session['user_id'])
        if user:
            return user.to_dict(), 200  # Return user details if found
        
        return {}, 204  # No content if user not found

class Login(Resource):
    def post(self):
        json = request.get_json()
        username = json.get('username')
        password = json.get('password')

        # Find the user by username
        user = User.query.filter_by(username=username).first()

        # Check if the user exists and the password is correct
        if user and bcrypt.check_password_hash(user.password_hash, password):
            # Store user_id in session
            session['user_id'] = user.id

            # Return only safe user fields (e.g., username)
            return {'username': user.username}, 200
        
        return {'error': 'Invalid username or password'}, 401  # 

class Logout(Resource):
    def delete(self):
        session.pop('user_id', None)  # Clear user_id from the session
        return {}, 204

# Add the resources to the API
api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
