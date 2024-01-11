# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from datetime import datetime, timezone, timedelta

from functools import wraps

from flask import request
from flask_restx import Api, Resource, fields

import jwt

from .models import Post, db, Users, Avatar, JWTTokenBlocklist
from .config import BaseConfig
import requests


from googleapiclient.discovery import build
from google.oauth2 import service_account

# Google Drive API setup
SERVICE_ACCOUNT_FILE = 'luen-410907-53f3167bda0c.json'
SCOPES = ['https://www.googleapis.com/auth/drive.readonly']
credentials = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE, scopes=SCOPES)

service = build('drive', 'v3', credentials=credentials)



rest_api = Api(version="1.0", title="Users API")


"""
    Flask-Restx models for api request and response data
"""

signup_model = rest_api.model('SignUpModel', {"username": fields.String(required=True, min_length=2, max_length=32),
                                              "email": fields.String(required=True, min_length=4, max_length=64),
                                              "password": fields.String(required=True, min_length=4, max_length=16)
                                              })

login_model = rest_api.model('LoginModel', {"email": fields.String(required=True, min_length=4, max_length=64),
                                            "password": fields.String(required=True, min_length=4, max_length=16)
                                            })

user_edit_model = rest_api.model('UserEditModel', {"userID": fields.String(required=True, min_length=1, max_length=32),
                                                   "username": fields.String(required=True, min_length=2, max_length=32),
                                                   "email": fields.String(required=True, min_length=4, max_length=64)
                                                   })

                                                

admin_avatar_model = rest_api.model('AdminAvatar', {
    'user_id': fields.Integer(required=True, description='ID of the user for whom the avatar is being created'),
    'name': fields.String(required=True, description='Name of the avatar'),
    'profile_image_id': fields.String(required=False, description='Profile image URL of the avatar'),
    'followers': fields.Integer(required=False, default=0, description='Number of followers of the avatar'),
    'following': fields.Integer(required=False, default=0, description='Number of users the avatar is following'),
})


avatar_model = rest_api.model('Avatar', {
    'name': fields.String(required=True, description='Name of the avatar'),
    'profile_image_id': fields.String(required=False, description='Profile image URL of the avatar'),
    'followers': fields.Integer(required=False, default=0, description='Number of followers of the avatar'),
    'following': fields.Integer(required=False, default=0, description='Number of users the avatar is following'),
})


post_model = rest_api.model('Post', {
    'media_id': fields.String(required=False, description='Media URL of the post'),
    'content': fields.String(required=True, description='Content of the post'),
    # Add other fields as necessary, based on your Post model structure
})


"""
   Helper function for JWT token required
"""

def token_required(f):

    @wraps(f)
    def decorator(*args, **kwargs):

        token = None

        if "authorization" in request.headers:
            token = request.headers["authorization"]

        if not token:
            return {"success": False, "msg": "Valid JWT token is missing"}, 400

        try:
            data = jwt.decode(token, 'DEV_KEY', algorithms=["HS256"])
            current_user = Users.get_by_email(data["email"])

            if not current_user:
                return {"success": False,
                        "msg": "Sorry. Wrong auth token. This user does not exist."}, 400

            token_expired = db.session.query(JWTTokenBlocklist.id).filter_by(jwt_token=token).scalar()

            if token_expired is not None:
                return {"success": False, "msg": "Token revoked."}, 400

            if not current_user.check_jwt_auth_active():
                return {"success": False, "msg": "Token expired."}, 400

        except:
            return {"success": False, "msg": "Token is invalid"}, 400

        return f(*args, current_user=current_user, **kwargs)

    return decorator







def get_media_thumb(file_id):
    # Assuming current_user has a one-to-many relationship with Avatar
    # Request the file metadata from Google Drive
    file_metadata = service.files().get(fileId=file_id, fields='thumbnailLink').execute()

    thumbnail_url = file_metadata.get('thumbnailLink', None)

    return thumbnail_url



"""
    Flask-Restx routes
"""


@rest_api.route('/api/users/register')
class Register(Resource):
    """
       Creates a new user by taking 'signup_model' input
    """

    @rest_api.expect(signup_model, validate=True)
    def post(self):

        req_data = request.get_json()

        _username = req_data.get("username")
        _email = req_data.get("email")
        _password = req_data.get("password")

        user_exists = Users.get_by_email(_email)
        if user_exists:
            return {"success": False,
                    "msg": "Email already taken"}, 400

        new_user = Users(username=_username, email=_email)

        new_user.set_password(_password)
        new_user.save()

        return {"success": True,
                "userID": new_user.id,
                "msg": "The user was successfully registered"}, 200


@rest_api.route('/api/users/login')
class Login(Resource):
    """
       Login user by taking 'login_model' input and return JWT token
    """

    @rest_api.expect(login_model, validate=True)
    def post(self):

        req_data = request.get_json()

        _email = req_data.get("email")
        _password = req_data.get("password")

        user_exists = Users.get_by_email(_email)

        if not user_exists:
            return {"success": False,
                    "msg": "This email does not exist."}, 400

        if not user_exists.check_password(_password):
            return {"success": False,
                    "msg": "Wrong credentials."}, 400

        # create access token uwing JWT
        token = jwt.encode({'email': _email, 'exp': datetime.utcnow() + timedelta(minutes=30)}, 'DEV_KEY', algorithm="HS256")

        user_exists.set_jwt_auth_active(True)
        user_exists.save()

        return {"success": True,
                "token": token,
                "user": user_exists.toJSON()}, 200


@rest_api.route('/api/users/edit')
class EditUser(Resource):
    """
       Edits User's username or password or both using 'user_edit_model' input
    """

    @rest_api.expect(user_edit_model)
    @token_required
    def post(self, current_user):

        req_data = request.get_json()

        _new_username = req_data.get("username")
        _new_email = req_data.get("email")

        if _new_username:
            self.update_username(_new_username)

        if _new_email:
            self.update_email(_new_email)

        self.save()

        return {"success": True}, 200


@rest_api.route('/api/users/logout')
class LogoutUser(Resource):
    """
       Logs out User using 'logout_model' input
    """

    @token_required
    def post(self, current_user):

        _jwt_token = request.headers["authorization"]

        jwt_block = JWTTokenBlocklist(jwt_token=_jwt_token, created_at=datetime.now(timezone.utc))
        jwt_block.save()

        self.set_jwt_auth_active(False)
        self.save()

        return {"success": True}, 200


@rest_api.route('/api/sessions/oauth/github/')
class GitHubLogin(Resource):
    def get(self):
        code = request.args.get('code')
        client_id = BaseConfig.GITHUB_CLIENT_ID
        client_secret = BaseConfig.GITHUB_CLIENT_SECRET
        root_url = 'https://github.com/login/oauth/access_token'

        params = { 'client_id': client_id, 'client_secret': client_secret, 'code': code }

        data = requests.post(root_url, params=params, headers={
            'Content-Type': 'application/x-www-form-urlencoded',
        })

        response = data._content.decode('utf-8')
        access_token = response.split('&')[0].split('=')[1]

        user_data = requests.get('https://api.github.com/user', headers={
            "Authorization": "Bearer " + access_token
        }).json()
        
        user_exists = Users.get_by_username(user_data['login'])
        if user_exists:
            user = user_exists
        else:
            try:
                user = Users(username=user_data['login'], email=user_data['email'])
                user.save()
            except:
                user = Users(username=user_data['login'])
                user.save()
        
        user_json = user.toJSON()

        token = jwt.encode({"username": user_json['username'], 'exp': datetime.utcnow() + timedelta(minutes=30)}, BaseConfig.SECRET_KEY)
        user.set_jwt_auth_active(True)
        user.save()

        return {"success": True,
                "user": {
                    "_id": user_json['_id'],
                    "email": user_json['email'],
                    "username": user_json['username'],
                    "token": token,
                }}, 200



@rest_api.route('/api/avatars')
class AvatarResource(Resource):
    
    @rest_api.expect(avatar_model)
    @token_required
    def get(self,current_user):
        # Fetch the avatar based on the current_user's ID
        avatar = Avatar.query.filter_by(user_id=current_user.id).first()

        
        if avatar:
            return {"success": True,
                "avatar": {
                   'id': avatar.id,
                    'name': avatar.name,
                    'profile_image_url': get_media_thumb(avatar.profile_image_id),
                    'followers': avatar.followers,
                    'following': avatar.following
                }}, 200

             
        else:
            rest_api.abort(404, "Avatar not found for the current user")

@rest_api.route('/api/users/<int:user_id>/avatars')
class AdminAvatarResource(Resource):

    @rest_api.expect(admin_avatar_model)
    def post(self, user_id):
        req_data = request.get_json()

        # Optional: Check if the current_user has the privilege to create an avatar for another user
        # if not current_user.is_admin:
        #     return {"message": "Unauthorized"}, 403

        # Create a new Avatar instance with the provided user_id
        new_avatar = Avatar(
            user_id=user_id,
            name=req_data.get('name'),
            profile_image_id=req_data.get('profile_image_id'),
            followers=req_data.get('followers', 0),
            following=req_data.get('following', 0)
        )

        # Add the avatar to the database
        db.session.add(new_avatar)
        db.session.commit()

        return {"message": "Avatar created successfully for user " + str(user_id)}, 201

@rest_api.route('/api/users/stats')
class GetUserStats(Resource):
    """
    Gets User's statistics including total spend, spend this month, and leads count
    """

    @token_required
    def get(self, current_user):

        stats = current_user.get_stats()
        return {"success": True, "stats": stats}, 200


@rest_api.route('/api/users/<int:user_id>/avatars/posts')
class AdminUserAvatarPostResource(Resource):

    @rest_api.expect(post_model)  # Ensure post_model is defined according to your Post schema
    def post(self, user_id):
        req_data = request.get_json()

        # Optional: Check if the current_user has the privilege to create a post for this avatar
        # if not current_user.is_authorized_for_avatar(user_id, avatar_id):
        #     return {"message": "Unauthorized"}, 403

        avatar = Avatar.query.filter_by(user_id=user_id).first()
        if not avatar:
            return {"message": "No avatars found for user " + str(user_id)}, 404
        avatar_id = avatar.id

        new_post = Post(
            avatar_id=avatar_id,
            media_id=req_data.get('media_id'),
            content=req_data.get('content'),
            # Add other fields as necessary
        )

        db.session.add(new_post)
        db.session.commit()

        return {"message": "Post created successfully for avatar " + str(avatar_id)}, 201



@rest_api.route('/api/posts')
class UserPosts(Resource):

    @token_required
    def get(self, current_user):
        # Assuming current_user has a one-to-many relationship with Avatar
        first_avatar = Avatar.query.filter_by(user_id=current_user.id).first()

        if first_avatar:
            posts = Post.query.filter_by(avatar_id=first_avatar.id).all()
            posts_data = [{
                'id': post.id,
                'timestamp': post.timestamp.isoformat(),
                'media_url': get_media_thumb(post.media_id),
                'status': post.status,
                'content': post.content
            } for post in posts]

            return {'success': True, 'posts': posts_data}, 200
        else:
            return {'success': False, 'message': 'No avatar found for the user'}, 404


# @rest_api.route('/api/thumb')
# class DriveResource(Resource):

#     def get(self):
#         # Assuming current_user has a one-to-many relationship with Avatar
#         # Request the file metadata from Google Drive
#         file_metadata = service.files().get(fileId='1azj7rkZwS1WzMdz3-OEP-HaVjKGPDLSr', fields='thumbnailLink').execute()

#         thumbnail_url = file_metadata.get('thumbnailLink', None)

#         if thumbnail_url:
#             return {'success': True, 'thumb': thumbnail_url}, 200
#         else:
#             return {'success': False, 'message': 'No thumb found for the id'}, 404


