# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from datetime import datetime, timezone, timedelta

from functools import wraps

from flask import request
from flask_restx import Api, Resource, fields, Namespace

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


admin_api = Namespace('admin', description='Admin operations')


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

user_create_or_update_model = rest_api.model('UserCreateOrUpdateModel', {
    "userID": fields.String(required=False, min_length=1, max_length=32),
    "username": fields.String(required=True, min_length=2, max_length=32),
    "email": fields.String(required=True, min_length=4, max_length=64),
    "spend_total": fields.Float(required=False),
    "spend_month": fields.Float(required=False),
    "leads_count": fields.Integer(required=False)
    # Add any other fields if necessary
})


                                                

admin_avatar_model = rest_api.model('AdminAvatar', {
    'user_id': fields.Integer(required=True, description='ID of the user for whom the avatar is being created'),
    'name': fields.String(required=True, description='Name of the avatar'),
    'profile_image_id': fields.String(required=False, description='Profile image URL of the avatar'),
    'followers': fields.Integer(required=False, default=0, description='Number of followers of the avatar'),
    'following': fields.Integer(required=False, default=0, description='Number of users the avatar is following'),
})


post_model = admin_api.model('Post', {
    'media_id': fields.String(required=True, description='Media URL of the post'),
    'content': fields.String(required=True, description='Content of the post'),
    'customer_email': fields.String(required=True, description='email of the owner of the avatar'),
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

@rest_api.route('/api/users/createOrUpdate')
class CreateOrUpdateUser(Resource):
    """
    Edits User's and their Avatar's details using 'user_edit_model' input
    """

    @rest_api.expect(user_create_or_update_model, validate=True)
    def post(self):
        req_data = request.get_json()

        # Extract fields
        _username = req_data.get("username")
        _email = req_data.get("email")
        _password = req_data.get("password")
        _posts_credit = req_data.get("posts_credit")
        _spend_total = req_data.get("spend_total")
        _spend_month = req_data.get("spend_month")
        _leads_total = req_data.get("leads_total")

        # Avatar fields
        _avatar_name = req_data.get("avatar_name")
        _avatar_profile_id = req_data.get("avatar_profile_id")
        _avatar_following = req_data.get("avatar_following")
        _avatar_followers = req_data.get("avatar_followers")

        user = Users.get_by_email(_email)
        if not user:
            user = Users(email=_email)
            if _password:
                user.set_password(_password)
        
        # Updating user fields
        if _username:
            user.username = _username
        if _posts_credit:
            user.posts_credit = _posts_credit
        if _spend_total:
            user.spend_total = _spend_total
        if _spend_month:
            user.spend_month = _spend_month
        if _leads_total:
            user.leads_count = _leads_total

        # Update or create Avatar
        avatar = Avatar.query.filter_by(user_id=user.id).first()
        if not avatar:
            avatar = Avatar(user_id=user.id)
            db.session.add(avatar)

        # Update avatar fields
        if _avatar_name:
            avatar.name = _avatar_name
        if _avatar_profile_id:
            avatar.profile_image_id = _avatar_profile_id
        if _avatar_following is not None:
            avatar.following = _avatar_following
        if _avatar_followers is not None:
            avatar.followers = _avatar_followers

        try:
            db.session.commit()
            user.save()
            return {"success": True, "msg": "User and Avatar details updated successfully"}, 200
        except Exception as e:
            db.session.rollback()
            return {"success": False, "msg": str(e)}, 500


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

        current_user.set_jwt_auth_active(False)
        current_user.save()

        return {"success": True}, 200



@rest_api.route('/api/avatars')
class AvatarResource(Resource):
    
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

@admin_api.route('/posts')
class AdminUserAvatarPostResource(Resource):

    @admin_api.expect(post_model, validate=True)
    def post(self):
        req_data = admin_api.payload
        email = req_data.get('customer_email')  # Ensure 'email' is passed in the request body

        # Find the user by email
        user = Users.query.filter_by(email=email).first()
        if not user:
            return {"message": "User not found"}, 404

        # Find the first avatar for the user
        avatar = Avatar.query.filter_by(user_id=user.id).first()
        if not avatar:
            return {"message": "No avatars found for user with email: " + email}, 404

        # Check for an existing post with the same media_id
        media_id = req_data.get('media_id')
        existing_post = Post.query.filter_by(media_id=media_id, avatar_id=avatar.id).first()

        if existing_post:
            # Update the existing post
            existing_post.content = req_data.get('content')
            existing_post.media_id = media_id
            if req_data.get('status'):
                existing_post.status = req_data.get('status')
            # Update other fields as necessary
            message = "Post updated successfully"
        else:
            # Create a new post
            new_post = Post(
                avatar_id=avatar.id,
                media_id=media_id,
                content=req_data.get('content'),
                # Add other fields as necessary

            )
            # Assign status only if it's present and not empty
            status = req_data.get('status')
            if status:
                new_post.status = status

            db.session.add(new_post)
            message = "Post created successfully"

        db.session.commit()
        return {"message": message + " for avatar " + str(avatar.id)}, 200
# Add this namespace to your Flask-RESTx Api instance
rest_api.add_namespace(admin_api, path='/api/admin')

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


