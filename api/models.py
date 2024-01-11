# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from datetime import datetime

import json

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()



class Users(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(32), nullable=False)
    email = db.Column(db.String(64), nullable=True)
    password = db.Column(db.Text())
    jwt_auth_active = db.Column(db.Boolean())
    date_joined = db.Column(db.DateTime(), default=datetime.utcnow)


    spend_total = db.Column(db.Float(), default=0.0)
    spend_month = db.Column(db.Float(), default=0.0)
    leads_count = db.Column(db.Integer(), default=0)

    avatars = db.relationship('Avatar', backref='user', lazy='dynamic')


    def __repr__(self):
        return f"User {self.username}"

    def save(self):
        db.session.add(self)
        db.session.commit()

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def update_email(self, new_email):
        self.email = new_email

    def update_username(self, new_username):
        self.username = new_username

    def check_jwt_auth_active(self):
        return self.jwt_auth_active

    def set_jwt_auth_active(self, set_status):
        self.jwt_auth_active = set_status

    @classmethod
    def get_by_id(cls, id):
        return cls.query.get_or_404(id)

    @classmethod
    def get_by_email(cls, email):
        return cls.query.filter_by(email=email).first()
    
    @classmethod
    def get_by_username(cls, username):
        return cls.query.filter_by(username=username).first()

    def toDICT(self):

        cls_dict = {}
        cls_dict['_id'] = self.id
        cls_dict['username'] = self.username
        cls_dict['email'] = self.email
        # cls_dict['spend_total'] = self.spend_total
        # cls_dict['spend_month'] = self.spend_month
        # cls_dict['leads_count'] = self.leads_count

        return cls_dict

    def toJSON(self):

        return self.toDICT()
    
    def get_stats(self):
    
        stats = {
            "spend_total": self.spend_total,
            "spend_month": self.spend_month,
            "leads_count": self.leads_count,
        }
        
        return stats



class JWTTokenBlocklist(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    jwt_token = db.Column(db.String(), nullable=False)
    created_at = db.Column(db.DateTime(), nullable=False)

    def __repr__(self):
        return f"Expired Token: {self.jwt_token}"

    def save(self):
        db.session.add(self)
        db.session.commit()



# Avatar Model
class Avatar(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    profile_image_id = db.Column(db.String(255))
    followers = db.Column(db.Integer(), default=0)
    following = db.Column(db.Integer(), default=0)

    # User relationship (foreign key)
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id'))

    # Relationship to Post
    posts = db.relationship('Post', backref='avatar', lazy='dynamic')

    def __repr__(self):
        return f"Avatar {self.name}"


# Post Model
class Post(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    timestamp = db.Column(db.DateTime(), default=datetime.utcnow)
    media_id = db.Column(db.String(255))
    status = db.Column(db.String(32), default="Pending") # Consider using Enum for status
    content = db.Column(db.Text(), default='')

    # Avatar relationship
    avatar_id = db.Column(db.Integer(), db.ForeignKey('avatar.id'))

    def __repr__(self):
        return f"Post {self.id} - {self.status}"


        