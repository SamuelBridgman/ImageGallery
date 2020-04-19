from flask import Flask, redirect, url_for, render_template, request, session, flash, jsonify, make_response
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from flask_paginate import Pagination, get_page_args

import random
import glob

from os import listdir
from os.path import isfile, join
import os
import logging
logging.basicConfig(filename='app.log',level=logging.DEBUG)

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#app.config['EXPLAIN_TEMPLATE_LOADING'] = True
db = SQLAlchemy(app)

class Users(db.Model):
    _id = db.Column("id", db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(80))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)
    #email = db.Column(db.String(80))

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        cookieToken = request.cookies.get('ImageGalleryCookie')
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        elif cookieToken:
            token = cookieToken

        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = Users.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route("/gallery", methods=['GET', 'POST'])
@token_required
def gallery(self):
    path = ".\static\images"
    image_names = os.listdir(path)

    return render_template("gallery.html", image_names = image_names)

image_names = []

def get_images(offset=0, per_page=25):
    return image_names[offset: offset + per_page]

@app.route('/gallery/paged')
@token_required
def paginated_gallery(self):
    page, per_page, offset = get_page_args(page_parameter='page',
                                           per_page_parameter='per_page')
    total = len(image_names)
    pagination_images = get_images(offset=offset, per_page=per_page)
    pagination = Pagination(page=page, per_page=per_page, total=total,
                            css_framework='bootstrap4')
    return render_template('pagedgallery.html',
                           images=pagination_images,
                           page=page,
                           per_page=per_page,
                           pagination=pagination,
                           )

@app.route("/user", methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot preform that function!'})

    users = Users.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data["public_id"] = user.public_id
        user_data["name"] = user.name
        user_data["password"] = user.password
        user_data["admin"] = user.admin
        output.append(user_data)

    return jsonify({"users" : output})

@app.route('/user/<public_id>',methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot preform that function!'})

    user = Users.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'no user found'})

    user_data = {}
    user_data["public_id"] = user.public_id
    user_data["name"] = user.name
    user_data["password"] = user.password
    user_data["admin"] = user.admin

    return jsonify({'user' : user_data})

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Cannot preform that function!'})

    # If content-type application/json not on request force=true required
#    data = request.get_json(force=true)
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = Users(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'new user created!'})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def prompte_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot preform that function!'})

    user = Users.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'no user found'})

    user.admin = True
    db.session.commit()
    return jsonify({'message' : 'User has been promoted!'})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot preform that function!'})

    user = Users.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'no user found'})

    db.session.delete(user)
    db.session.commit()
    return jsonify({'message' : 'User has been deleted!'})

# username case sensitive
@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login Requried!"'})

    user = Users.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not find user', 401, {'WWW-Authenticate' : 'Basic realm="Login Requried!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id,
                            'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
                            app.config['SECRET_KEY'])
        token = token.decode('UTF-8')
        #return jsonify({'token': token})

        resp = make_response(redirect(url_for("paginated_gallery")))
        #resp.response = jsonify({'token': token})
        resp.set_cookie('ImageGalleryCookie', value=token, httponly=True)
        return resp

    return make_response('Could not verify credentials', 401, {'WWW-Authenticate': 'Basic realm="Login Requried!"'})

if __name__ == "__main__":
        db.create_all()
        image_names = os.listdir(".\static\images")
        app.run(host='127.0.0.1', port=50000, debug=True)
