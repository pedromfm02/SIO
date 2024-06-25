from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User, PublicKey
from . import db
from flask_login import login_user, login_required, logout_user, current_user
import re
from cryptography.hazmat.primitives import hashes

from .generatekeys import generate_key_pair


auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        digest = hashes.Hash(hashes.SHA256())
        digest.update(password.encode('UTF-8'))
        hashpass=digest.finalize()

        AllowList_email = "^[a-zA-Z0-9-_]+@[a-zA-Z0-9]+\.[a-z]{1,3}$"       #make sure that email is correct format
        if re.match(AllowList_email,email):
            pass
        else:
            return render_template("login.html", user=current_user)


        print(email)
        print(password)
        print(str(hashpass))
        
        records = db.engine.execute('SELECT * FROM User WHERE user.email = ? AND user.password = ?', email, str(hashpass)) #checks if hash matches db
        print(records)
        i = 0
        for record in records:
            i += 1
            user = record


        if i != 0:
            print("Olha Olha")
            print(user)
            user = User(id=user[0],email=user[1], first_name=user[2], password=user[3], private_key=user[4])
            login_user(user, remember=True)
            flash("Succesful login")
            return redirect(url_for('views.home'))

    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out")
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('first_name')
        password = request.form.get('password')
        role = request.form.get('role')

        
        digest = hashes.Hash(hashes.SHA256())
        digest.update(password.encode('UTF-8'))
        hashpass=digest.finalize() #stores the hash of password

        print("STRING DA HASH PASSWORD")
        print(str(hashpass))

        AllowList_email = "^[a-zA-Z0-9-_]+@[a-zA-Z0-9]+\.[a-z]{1,3}$"       #make sure that email is correct format
        if re.match(AllowList_email,email):
            pass
        else:
            flash("Bad email")
            return render_template("login.html", user=current_user)

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        else:
            public_key, private_key = generate_key_pair(2048, str(hashpass))
            
            new_user = User(email=email, first_name=first_name, password=str(hashpass), private_key=private_key,role=role)
            db.session.add(new_user)
            db.session.commit()
            new_public_key = PublicKey(key=public_key,user_id=new_user.id)
            db.session.add(new_public_key)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)
