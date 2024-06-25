from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from . import db
from flask_login import login_user, login_required, logout_user, current_user
from cryptography.hazmat.primitives import hashes

auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        digest = hashes.Hash(hashes.MD5())
        digest.update(password.encode('UTF-8'))
        hashpass=digest.finalize()

        print(email)
        print(password)
        
        records = db.engine.execute(f'SELECT * FROM User WHERE user.email = "{email}" AND user.password = "{str(hashpass)}"')
        print(records)
        i = 0
        for record in records:
            i += 1
            user = record


        if i != 0:
            print("Olha Olha")
            print(user)
            user = User(id=user[0],email=user[1], first_name=user[2], password=user[3], role=user[4])
            login_user(user, remember=True)
            return redirect(url_for('views.home'))

    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('first_name')
        role = request.form.get('role')
        password = request.form.get('password')
        digest = hashes.Hash(hashes.MD5())
        digest.update(password.encode('UTF-8'))
        hashpass=digest.finalize()


        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        else:
            new_user = User(email=email, first_name=first_name, password=str(hashpass), role=role)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            print('User created: ', new_user)
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)
