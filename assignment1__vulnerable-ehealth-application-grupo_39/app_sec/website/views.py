from flask import Blueprint, render_template, request, flash, jsonify
from flask_login import login_required, current_user
from . import db
import json
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import re
import html

from .models import Appointment, PublicKey, Message, User,Exam
from .encrypt import *
from .decrypt import *

views = Blueprint('views', __name__)

@views.route('/', methods=['GET', 'POST'])
@login_required
def home():

    if request.form.get('destination_email') and request.form.get('message'):

        from_email = current_user.email
        to_email = request.form.get('destination_email')
        message = html.escape(request.form.get('message'))

        AllowList_email = "^[a-zA-Z0-9-_]+@[a-zA-Z0-9]+\.[a-z]{1,3}$"       #make sure that email is correct format
        if re.match(AllowList_email,to_email):
            pass
        else:
            flash("BAD EMAIL")
            return render_template("home.html", user=current_user)


        print(f"From Email {from_email}")
        print(f"To Email {to_email}")
        print(f"Message {message}")


        dest_role = "User"
        dest_role = User.query.filter_by(email=to_email).first().role

        if dest_role == "Doctor" or current_user.role == "Doctor":

            user_id = User.query.filter_by(email=to_email).first().id

            key = db.engine.execute("SELECT * FROM public_key WHERE user_id = ?", user_id).first()

            pub_key = key.key

            key = serialization.load_pem_public_key(
                pub_key,
                backend=default_backend()
            )

            encrypted_message = rsa_encrypt(message, key)

            print(encrypted_message)

            new_message = Message(from_email=from_email, to_email=to_email, message=encrypted_message)
            db.session.add(new_message)
            db.session.commit()
            flash("Message sent")
            return render_template("home.html", user=current_user)

        else:
            flash("Can only message doctors")
            return render_template("home.html", user=current_user)

    if request.form.get('code_input'):
        code = request.form.get('code_input')
        if len(code) == 4:
            if not code.isalpha():
                print(code)
                exam = db.engine.execute('SELECT * FROM Exam WHERE exam.code = ?', code).first()

                if exam != None:
                    if exam.user_id == current_user.id:
                        return render_template("exams.html",user=current_user, exam=exam)
                    else:
                        flash("ERRO!")
                else:
                    flash("NO EXAM FOUND!") 
            else:
                flash("CODE IS STRING!")

        else:
            flash("CODE IS NOT CORRECT SIZE!!")

    elif request.form.get('exam_email') and request.form.get('exam_description') and request.form.get('exam_code'):

        code = request.form.get('exam_code')
        email = request.form.get('exam_email')
        description = html.escape(request.form.get('exam_description'))

        AllowList_email = "^[a-zA-Z0-9-_]+@[a-zA-Z0-9]+\.[a-z]{1,3}$"       #make sure that email is correct format
        if re.match(AllowList_email,email):
            pass
        else:
            flash("BAD EMAIL")
            return render_template("home.html", user=current_user)
        dest_role = "None"
        if User.query.filter_by(email=email).first():
            dest_role = User.query.filter_by(email=email).first().role

        print("Tou sim")

        if dest_role=="User":
            if len(code) == 4:
                user_id = db.engine.execute("SELECT * FROM User WHERE user.email = ?", email).first().id
                print(user_id)
                new_exam = Exam(code=code, user_id=user_id, description=description)


                db.session.add(new_exam)
                db.session.commit()
                flash("Exame commited")


            else:
                flash("CODE IS NOT CORRECT SIZE!!")  
        else:
            flash("Exam must be associated to user") 

    return render_template("home.html", user=current_user)

@views.route('/appointment', methods=['GET','POST'])
def appointment():
    if request.method == "POST":
        service = request.form.get("service")
        date = request.form.get("date")
        description = html.escape(request.form.get("description"))
        
        appointment = Appointment(service=service, date=date, description=description, user_id=current_user.id)
        db.session.add(appointment)
        db.session.commit()
        flash("Appointment scheduled")

    return render_template("appointment.html")

@views.route('/appointments')
def appointments():
    return render_template("appointments.html", user=current_user)

@views.route('/messages')
def messages():

    print(current_user.email)
    query = Message.query.filter_by(to_email=current_user.email)

    messages = []

    for m in query:

        private_key = current_user.private_key

        print("CURENT USER PASSWORD")
        print(str(current_user.password))   

        key = serialization.load_pem_private_key(
              private_key,
              password=bytes(str(current_user.password), "UTF-8"),
              backend=default_backend()
          )

        decrypted_message = rsa_decrypt(m.message,key).decode('utf-8')
        print("Decrypted message")
        print(decrypted_message)

        new_message = Message(from_email=m.from_email, to_email=m.to_email, message=decrypted_message)

        messages.append(new_message)
    


    return render_template("messages.html", user=current_user, messages=messages)



@views.route('/exams')
def exams():
    my_var = request.args.get('my_var', None)
    print("VARR")
    print(my_var)
    return render_template("exams.html", user=current_user)
