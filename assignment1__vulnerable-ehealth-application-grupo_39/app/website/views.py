from flask import Blueprint, render_template, request, flash, jsonify
from flask_login import login_required, current_user
from . import db
import json

from .models import Appointment, Message, Exam

views = Blueprint('views', __name__)

@views.route('/', methods=['GET', 'POST'])
@login_required
def home():

    if request.form.get('code_input'):
        try:
            code = int(request.form.get('code_input'))

            if len(str(code)) == 4:
                records = db.engine.execute(f'SELECT * FROM Exam WHERE exam.code = "{code}"')
                for record in records:
                    exam = record

                code = request.form.get('code_input')
                return render_template("exams.html",user=current_user, exam=exam)
        
        except:
            print("Websites crashes throwing an exception")

    elif request.form.get('destination_email') and request.form.get('message'):

        from_email = current_user.email
        to_email = request.form.get('destination_email')
        message = request.form.get('message')

        print(f"From Email {from_email}")
        print(f"To Email {to_email}")
        print(f"Message {message}")

        new_message = Message(from_email=from_email, to_email=to_email, message=message)
        db.session.add(new_message)
        db.session.commit()

    elif request.form.get('exam_email') and request.form.get('exam_description') and request.form.get('exam_code'):

        code = request.form.get('exam_code')
        email = request.form.get('exam_email')
        description = request.form.get('exam_description')

        print("Tou sim")

        if len(code) == 4:
            user_id = db.engine.execute("SELECT * FROM User WHERE user.email = ?", email).first().id
            print(user_id)
            new_exam = Exam(code=code, user_id=user_id, description=description)


            db.session.add(new_exam)
            db.session.commit()
            print("Exame commited")


        else:
            print("CODE IS NOT CORRECT SIZE!!")


        

    return render_template("home.html", user=current_user)




@views.route('/appointment', methods=['GET','POST'])
def appointment():
    if request.method == "POST":
        service = request.form.get("service")
        date = request.form.get("date")
        description = request.form.get("description")
        appointment = Appointment(service=service, date=date, description=description, user_id=current_user.id)
        db.session.add(appointment)
        db.session.commit()

    return render_template("appointment.html")

@views.route('/appointments')
def appointments():
    return render_template("appointments.html", user=current_user)



@views.route('/exams')
def exams():
    my_var = request.args.get('my_var', None)
    print("VARR")
    print(my_var)
    return render_template("exams.html", user=current_user)

@views.route('/messages')
def messages():

    print(current_user.email)
    query = Message.query.filter_by(to_email=current_user.email)

    messages = []

    for m in query:
        messages.append(m)

    return render_template("messages.html", user=current_user, messages=messages)
