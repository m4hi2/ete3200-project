import functools
import face_recognition
import cv2
import numpy as np

from flask import (
    Blueprint, flash, g, redirect, render_template,
    request, session, url_for
    )
from werkzeug.security import check_password_hash, generate_password_hash

from bio_metric_atm.db import get_db
import RPi.GPIO as GPIO
from mfrc522 import SimpleMFRC522
import serial
import hashlib
from pyfingerprint.pyfingerprint import PyFingerprint

reader = SimpleMFRC522()

bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/register', methods=('GET', 'POST'))
def admin_register():
    if request.method == 'POST':
        user_id = request.form['user_id']
        name = request.form['name']
        password = request.form['password']
        balance = request.form['balance']
        face_encoding = request.form['image']
        finger_id = request.form['finger_id']
        finger_id_emergency = request.form['finger_id_emergency']
        db = get_db()
        error = None

        if not user_id:
            error = 'User ID is required.'

        elif not name:
            error = 'Full Name is requiered.'

        elif not password:
            error = 'Password is reqired.'
        
        elif not balance:
            error = 'Initial Balance is required.'

        elif face_encoding and finger_id:
            error = 'fi'

        elif face_encoding:
            error = 'f'

        elif finger_id:
            error = 'i'

        if error is 'fi':
            db.execute(
                'INSERT INTO user (user_id, name, password, balance, face_encoding, finger_id, finger_id_emergency) VALUES (?, ?, ?, ?, ?, ?, ?)',
                (user_id, name, generate_password_hash(password),
                    balance, face_encoding, finger_id, finger_id_emergency)
                )
            db.commit()
            return redirect(url_for('auth.success'))

        elif error is 'i':
            db.execute(
                'INSERT INTO user (user_id, name, password, balance, finger_id, finger_id_emergency) VALUES (?, ?, ?, ?, ?, ?)',
                (user_id, name, generate_password_hash(password),
                    balance, finger_id, finger_id_emergency)
                )
            db.commit()
            return redirect(url_for('auth.success'))

        elif error is 'f':
            db.execute(
                'INSERT INTO user (user_id, name, password, balance, face_encoding) VALUES (?, ?, ?, ?, ?)',
                (user_id, name, generate_password_hash(password),
                    balance, face_encoding)
                )
            db.commit()
            return redirect(url_for('auth.success'))

        elif error is None:
            db.execute(
                'INSERT INTO user (user_id, name, password, balance) VALUES (?, ?, ?, ?)',
                (user_id, name, generate_password_hash(password),
                    balance)
                )
            db.commit()
            return redirect(url_for('auth.success'))

        flash(error)
    return render_template('register.html')


@bp.route('/success', methods=('GET', 'POST'))
def success():
    return render_template('success.html')


@bp.route('/login', methods=('GET', 'POST'))
def login():
    session.clear()
    return render_template('wait.html')


@bp.route('/password', methods=('GET', 'POST'))
def password():
    error = None
    db = get_db()

    try:
        user_id, text = reader.read()

    finally:
        GPIO.cleanup()
    db.execute(
        'INSERT INTO internal (user_id, facematch, fingermatch) VALUES (NULL, 0, 0)'
        )
    db.commit()
    user = db.execute(
        'SELECT * FROM user WHERE user_id = ?', (user_id,)
        ).fetchone() 

    if request.method == 'POST':
        password = request.form['password']

        if not check_password_hash(user['password'], password):
            error = 'Incorrect password'
        else:
            session['user_id'] = user['user_id']
            if user['finger_id']:
                return redirect(url_for('auth.finger_view'))
            elif user['face_encoding']:
                return redirect(url_for('auth.face_view'))
            else:
                return redirect(url_for('auth.balance_view'))          

    if user is None:
        error = 'Please put your card and press "Continue"'
        flash(error)
        return redirect(url_for('auth.login'))
    else:
        if error:
            flash(error)
        return render_template('password.html', user=user)


@bp.route('/finger', methods=('GET', 'POST'))
def finger_view():
    """
    This will be the view for the finger print id
    """
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('auth.login'))
    
    return render_template('finger.html')

@bp.route('/finger_verification', methods=('GET', 'POST'))
def finger_verification():
    user_id = session.get('user_id')
    error = None
    db = get_db()
    try:
        
        f = PyFingerprint('/dev/ttyUSB1', 57600, 0xFFFFFFFF, 0x00000000)
        
        if(f.verifyPassword() == False):
            raise ValueError('The given password is wrong!')
    
    except Exception as e:
        print('Not initialized')
        print('Exception:' + str(e))
    
    try:
        while (f.readImage() == False):
            pass
        f.convertImage(0x01)
        result = f.searchTemplate()
        positionNumber = result[0]
        accuracyScore = result[1]
        if (positionNumber == -1):
            error = 'Finger Print not matched. Try again.'
            flash(error)
            return redirect(url_for('auth.finger_view'))
        else:
            user = db.execute(
                'SELECT * FROM user WHERE user_id =?',
                (user_id,)).fetchone()
            print(user['finger_id'])
            if user['finger_id'] == positionNumber:
                if user['face_encoding']:
                    return redirect(url_for('auth.face_view'))
                else:
                    return redirect(url_for('auth.balance_view'))
            elif user['finger_id_emergency'] == positionNumber:
                error = "Emergency Protocol Activated"
                flash(error)
                return redirect(url_for('auth.finger_view'))
    except Exception as e:
        error = str(e)
        flash(error)
        return redirect(url_for('auth.finger_view'))
                    

@bp.route('/face', methods=('GET', 'POST'))
def face_view():
    """
    This will be the view for the facial recognation
    """
    db = get_db()
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('auth.login'))
    user = db.execute(
        'SELECT * FROM user WHERE user_id = ?', (user_id,)
        ).fetchone() 

    return render_template('face.html')


@bp.route('/face_verification', methods=('GET', 'POST'))
def face_verification():
    user_id = session.get('user_id')
    db = get_db()
    if not user_id:
        return redirect(url_for('auth.login'))
    user = db.execute(
        'SELECT * FROM user WHERE user_id =?', (user_id,)
        ).fetchone()
    video_capture = cv2.VideoCapture(0)
    
    filename ="/home/pi/"+ user['face_encoding']
    file = face_recognition.load_image_file(filename)
    file_encoding = face_recognition.face_encodings(file)[0]
    known_face_encodings = [
        file_encoding,
        ]
    known_face_names = [
        user['name'],
        ]
    face_locations = []
    face_encodings = []
    face_names = []
    process_this_frame = True
    while True:
        ret, frame = video_capture.read()
        small_frame = cv2.resize(frame, (0, 0), fx=0.25, fy=0.25)
        
        rgb_small_frame = small_frame[:,:,::-1]
        if process_this_frame:
            face_locations = face_recognition.face_locations(rgb_small_frame)
            face_encodings = face_recognition.face_encodings(rgb_small_frame, face_locations)
            face_names = []
            for face_encoding in face_encodings:
                matches = face_recognition.compare_faces(known_face_encodings, face_encoding)
                name = "Unknown"
                face_distances = face_recognition.face_distance(known_face_encodings, face_encoding)
                best_match_index = np.argmin(face_distances)
                if matches[best_match_index]:
                    name = known_face_names[best_match_index]
                face_names.append(name)
        process_this_frame = not process_this_frame
      
            
        if user['name'] in face_names:
            break
    video_capture.release()
    cv2.destroyAllWindows()
    return redirect(url_for('auth.balance_view'))
            
        
    
    
    

@bp.route('/balance', methods=('GET', 'POST'))
def balance_view():
    """
    This will be the view for the balance information
    """
    db = get_db()
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('auth.login'))
    user = db.execute(
        'SELECT * FROM user WHERE user_id = ?', (user_id,)
        ).fetchone() 
    return render_template('balance.html', user=user)


@bp.route('/withdraw', methods=('GET', 'POST'))
def withdraw():
    db = get_db()
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('auth.login'))
    user = db.execute(
        'SELECT * FROM user WHERE user_id = ?', (user_id,)
        ).fetchone()
    if request.method == 'POST':
        ammount = request.form['withdraw']
        balance = user['balance']
        if int(ammount) > balance:
            error = 'You do not have enough money'
            flash(error)
            return redirect(url_for('auth.balance_view'))
        else: 
            """ 
            The code logic that will send the number of notes to the 
            Arduino based cash dispensing system through serial.
            Also the balance of the user will be updated here.
            """
            note = int(ammount) /100
            ser = serial.Serial('/dev/ttyUSB0')
            print(ser)
            note = int(note)
            print(type(note))
            ser.write(b'%d' % note)
            print(note)
            ser.close()
            new_balance = balance - int(ammount)
            db.execute(
                'UPDATE user SET balance=? WHERE user_id=?',
                (new_balance,user_id))
            db.commit()
                
            return redirect(url_for('auth.balance_view'))

    return render_template('withdraw.html', user=user)
