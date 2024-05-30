from flask import Flask, request, jsonify, render_template, url_for, redirect, flash,send_file,send_from_directory
from pymongo import MongoClient
import json
from flask_bcrypt import Bcrypt
from flask_pymongo import PyMongo
from flask_cors import CORS
import os
from flask_cors import cross_origin
from bson import ObjectId  # Import ObjectId from bson
import jwt
import datetime
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask_jwt_extended import create_access_token,get_jwt,get_jwt_identity,unset_jwt_cookies, jwt_required, JWTManager
import base64
from Crypto.PublicKey import RSA
import binascii
import io

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": ["http://localhost:3000", "http://127.0.0.1:5000",'https://52.65.164.78','https://52.65.164.78','ssh://52.65.164.78']}})  # Allow requests from localhost:3000



app.config['SECRET_KEY'] = '43ee078a2665428e8ad5aa1695f953df'
first = 'mongodb+srv://newuser:sasheela0@newuser.yph0wbb.mongodb.net/?retryWrites=true&w=majority&appName=newuser'
second_mongo_uri  = 'mongodb+srv://kssathya:Sasheela0@library.app7t7w.mongodb.net/?retryWrites=true&w=majority&appName=library'
first_mongo = PyMongo(app,first)
second_mongo = PyMongo(app,second_mongo_uri)
bcrypt = Bcrypt(app)
# csrf = CSRFProtect(app)
# csrf.init_app(app)
app.config["JWT_SECRET_KEY"] = "testing"
jwt = JWTManager(app)
try:
    first_mongo = PyMongo(app,first)
    second_mongo = PyMongo(app,second_mongo_uri)
    print("Successfully connected to MongoDB.")
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")

def generate_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

private_key, public_key = generate_key_pair()
generate_key_pair()
def sign_data(data, private_key):
    key = RSA.import_key(private_key)
    h = SHA256.new(data)
    signature = pkcs1_15.new(key).sign(h)
    return signature


@app.route('/')
def index():
    return send_from_directory('build/templates', 'index.html')


@app.route('/static/css/<path:filename>')
def serve_css(filename):
    return send_from_directory('build/static/css', filename)

# Route to serve JavaScript files
@app.route('/static/js/<path:filename>')
def serve_js(filename):
    return send_from_directory('build/static/js', filename)

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('build/static', filename)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'Authorization' in request.headers:
            token = request.headers.get('Authorization')

        if not token:
            return jsonify({'error': 'Token is missing'}), 401

        print("Received token:", token)
        try:
            print("Token before decoding:", token)
            print("Secret Key:", app.config['SECRET_KEY'])
            data = jwt.decode(token, app.config['SECRET_KEY'])
            print("Decoded data",data)
            client = MongoClient("mongodb+srv://newuser:sasheela0@newuser.yph0wbb.mongodb.net/?retryWrites=true&w=majority&appName=newuser")
            db = client["users"]
            current_user = db.users.find_one({'_id': data['_id']})
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({'error': 'Token is invalid'}), 401
        except Exception as e:
            print(f"Error decoding token: {e}")
            return jsonify({'error': 'Error decoding token'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

def get_next_sequence(collection, sequence_name):
    result = collection.find_one_and_update(
        {'_id': sequence_name},
        {'$inc': {'value': 1}},
        upsert=True,
        return_document=True
    )
    return result['value']

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    answer = data.get('answer')
    security = data.get('security_question')
    password = data.get('password')
    confirm_password = data.get('confirm_password')


    if not name or not email or not security or not answer or not password or not confirm_password:
        return jsonify({'error': 'Missing required fields'}), 400   

    # Password Validation
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters long'}), 400
    
    if password != confirm_password:
        return jsonify({'error': 'Password and confirm password do not match'}), 400


    try:
        client = MongoClient("mongodb+srv://newuser:sasheela0@newuser.yph0wbb.mongodb.net/?retryWrites=true&w=majority&appName=newuser")
        db = client["users"]
        collection = db["users"]
        existing_user = collection.find_one({'email': email,'name':name})
        if existing_user:
            return jsonify({'error': 'Email already exists'}), 400
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        next_id = get_next_sequence(db['counters'], 'user_id_sequence')
        user_data = {
        "_id": next_id,
        "name": name,
        "email": email,
        'security_question':security,
        "answer": answer,
        "password": hashed_password
    }
        print("User Data:", user_data)
        collection.insert_one(user_data)
        client.close()
        return jsonify({ 'message': 'Registration  successful'})

        # Return a JSON response with the user data
    except Exception as e:
        print(f"Error inserting user data into MongoDB: {e}")
        return jsonify({'error': 'Registration failed'}), 500

@app.after_request
def refresh_expiring_jwts(response):
    try:
        exp_timestamp = get_jwt()["exp"]
        now = datetime.now(timezone.utc)
        target_timestamp = datetime.timestamp(now + timedelta(minutes=30))
        if target_timestamp > exp_timestamp:
            access_token = create_access_token(identity=get_jwt_identity())
            data = response.get_json()
            if type(data) is dict:
                data["access_token"] = access_token 
                response.data = json.dumps(data)
        return response
    except (RuntimeError, KeyError):
        # Case where there is not a valid JWT. Just return the original respone
        return response
    
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Missing email or password'}), 400

    # Check if the user with the provided email exists
    client = MongoClient("mongodb+srv://newuser:sasheela0@newuser.yph0wbb.mongodb.net/?retryWrites=true&w=majority&appName=newuser")
    db = client["users"]
    collection = db["users"]
    user = db.users.find_one({'email': email})

    if not user:
        return jsonify({'error': 'User not found'}), 401
    
    user_id_str = str(user['_id'])

    # Check if the provided password matches the stored hashed password
    if bcrypt.check_password_hash(user['password'], password):
            access_token = create_access_token(identity=email)  
            response = {"access_token":access_token,'message': 'Login successful'}
            books_info = all_books()
            client.close()
            return {**response, **books_info}
        # return jsonify({'token': token, 'message': 'Login successful'})
    else:
        client.close()
        return jsonify({'error': 'Invalid password'}), 401


@app.route('/public_key', methods=['GET'])
def serve_public_key():
    return public_key


def all_books():
    try:
        client = MongoClient('mongodb+srv://kssathya:Sasheela0@library.app7t7w.mongodb.net/?retryWrites=true&w=majority&appName=library')
        db = client.library  
        collection = db.books
        titles = collection.distinct("title")
        author = collection.distinct('author')
        year = collection.distinct('year_published')
        books_info = {}
        for title, author, year in zip(titles, author, year):
            books_info[title] = {'author': author, 'year_published': year}
        client.close()
        return {'books':books_info}
    except Exception as e:
        print(f"Error connecting to MongoDB: {e}")
        return jsonify({'error': 'Failed to connect to MongoDB'}), 500
    finally:
        # Close MongoDB connection
        client.close()

@app.route('/reset',methods=['POST'])
def reset():
    data = request.get_json()
    name = data.get('name')            
    # security_question = data.get('security_question')
    # answer = data.get('answer')
    if not name:
        return jsonify({'error': 'Missing question or answer'}), 400
    client = MongoClient("mongodb+srv://newuser:sasheela0@newuser.yph0wbb.mongodb.net/?retryWrites=true&w=majority&appName=newuser")
    db = client["users"]
    collection = db["users"]
    user = db.users.find_one({'name':name})
    if user:
        security_question = user.get('security_question')
        if(security_question):
            if(security_question == 'q1'):
                security_question = "What is your mother's maiden name?"
                return jsonify({'security_question': security_question}), 200
            elif(security_question == 'q2'):
                security_question = "What is the name of your first pet?"
                return jsonify({'security_question': security_question}), 200
            elif(security_question == 'q3'):
                security_question = "What city were you born in?"
                return jsonify({'security_question': security_question}), 200
            elif(security_question == 'q4'):
                security_question = "What is your favorite food?"
                return jsonify({'security_question': security_question}), 200
            elif(security_question == 'q5'):
                security_question = "What is the name of your best friend in childhood?"
                return jsonify({'security_question': security_question}), 200
        client.close()
        return jsonify({'security_question': security_question}), 200
    else:
        return jsonify({'error': 'Invalid name'}), 400

@app.route('/verify', methods=['POST'])
def verify_answer():
    data = request.get_json()
    name = data.get('name')
    answer = data.get('answer')

    if not name or not answer:
        return jsonify({'error': 'Missing name or answer'}), 400
    client = MongoClient("mongodb+srv://newuser:sasheela0@newuser.yph0wbb.mongodb.net/?retryWrites=true&w=majority&appName=newuser")
    db = client["users"]
    collection = db["users"]     
    user = db.users.find_one({'name': name, 'answer': answer})
    if user:
        client.close()

        return jsonify({'message': 'Answer is correct'}), 200
    else:
        client.close()

        return jsonify({'error': 'Incorrect answer'}), 400

@app.route('/change',methods=['POST'])
def change_password():
    data = request.get_json()
    name = data.get('name')
    answer = data.get('answer')
    password =data.get('password')
    confirm_password= data.get('confirm_password')
    
    if not name or not answer or not password or not confirm_password:
        return jsonify({'error': 'Missing name, answer, password, or confirm_password'}), 400
    
    if password != confirm_password:
        return jsonify({'error': 'Passwords do not match'}), 400
    
    client = MongoClient("mongodb+srv://newuser:sasheela0@newuser.yph0wbb.mongodb.net/?retryWrites=true&w=majority&appName=newuser")
    db = client["users"]
    collection = db["users"]     
    user = db.users.find_one({'name': name})
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    db.users.update_one({'name': name}, {'$set': {'password': hashed_password}})
    client.close()

    return jsonify({'message': 'Password changed successfully'}), 200

@app.route('/search',methods = ["POST"])
def get_book():
    try:
        client = MongoClient('mongodb+srv://kssathya:Sasheela0@library.app7t7w.mongodb.net/?retryWrites=true&w=majority&appName=library')
        db = client.library  
        collection = db.books
        data = request.get_json()
        book_name = data.get('name')
        if not book_name:
            return jsonify({'error': 'Missing book name'}), 400
        requested_book = collection.find_one({'title': book_name})
        serialized_data = book_name.encode()
        signature = sign_data(serialized_data,private_key)
        if not requested_book:
            client.close()
            return jsonify({'error': 'Book not found'}), 401
        else:
            client.close()
            requested_book['_id'] = str(requested_book['_id'])
            return jsonify({'book': requested_book,'signature': binascii.hexlify(signature).decode()})
    except Exception as e:
        print(f"Error connecting to MongoDB: {e}")
        return jsonify({'error': 'Failed to connect to MongoDB'}), 500
    finally:
        # Close MongoDB connection
        client.close()

@app.route('/download', methods=['GET'])
def download_signed_book():
    # Assuming 'book.pdf' is the name of the file you want to download
    # Adjust the file path as per your file structure
    # file_path = os.path.join('ITIS', 'itis_app', 'server', 'Gatsby_PDF_FullText.pdf')
    file_path = "D:\\ITIS\\itis_app\\server\\Gatsby_PDF_FullText.pdf"
    # Load the book file
    with open(file_path, 'rb') as f:
        book_data = f.read()
    
    # Combine the book data and signature

    signature = sign_data(book_data, private_key)
    # Encode the book data and signature as base64
    signed_book_base64 = base64.b64encode(book_data).decode('utf-8')
    signature_base64 = base64.b64encode(signature).decode('utf-8')

    return jsonify({
        'size': len(signed_book_base64),
        'type': 'application/pdf',
        'book': signed_book_base64,
        'signature': signature_base64
    })

@app.route("/logout", methods=["POST"])
def logout():
    response = jsonify({"msg": "logout successful"})
    unset_jwt_cookies(response)
    return response


if __name__ == '__main__':
    app.run()

