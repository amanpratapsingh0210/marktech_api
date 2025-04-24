from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
api = Api(app)

app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'fallback-secret-key')
jwt = JWTManager(app)

def init_db():
    if not os.path.exists('database'):
        os.makedirs('database')
        
    conn = sqlite3.connect('database/marktech.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

def get_db_connection():
    conn = sqlite3.connect('database/marktech.db')
    conn.row_factory = sqlite3.Row
    return conn

class UserRegistration(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return {'message': 'Username and password are required'}, 400
        
        hashed_password = generate_password_hash(password)
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            return {'message': 'user created successfully'}, 201
        except sqlite3.IntegrityError:
            return {'message': 'Username already exists'}, 400
        finally:
            conn.close()
            
class UserLogin(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            access_token = create_access_token(identity=str(user['id']))
            return {'access_token': access_token}, 200
        else:
            return {'message': 'Invalid credentials'}, 401
        
class Tasks(Resource):
    @jwt_required()
    def get(self):
        current_user = int(get_jwt_identity())
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM tasks WHERE user_id = ?', (current_user,))
        tasks = cursor.fetchall()
        conn.close()
        
        tasks_list = []
        for task in tasks:
            tasks_list.append({
                'id': task['id'],
                'title': task['title'],
                'description': task['description'],
                'created_at': task['created_at'],
                'completed': bool(task['completed'])
            })
        return {'tasks': tasks_list}, 200
    
    @jwt_required()
    def post(self):
        current_user = int(get_jwt_identity())
        data = request.get_json()
        title = data.get('title')
        description = data.get('description', '')
        
        if not title:
            return {'message': 'Title is required'}, 400
        
        created_at = datetime.now().isoformat()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO tasks (user_id, title, description, created_at)
            VALUES (?, ?, ?, ?)
        ''', (current_user, title, description, created_at))
        conn.commit()
        task_id = cursor.lastrowid
        conn.close()
        
        return {
            'message': 'Task created successfully',
            'task_id': task_id
        }, 201

class Task(Resource):
    @jwt_required()
    def get(self, task_id):
        current_user = int(get_jwt_identity())
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM tasks 
            WHERE id = ? AND user_id = ?
        ''', (task_id, current_user))
        task = cursor.fetchone()
        conn.close()
        
        if not task:
            return {'message': 'Task not found'}, 404
        
        return {
            'id': task['id'],
            'title': task['title'],
            'description': task['description'],
            'created_at': task['created_at'],
            'completed': bool(task['completed'])
        }, 200
        
    @jwt_required()
    def put(self, task_id):
        current_user = int(get_jwt_identity())
        data = request.get_json()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM tasks 
            WHERE id = ? AND user_id = ?
        ''', (task_id, current_user))
        task = cursor.fetchone()
        
        if not task:
            conn.close()
            return {'message': 'Task not found'}, 404
        
        title = data.get('title', task['title'])
        description = data.get('description', task['description'])
        completed = data.get('completed', task['completed'])
        
        cursor.execute('''
            UPDATE tasks 
            SET title = ?, description = ?, completed = ?
            WHERE id = ? AND user_id = ?
        ''', (title, description, int(completed), task_id, current_user))
        conn.commit()
        conn.close()
        
        return {'message': 'Task updated successfully'}, 200
    
    @jwt_required()
    def delete(self, task_id):
        current_user = int(get_jwt_identity())
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM tasks 
            WHERE id = ? AND user_id = ?
        ''', (task_id, current_user))
        task = cursor.fetchone()
        if not task:
            conn.close()
            return {'message': 'Task not found'}, 404
        
        cursor.execute('''
            DELETE FROM tasks 
            WHERE id = ? AND user_id = ?
        ''', (task_id, current_user))
        conn.commit()
        conn.close()
        
        return {'message': 'Task deleted successfully'}, 200

api.add_resource(UserRegistration, '/register')
api.add_resource(UserLogin, '/login')
api.add_resource(Tasks, '/tasks')
api.add_resource(Task, '/tasks/<int:task_id>')

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))