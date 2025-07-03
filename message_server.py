import socket
import threading
import json
import sqlite3
import hashlib
import base64
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Database:
    def __init__(self, db_file="chat.db"):
        self.db_file = db_file
        self.setup_tables()
    
    def setup_tables(self):
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            online INTEGER DEFAULT 0
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY,
            from_user INTEGER,
            to_user INTEGER,
            content TEXT,
            file_data BLOB,
            filename TEXT,
            sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        conn.commit()
        conn.close()
    
    def add_user(self, username, password):
        try:
            conn = sqlite3.connect(self.db_file)
            c = conn.cursor()
            hashed = hashlib.sha256(password.encode()).hexdigest()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                     (username, hashed))
            conn.commit()
            conn.close()
            return True
        except:
            return False
    
    def check_login(self, username, password):
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        hashed = hashlib.sha256(password.encode()).hexdigest()
        c.execute("SELECT id FROM users WHERE username=? AND password=?", 
                 (username, hashed))
        result = c.fetchone()
        conn.close()
        return result[0] if result else None
    
    def save_msg(self, from_id, to_id, content=None, file_data=None, filename=None):
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        c.execute('''INSERT INTO messages (from_user, to_user, content, file_data, filename) 
                     VALUES (?, ?, ?, ?, ?)''', 
                 (from_id, to_id, content, file_data, filename))
        conn.commit()
        conn.close()

class ChatServer:
    def __init__(self, port=9999):
        self.port = port
        self.clients = {}
        self.users = {}
        self.db = Database()
        self.running = False
    
    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('localhost', self.port))
        self.sock.listen(5)
        self.running = True
        
        print(f"Server running on port {self.port}")
        
        while self.running:
            try:
                client, addr = self.sock.accept()
                threading.Thread(target=self.handle_client, args=(client, addr)).start()
            except:
                break
    
    def handle_client(self, client, addr):
        user_id = None
        try:
            while True:
                data = client.recv(4)
                if not data:
                    break
                
                msg_len = int.from_bytes(data, 'big')
                msg_data = client.recv(msg_len)
                
                try:
                    msg = json.loads(msg_data.decode())
                    response = self.process_msg(msg, user_id)
                    
                    if msg.get('type') == 'login' and response.get('success'):
                        user_id = response.get('user_id')
                        self.clients[user_id] = client
                        self.users[user_id] = msg.get('username')
                    
                    self.send_response(client, response)
                except:
                    pass
        except:
            pass
        finally:
            if user_id and user_id in self.clients:
                del self.clients[user_id]
                del self.users[user_id]
            client.close()
    
    def process_msg(self, msg, user_id):
        cmd = msg.get('type')
        
        if cmd == 'register':
            username = msg.get('username')
            password = msg.get('password')
            success = self.db.add_user(username, password)
            return {'type': 'register_result', 'success': success}
        
        elif cmd == 'login':
            username = msg.get('username')
            password = msg.get('password')
            uid = self.db.check_login(username, password)
            if uid:
                return {'type': 'login_result', 'success': True, 'user_id': uid}
            return {'type': 'login_result', 'success': False}
        
        elif cmd == 'send_msg':
            if not user_id:
                return {'error': 'not logged in'}
            
            to_user = msg.get('to')
            content = msg.get('content')
            
            # find recipient id
            to_id = None
            for uid, uname in self.users.items():
                if uname == to_user:
                    to_id = uid
                    break
            
            if not to_id:
                return {'error': 'user not found'}
            
            self.db.save_msg(user_id, to_id, content)
            
            # forward if online
            if to_id in self.clients:
                fwd_msg = {
                    'type': 'new_msg',
                    'from': self.users[user_id],
                    'content': content,
                    'time': datetime.now().strftime('%H:%M')
                }
                self.send_response(self.clients[to_id], fwd_msg)
            
            return {'success': True}
        
        elif cmd == 'send_file':
            if not user_id:
                return {'error': 'not logged in'}
            
            to_user = msg.get('to')
            filename = msg.get('filename')
            file_data = msg.get('file_data')
            
            to_id = None
            for uid, uname in self.users.items():
                if uname == to_user:
                    to_id = uid
                    break
            
            if not to_id:
                return {'error': 'user not found'}
            
            # decode and save
            try:
                decoded_data = base64.b64decode(file_data)
                self.db.save_msg(user_id, to_id, None, decoded_data, filename)
                
                if to_id in self.clients:
                    fwd_msg = {
                        'type': 'new_file',
                        'from': self.users[user_id],
                        'filename': filename,
                        'file_data': file_data,
                        'time': datetime.now().strftime('%H:%M')
                    }
                    self.send_response(self.clients[to_id], fwd_msg)
                
                return {'success': True}
            except:
                return {'error': 'invalid file'}
        
        elif cmd == 'get_users':
            return {'type': 'users_list', 'users': list(self.users.values())}
        
        return {'error': 'unknown command'}
    
    def send_response(self, client, data):
        try:
            response = json.dumps(data).encode()
            length = len(response).to_bytes(4, 'big')
            client.send(length + response)
        except:
            pass

if __name__ == "__main__":
    server = ChatServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.running = False