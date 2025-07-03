import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import socket
import threading
import json
import base64
import os

class ChatClient:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Chat Client")
        self.root.geometry("700x500")
        
        self.sock = None
        self.connected = False
        self.logged_in = False
        self.username = ""
        self.user_id = None
        
        self.create_widgets()
        self.show_login()
    
    def create_widgets(self):
        # Login frame
        self.login_frame = tk.Frame(self.root, bg='#f0f0f0')
        
        tk.Label(self.login_frame, text="Chat Client", font=('Arial', 16), 
                bg='#f0f0f0').pack(pady=20)
        
        # Connection section
        conn_frame = tk.LabelFrame(self.login_frame, text="Server", padx=10, pady=10)
        conn_frame.pack(pady=10, padx=20, fill='x')
        
        tk.Label(conn_frame, text="Host:").grid(row=0, column=0, sticky='w')
        self.host_entry = tk.Entry(conn_frame, width=20)
        self.host_entry.insert(0, "localhost")
        self.host_entry.grid(row=0, column=1, padx=5)
        
        tk.Label(conn_frame, text="Port:").grid(row=1, column=0, sticky='w')
        self.port_entry = tk.Entry(conn_frame, width=20)
        self.port_entry.insert(0, "9999")
        self.port_entry.grid(row=1, column=1, padx=5)
        
        tk.Button(conn_frame, text="Connect", command=self.connect).grid(row=2, column=0, columnspan=2, pady=5)
        
        # Auth section
        self.auth_frame = tk.LabelFrame(self.login_frame, text="Login", padx=10, pady=10)
        self.auth_frame.pack(pady=10, padx=20, fill='x')
        
        tk.Label(self.auth_frame, text="Username:").grid(row=0, column=0, sticky='w')
        self.user_entry = tk.Entry(self.auth_frame, width=20)
        self.user_entry.grid(row=0, column=1, padx=5)
        
        tk.Label(self.auth_frame, text="Password:").grid(row=1, column=0, sticky='w')
        self.pass_entry = tk.Entry(self.auth_frame, width=20, show='*')
        self.pass_entry.grid(row=1, column=1, padx=5)
        
        btn_frame = tk.Frame(self.auth_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=5)
        
        tk.Button(btn_frame, text="Login", command=self.login).pack(side='left', padx=2)
        tk.Button(btn_frame, text="Register", command=self.register).pack(side='left', padx=2)
        
        self.status_label = tk.Label(self.login_frame, text="Not connected", fg='red')
        self.status_label.pack(pady=10)
        
        # Chat frame
        self.chat_frame = tk.Frame(self.root)
        
        # Header
        header = tk.Frame(self.chat_frame, bg='#e0e0e0')
        header.pack(fill='x', padx=5, pady=2)
        
        self.welcome_label = tk.Label(header, text="", font=('Arial', 12), bg='#e0e0e0')
        self.welcome_label.pack(side='left')
        
        tk.Button(header, text="Logout", command=self.logout).pack(side='right')
        
        # Main area
        main_pane = tk.PanedWindow(self.chat_frame, orient='horizontal')
        main_pane.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Users list
        left_frame = tk.LabelFrame(main_pane, text="Users")
        main_pane.add(left_frame)
        
        self.users_list = tk.Listbox(left_frame, width=15)
        self.users_list.pack(fill='both', expand=True, padx=5, pady=5)
        self.users_list.bind('<Double-Button-1>', self.select_user)
        
        tk.Button(left_frame, text="Refresh", command=self.get_users).pack(pady=2)
        
        # Chat area
        right_frame = tk.Frame(main_pane)
        main_pane.add(right_frame)
        
        tk.Label(right_frame, text="Messages", font=('Arial', 10, 'bold')).pack(anchor='w')
        
        self.chat_area = scrolledtext.ScrolledText(right_frame, height=15, state='disabled')
        self.chat_area.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Input area
        input_frame = tk.Frame(right_frame)
        input_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Label(input_frame, text="To:").grid(row=0, column=0, sticky='w')
        self.to_entry = tk.Entry(input_frame, width=15)
        self.to_entry.grid(row=0, column=1, padx=5)
        
        tk.Label(input_frame, text="Message:").grid(row=1, column=0, sticky='w')
        self.msg_entry = tk.Entry(input_frame, width=40)
        self.msg_entry.grid(row=1, column=1, padx=5, sticky='ew')
        self.msg_entry.bind('<Return>', lambda e: self.send_msg())
        
        btn_frame2 = tk.Frame(input_frame)
        btn_frame2.grid(row=2, column=0, columnspan=2, pady=5)
        
        tk.Button(btn_frame2, text="Send", command=self.send_msg).pack(side='left', padx=2)
        tk.Button(btn_frame2, text="Send File", command=self.send_file).pack(side='left', padx=2)
        
        input_frame.columnconfigure(1, weight=1)
        
        self.disable_auth()
    
    def show_login(self):
        self.login_frame.pack(fill='both', expand=True)
        self.chat_frame.pack_forget()
    
    def show_chat(self):
        self.login_frame.pack_forget()
        self.chat_frame.pack(fill='both', expand=True)
        self.welcome_label.config(text=f"Welcome, {self.username}")
        self.get_users()
    
    def disable_auth(self):
        for widget in self.auth_frame.winfo_children():
            if isinstance(widget, (tk.Entry, tk.Button, tk.Frame)):
                try:
                    widget.config(state='disabled')
                except:
                    for child in widget.winfo_children():
                        if isinstance(child, tk.Button):
                            child.config(state='disabled')
    
    def enable_auth(self):
        for widget in self.auth_frame.winfo_children():
            if isinstance(widget, (tk.Entry, tk.Button, tk.Frame)):
                try:
                    widget.config(state='normal')
                except:
                    for child in widget.winfo_children():
                        if isinstance(child, tk.Button):
                            child.config(state='normal')
    
    def connect(self):
        try:
            host = self.host_entry.get() or "localhost"
            port = int(self.port_entry.get() or "9999")
            
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, port))
            self.connected = True
            
            self.status_label.config(text="Connected", fg='green')
            self.enable_auth()
            
            threading.Thread(target=self.listen, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {e}")
    
    def send_data(self, data):
        if not self.connected:
            return False
        try:
            msg = json.dumps(data).encode()
            length = len(msg).to_bytes(4, 'big')
            self.sock.send(length + msg)
            return True
        except:
            return False
    
    def listen(self):
        while self.connected:
            try:
                data = self.sock.recv(4)
                if not data:
                    break
                
                msg_len = int.from_bytes(data, 'big')
                msg_data = self.sock.recv(msg_len)
                msg = json.loads(msg_data.decode())
                
                self.handle_message(msg)
            except:
                break
    
    def handle_message(self, msg):
        msg_type = msg.get('type')
        
        if msg_type == 'new_msg':
            sender = msg.get('from')
            content = msg.get('content')
            time = msg.get('time')
            self.add_to_chat(f"[{time}] {sender}: {content}")
        
        elif msg_type == 'new_file':
            sender = msg.get('from')
            filename = msg.get('filename')
            time = msg.get('time')
            file_data = msg.get('file_data')
            
            self.add_to_chat(f"[{time}] {sender} sent file: {filename}")
            
            # Add save button
            def save_file():
                try:
                    decoded = base64.b64decode(file_data)
                    save_path = filedialog.asksaveasfilename(initialname=filename)
                    if save_path:
                        with open(save_path, 'wb') as f:
                            f.write(decoded)
                        messagebox.showinfo("Success", "File saved!")
                except Exception as e:
                    messagebox.showerror("Error", f"Save failed: {e}")
            
            self.chat_area.config(state='normal')
            btn = tk.Button(self.chat_area, text=f"Save {filename}", command=save_file)
            self.chat_area.window_create('end', window=btn)
            self.chat_area.insert('end', '\n\n')
            self.chat_area.config(state='disabled')
            self.chat_area.see('end')
        
        elif msg_type == 'users_list':
            users = msg.get('users', [])
            self.users_list.delete(0, 'end')
            for user in users:
                if user != self.username:
                    self.users_list.insert('end', user)
    
    def register(self):
        username = self.user_entry.get()
        password = self.pass_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Enter username and password")
            return
        
        data = {'type': 'register', 'username': username, 'password': password}
        if self.send_data(data):
            messagebox.showinfo("Info", "Registration sent. Try logging in.")
    
    def login(self):
        username = self.user_entry.get()
        password = self.pass_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Enter username and password")
            return
        
        data = {'type': 'login', 'username': username, 'password': password}
        if self.send_data(data):
            # Simple check - in real app would handle response properly
            self.root.after(500, lambda: self.check_login(username))
    
    def check_login(self, username):
        # Simplified login check
        self.logged_in = True
        self.username = username
        self.user_id = 1
        messagebox.showinfo("Success", "Logged in!")
        self.show_chat()
    
    def logout(self):
        self.logged_in = False
        self.username = ""
        self.user_id = None
        if self.sock:
            self.sock.close()
        self.connected = False
        self.show_login()
        self.status_label.config(text="Disconnected", fg='red')
        self.disable_auth()
    
    def send_msg(self):
        if not self.logged_in:
            return
        
        to_user = self.to_entry.get()
        content = self.msg_entry.get()
        
        if not to_user or not content:
            messagebox.showerror("Error", "Enter recipient and message")
            return
        
        data = {'type': 'send_msg', 'to': to_user, 'content': content}
        if self.send_data(data):
            self.add_to_chat(f"You to {to_user}: {content}")
            self.msg_entry.delete(0, 'end')
    
    def send_file(self):
        if not self.logged_in:
            return
        
        to_user = self.to_entry.get()
        if not to_user:
            messagebox.showerror("Error", "Enter recipient")
            return
        
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            if len(file_data) > 5 * 1024 * 1024:  # 5MB limit
                messagebox.showerror("Error", "File too large")
                return
            
            encoded = base64.b64encode(file_data).decode()
            filename = os.path.basename(file_path)
            
            data = {
                'type': 'send_file',
                'to': to_user,
                'filename': filename,
                'file_data': encoded
            }
            
            if self.send_data(data):
                self.add_to_chat(f"You sent file '{filename}' to {to_user}")
        except Exception as e:
            messagebox.showerror("Error", f"File send failed: {e}")
    
    def get_users(self):
        if self.logged_in:
            self.send_data({'type': 'get_users'})
            self.root.after(3000, self.get_users)  # refresh every 3 sec
    
    def select_user(self, event):
        selection = self.users_list.curselection()
        if selection:
            user = self.users_list.get(selection[0])
            self.to_entry.delete(0, 'end')
            self.to_entry.insert(0, user)
    
    def add_to_chat(self, text):
        self.chat_area.config(state='normal')
        self.chat_area.insert('end', text + '\n')
        self.chat_area.config(state='disabled')
        self.chat_area.see('end')
    
    def run(self):
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.mainloop()
    
    def on_close(self):
        if self.sock:
            self.sock.close()
        self.root.destroy()

if __name__ == "__main__":
    app = ChatClient()
    app.run()