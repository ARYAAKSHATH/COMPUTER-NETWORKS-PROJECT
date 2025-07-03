import sqlite3

def check_db(db_file="chat.db"):
    """Quick database checker"""
    try:
        conn = sqlite3.connect(db_file)
        c = conn.cursor()
        
        # Show all tables
        c.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = c.fetchall()
        print("Tables found:", [t[0] for t in tables])
        
        # Check users
        try:
            c.execute("SELECT COUNT(*) FROM users")
            user_count = c.fetchone()[0]
            print(f"Users: {user_count}")
            
            if user_count > 0:
                c.execute("SELECT id, username, online FROM users LIMIT 5")
                users = c.fetchall()
                print("Sample users:")
                for user in users:
                    print(f"  ID: {user[0]}, Name: {user[1]}, Online: {user[2]}")
        except:
            print("No users table or data")
        
        # Check messages
        try:
            c.execute("SELECT COUNT(*) FROM messages")
            msg_count = c.fetchone()[0]
            print(f"Messages: {msg_count}")
            
            if msg_count > 0:
                c.execute("SELECT from_user, to_user, content, filename FROM messages LIMIT 3")
                msgs = c.fetchall()
                print("Recent messages:")
                for msg in msgs:
                    content = msg[2] if msg[2] else f"[File: {msg[3]}]"
                    print(f"  {msg[0]} -> {msg[1]}: {content}")
        except:
            print("No messages table or data")
        
        conn.close()
        
    except Exception as e:
        print(f"DB check failed: {e}")

if __name__ == "__main__":
    check_db()