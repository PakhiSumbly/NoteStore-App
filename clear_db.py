import sqlite3

def clear_database():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Delete all data from the 'users' table
    cursor.execute("DELETE FROM users")
    
    # Optionally, you can reset the primary key sequence if needed
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='users'")

    conn.commit()
    conn.close()
    print("Database cleared successfully.")

if __name__ == '__main__':
    clear_database()
