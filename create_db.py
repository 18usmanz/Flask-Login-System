import sqlite3

#connect to database
conn = sqlite3.connect('database.db')
c = conn.cursor() # create cursor object

#create table called users if one doesnt exist already
c.execute('''
CREATE TABLE IF NOT EXISTS users(
    email TEXT PRIMARY KEY,
    password TEXT NOT NULL,
    is_locked INTEGER DEFAULT 0
)
''')

#save and close
conn.commit() 
conn.close()

print('Database and users table created successfully')