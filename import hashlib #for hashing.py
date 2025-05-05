import hashlib #for hashing
import pwinput #for covering up password with * 

def signup():
    email = input('Enter email address: ')
    try: #check if email is already signed up
        with open('credentials.txt', 'r') as f:
            for line in f:#check each line
                parts = line.strip().split()#split password and email seperate
                if len(parts) != 2:
                    continue  # skip bad lines
                stored_email, _ = parts
                if email == stored_email:
                    print('Email already exists. Try logging in!')
                    return
    except FileNotFoundError:
        pass
    except ValueError:
        pass
    
    pwd = pwinput.pwinput(prompt="Enter password: ", mask="*")
    confirm_pwd = pwinput.pwinput(prompt="Confirm password: ", mask="*") 
    
    if pwd == confirm_pwd: #check if passsword and confirmed password match
        enc = confirm_pwd.encode() # turn string into bytes
        hash1 = hashlib.sha256(enc).hexdigest() # get the hash string

        with open('credentials.txt', 'a') as f: #open credential file as append
            f.write(email + ' ' + hash1 + '\n') #add email and password after it passes checks
        print('You have registered successfully!')
    else:
        print("Passwords don't match. Please try again!")

def login():
    email = input('Enter email address: ')

    try: #check if email is actually in database
        with open('credentials.txt', 'r') as f:
            emails = [] #empty list
            for line in f:
                parts = line.strip().split()
                if len(parts) != 2:
                    continue
                emails_in_file = parts[0] #split email and password then get only email part
                emails.append(emails_in_file)
                
            if email not in emails:
                print("Email doesn't exist. Please register!")
                return
    except FileNotFoundError:
        print("No users registered yet. Please sign up first.")
        return
    
    try:
        with open('locked.txt', 'r') as lock_file:
            locked_accounts = [line.strip() for line in lock_file]

            if email in locked_accounts:
                print(' Your account is locked due too many failed login attempts.')
                return
    except FileNotFoundError:
        pass
    attempts = 0

    while attempts < 3:
        pwd = pwinput.pwinput(prompt="Enter password: ", mask="*")
        auth = pwd.encode() # turn string into bytes
        hash2 = hashlib.sha256(auth).hexdigest() # get the hash string

        try:
            with open('credentials.txt', 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) != 2:
                        continue
                    stored_email, stored_pwd = parts
                    if email == stored_email and hash2 == stored_pwd:
                        print("Logged in Successfully!")
                        return
            print("Login failed! Incorrect email or password.")
        except FileNotFoundError:
            print("No users found. Please sign up first.")

        attempts += 1
        print(f"Login failed! Attempts remaining: {3 - attempts}")

    with open('locked.txt', 'a') as lock_file:
        lock_file.write(email + '\n')
    print("Too many failed attempts. Your account has been locked.")    

while True:
    print('-----Login System-----')
    print('1.SignUp')
    print('2.Login')
    print('3.Exit')

    try:
        choice = int(input('Please enter your choice: '))
    except ValueError:
        print('Invalid input. Please enter a number.')
        continue

    if choice == 1:
        signup()
    elif choice == 2:
        login()
    elif choice == 3:
        print('Exiting... Goodbye')
        break
    else:
        print('Invalid choice. Please try again')
