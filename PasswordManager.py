'''

         PASSWORD MANAGER
               V3.1

Author  : @maneeshpradeep AKA @manojshan
mail    : maneesh.pradeep@protonmail.com
website : https://www.maneeshpradeep.in
github  : github.com/maneesh-pradeep

'''

## Importing the necessary libraries
import os
import random
import secrets
import base64
import json
import threading
import sys
import subprocess

try:
    import pandas as pd
    import PySimpleGUI as sg
    import pyrebase
    from pyrebase.pyrebase import Storage
    from pyrebase.pyrebase import raise_detailed_error
    import pyAesCrypt
    import requests
    import pyperclip
    import cryptography
    from cryptography.fernet import Fernet
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ModuleNotFoundError:
    subprocess.call([sys.executable, "-m", "pip", "install", 'pandas', 'pyperclip', 'PySimpleGUI', 'requests', 'pyrebase4', 'cryptography', 'pyAesCrypt'])
finally:
    import pandas as pd
    import PySimpleGUI as sg
    import pyrebase
    from pyrebase.pyrebase import Storage
    from pyrebase.pyrebase import raise_detailed_error
    import pyAesCrypt
    import requests
    import pyperclip
    from cryptography.fernet import Fernet
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

## Setting up the cloud data
firebaseConfig = {
    "apiKey": "AIzaSyAhz-ekJTOEApHwajGmOtQ0_G2qqOHwpCQ",
    "authDomain": "password-manager-9190e.firebaseapp.com",
    "databaseURL": "https://password-manager-9190e.firebaseio.com",
    "projectId": "password-manager-9190e",
    "storageBucket": "password-manager-9190e.appspot.com",
    "messagingSenderId": "483899833905",
    "appId": "1:483899833905:web:af97e4de5c69cd845d9f10",
    "measurementId": "G-RNWEK4N02Q"
}

firebase = pyrebase.initialize_app(firebaseConfig)
storage = firebase.storage()
db = firebase.database()
auth = firebase.auth()

# Monkey Patching and overriding an obsolete Pyrebase function
def delete(self, name, token):
    if self.credentials:
        self.bucket.delete_blob(name)
    else:
        request_ref = self.storage_bucket + "/o?name={0}".format(name)
        if token:
            headers = {"Authorization": "Firebase " + token}
            request_object = self.requests.delete(request_ref, headers=headers)
        else:
            request_object = self.requests.delete(request_ref)
        raise_detailed_error(request_object)

Storage.delete = delete

## GUI THEME
sg.theme('reddit')

## GUI FOR LOGIN
lgn_layout = [
    [sg.Text("Password Manager\nV3.1", justification='center', size=(25, 2), font=("", 25), relief=sg.RELIEF_RIDGE)],
    [sg.Text("New User?", font=("", 17))],
    [sg.Text("Email : ", size=(20, 1)), sg.InputText("", key="SUemail")],
    [sg.Text("Password : ", size=(20, 1)), sg.InputText("", key="SUpwd", password_char='*')],
    [sg.Text("Confirm Password : ", size=(20, 1)), sg.InputText("", key="CNpwd", password_char='*')],
    [sg.Button("Sign Up")],
    [sg.Text('=' * 70)],
    [sg.Text("Already have an account?", font=("", 17))],
    [sg.Text("Email : ", size=(20, 1)), sg.InputText("", key="SIemail", focus=True)],
    [sg.Text("Password : ", size=(20, 1)), sg.InputText("", key="SIpwd", password_char='*')],
    [sg.Button("Login", bind_return_key=True)]]
lgn_window = sg.Window("Login", lgn_layout)

while True:
    evt, val = lgn_window.read()
    if evt is None:
        lgn_window.Close()
        exit()
    if evt in "Sign Up":
        if (val['SUemail'] != '' and val['SUpwd'] != '' and val['CNpwd'] != ''):
            if (val['SUpwd'] == val['CNpwd']):
                try:
                    auth.create_user_with_email_and_password(val['SUemail'], val['SUpwd'])
                    sg.Popup("Account added successfully. Now login below", keep_on_top=True)
                except requests.exceptions.HTTPError as e:
                    error_json = e.args[1]
                    error = json.loads(error_json)['error']
                    if (error['message'] == "EMAIL_EXISTS"):
                        sg.PopupError("Email already exists! Try logging in", title='Error', keep_on_top=True)
                    else:
                        sg.PopupError(error['message'], title='Error', keep_on_top=True)
            else:
                sg.PopupError("The passwords does not match!", title="Error", keep_on_top=True)
        else:
            sg.PopupError("Fill all fields!", title="Error", keep_on_top=True)
    if evt in "Login":
        if (val['SIemail'] != '' and val['SIpwd'] != ''):
            try:
                global user
                global email
                global pwdKey
                email = val['SIemail']
                user = auth.sign_in_with_email_and_password(val['SIemail'], val['SIpwd'])
                sg.Popup("Logged In", keep_on_top=True)
                pwdKey = val['SIpwd']
                lgn_window.close()
                break
            except requests.exceptions.HTTPError as e:
                error_json = e.args[1]
                error = json.loads(error_json)['error']
                sg.PopupError(error['message'], title='Error', keep_on_top=True)
        else:
            sg.PopupError("Fill all fields!", title="Error", keep_on_top=True)

## Getting the USER INFO
id = auth.get_account_info(user['idToken'])
uid = id['users'][0]['localId']
key = uid[0:6]

## Encryption Algorithm
def generate_key(password, salt=b"\xb9\x1f|}'S\xa1\x96\xeb\x154\x04\x88\xf3\xdf\x05", length=32):
    password = password.encode()

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=length,
                     salt=salt,
                     iterations=100000,
                     backend=default_backend())

    return base64.urlsafe_b64encode(kdf.derive(password))

# Encrypted Keys
db_key = generate_key(pwdKey + key, b"\xb9\x1f|}'S\xa1\x96\xeb\x154\x04\x88\xf3\xdf\x05", 32)
fernet = Fernet(db_key)

vault_key = generate_key(uid + pwdKey, length=64)
buffer_size = 64 * 1024

## Password Generator
def pass_gen(size=14):
    digits = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    locase_chars = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                    'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q',
                    'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
                    'z']

    upcase_chars = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                    'I', 'J', 'K', 'M', 'N', 'O', 'p', 'Q',
                    'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
                    'Z']

    symbols = ['@', '#', '$', '%', '=', ':', '?', '.', '/', '|', '~', '>',
               '*', '(', ')', '&']

    pass_chars = digits + locase_chars + upcase_chars + symbols

    rand_digit = secrets.choice(digits)
    rand_lochar = secrets.choice(locase_chars)
    rand_upchar = secrets.choice(upcase_chars)
    rand_symbol = secrets.choice(symbols)

    temp_pass = rand_digit + rand_lochar + rand_symbol + rand_upchar

    for i in range(size - 4):
        temp_pass += secrets.choice(pass_chars)

    temp_list = list(temp_pass)
    random.shuffle(temp_list)

    password = ""
    for i in temp_list:
        password += i

    return password


## Function Declarations
# Functions used after Password Reset
def reEncrypt_db():
    for i, _ in enumerate(data):
        update_db(i, data[i]['aservice'], data[i]['mail'], data[i]['password'])

def reEncrypt_vault():
    get_file_db()
    for i,file in enumerate(filesData):
        filenameWithExt = file['filename']
        filename = filenameWithExt[:-4]
        storage.child('users/' + uid).child(filenameWithExt).download(path='/', filename=filenameWithExt, token=user['idToken'])
        filesize = os.path.getsize(filenameWithExt)
        pyAesCrypt.decryptFile(filenameWithExt, filename, prev_vault_key, buffer_size)
        os.remove(filenameWithExt)

        storage.delete(name="users/{}/{}".format(uid,filenameWithExt), token=user['idToken'])
        remove_file_db(i)

        add_file(filename, filenameWithExt, filesize)
        os.remove(filename)

def runAfterPwdReset():
    global temp_fernet
    global temp_key
    global prev_vault_key
    temp_data = db.child('temp/' + uid).child('key').get(user['idToken'])
    temp_data = temp_data.val()
    vault_data = db.child('temp/' + uid).child('vaultkey').get(user['idToken'])
    vault_data = vault_data.val()
    temp_key = generate_key(uid)
    temp_fernet = Fernet(temp_key)
    temp_key = (temp_fernet.decrypt((temp_data['key']).encode())).decode()
    prev_vault_key = (temp_fernet.decrypt((vault_data['key']).encode())).decode()
    temp_fernet = Fernet(temp_key.encode())
    db.child('temp/' + uid).child('key').remove(user['idToken'])
    db.child('temp/' + uid).child('vaultkey').remove(user['idToken'])
    get_db(temp_fernet)
    reEncrypt_db()
    get_db(fernet)
    reEncrypt_vault()

# A function to get the realtime data from the database
def get_db(fernet):
    global data
    global keys
    all_data = db.child("user/" + uid).get(user['idToken'])
    data = []
    keys = []
    headers = ['aservice', 'mail', 'password']
    try:
        for text in all_data.each():
            keys.append(text.key())
            for i in headers:
                if (i == 'password'):
                    text.val()[i] = (fernet.decrypt((text.val()[i]).encode())).decode()
                    data.append(text.val())
    except TypeError:
        add_db("Edit", "This", "Field")
        get_db(fernet)
    except (cryptography.exceptions.InvalidSignature, cryptography.fernet.InvalidToken):
        runAfterPwdReset()


# A function to update the database
def update_db(index, serv, mail, pwd):
    global data
    data[index]['aservice'] = serv
    data[index]['mail'] = mail
    data[index]['password'] = (fernet.encrypt(pwd.encode())).decode()
    upData = data[index]
    db.child("user/" + uid).child(keys[index]).update(upData, user['idToken'])


# A function to update the gui table values
def update_table():
    global data
    global df
    global table_data
    get_db(fernet)
    df = pd.DataFrame(data)
    table_data = df.values.tolist()


# A function to remove the selected values from the database
def remove_db(index):
    global keys
    db.child("user/" + uid).child(keys[index]).remove(user['idToken'])
    sg.Popup("Data successfully removed", title="Success")
    get_db(fernet)


# A function to add values to the database
def add_db(serv, mail, pwd):
    temp_data = {"aservice": serv, "mail": mail, "password": (fernet.encrypt(pwd.encode())).decode()}
    db.child("user/" + uid).push(temp_data, user['idToken'])
    get_db(fernet)

# File Encryption Vault Functions
# Function to get the filenames from the database
def get_file_db():
    global filesData
    global filesKey
    global dataUsed
    all_files_data = db.child('files/'+uid).get(user['idToken'])
    filesData = []
    filesKey = []
    dataUsed = 0
    try:
        for file in all_files_data.each():
            filesKey.append(file.key())
            temp = file.val()
            dataUsed += int(temp['size'])
            temp['size'] = size_conv(int(temp['size']))
            filesData.append(temp)
    except TypeError:
        with open('sample.txt', 'w') as f:
            f.write("The data you want to secure goes here")
        filenameWithExt = os.path.basename('sample.txt')+'.aes'
        filesize = os.path.getsize('sample.txt')
        add_file('sample.txt', filenameWithExt, filesize)
        os.remove('sample.txt')
        get_file_db()

# Funtion to Add a file to the storage
def add_file(filepath, filenameWithExt, filesize):
    pyAesCrypt.encryptFile(filepath, filenameWithExt, vault_key.decode(), buffer_size)
    storage.child('users/' + uid).child(filenameWithExt).put(filenameWithExt, user['idToken'])
    temp_data = {'filename': filenameWithExt, 'size': filesize}
    db.child("files/" + uid).push(temp_data, user['idToken'])
    os.remove(filenameWithExt)

# Function to update the files table
def update_file_table():
    global filesData
    global filesDF
    global filesTableData
    get_file_db()
    filesDF = pd.DataFrame(filesData)
    filesTableData = filesDF.values.tolist()

# Funtion to Remove a file from the storage
def remove_file_db(index):
    global filesKey
    db.child("files/" + uid).child(filesKey[index]).remove(user['idToken'])

# Function to convert bytes into Human readable form
def size_conv(bytes):
    unit = {1:'B', 2:'K', 3:'M', 4:'G', 5:'T'}
    if bytes==0:
        return "0B"
    for i in range(1,6):
        if(bytes < (1024**i)):
            return str(bytes//1024**(i-1)) + unit[i]


# A function to clear the clipboard
def clear():
    pyperclip.copy("")


## Initializing the database table and values
get_db(fernet)

try:
    db.child('temp/' + uid).child('key').remove(user['idToken'])
    db.child('temp/' + uid).child('vaultkey').remove(user['idToken'])
except Exception:
    pass

df = pd.DataFrame(data)
table_data = df.values.tolist()

## MAIN GUI
gui_col = sg.Column(layout=[[sg.Frame('Add Data', layout=[[sg.Column([[sg.T("Click this button to ADD new data : ", font=("bold", 15),
                                                                    text_color="green", tooltip="To add new data to the database")],
                                                                [sg.Button("Add", size=(7, 1), font=("", 12))]]
                                                                , size=(500,70))]
                                                    ], title_color="green")
                            ],
                            [sg.Frame('View Data', layout=[[sg.Column([[sg.T("Click this button to VIEW or UPDATE the existing data : ", font=("bold", 15), 
                                                                    text_color="red", tooltip="To view and update the data")],
                                                                [sg.Button("View", size=(7, 1), font=("", 12))]]
                                                                , size=(500,70))]
                                                    ], title_color="red")
                            ],
                            [sg.Frame('Encrypted Vault', layout=[[sg.Column([[sg.T("Click this button to Open your Vault : ", font=("bold", 15), 
                                                                    text_color="purple", tooltip="To open your secure vault")],
                                                                [sg.Button("Vault", size=(7, 1), font=("", 12))]]
                                                                , size=(500,70))]
                                                    ], title_color="purple")
                            ],
                            [sg.Frame('Reset Password', layout=[[sg.Column([[sg.T("Click this button to Reset your password : ", font=("bold", 15), 
                                                                    text_color='blue', tooltip="To Reset your Password")],
                                                                [sg.Button("Reset", size=(7, 1), font=("", 12))]] 
                                                                , size=(500,70))]
                                                    ], title_color="blue")
                            ]])

layout = [
    [sg.Text("Password Manager\nV3.1", justification='center', size=(25, 2), font=("", 25), relief=sg.RELIEF_RIDGE)],
    [gui_col]]

window = sg.Window("Password Manager", layout)
add_window_active = False
view_window_active = False
upd_window_active = False
vault_window_active = False
res_window_active = False

while True:
    event, value = window.Read()
    if event == None:
        window.close()
        break

    if event in 'Add' and not add_window_active:
        add_window_active = True
        window.hide()
        rnd_pass_frame = [
            [sg.T("Click here to generate a strong password : ", font=("", 14), text_color='blue')],
            [sg.Button("Generate", font=("", 12))]]
        add_layout = [
            [sg.T("Add a new entry : ", font=("", 15), size=(39, 1), text_color='green', relief=sg.RELIEF_RIDGE)],
            [sg.T("Service     : ", size=(12, 0), font=("", 14), text_color='orange'),
             sg.InputText('', key='serv', font=(10, 0), size=(30, 0))],
            [sg.T("User/Mail  : ", size=(12, 0), font=("", 14), text_color='orange'),
             sg.InputText('', key='mail', font=(10, 0), size=(30, 0))],
            [sg.T("Password  : ", size=(12, 0), font=("", 14), text_color='orange'),
             sg.InputText('', key='pwd', font=(10, 0), size=(30, 0))],
            [sg.T("=" * 65, text_color='lightblue')],
            [sg.Frame("Generate Password", rnd_pass_frame, title_color='purple')],
            [sg.T("=" * 65, text_color='lightblue')],
            [sg.B("Submit", size=(7, 1), font=("", 12), pad=(10, 5), bind_return_key=True)]]
        add_window = sg.Window("Add", add_layout)
        while True:
            e, v = add_window.read()
            if e == None:
                add_window_active = False
                add_window.close()
                window.UnHide()
                break
            if e in 'Submit':
                if(v['pwd'] != ''):
                    add_db(v['serv'], v['mail'], v['pwd'])
                    update_table()
                    sg.Popup("Entry Added successfully", title='Success', keep_on_top=True)
                    window.refresh()
                    add_window_active = False
                    add_window.close()
                    window.UnHide()
                    break
                else:
                    sg.PopupError("Password field should not be empty!", title='Error', keep_on_top=True)
            if e in 'Generate':
                size = sg.PopupGetText("Enter the length of the password : ", keep_on_top=True)
                try:
                    pwd = pass_gen(int(size))
                    add_window['pwd'](pwd)
                except:
                    pass

    if event == 'View' and not view_window_active:
        view_window_active = True
        window.hide()
        clip_frame = [[sg.T("Select a row and double click or press enter to copy\n the password to clipboard")],
                      [sg.T(
                          "NOTE : The copied password will be cleared from the\n clipboard automatically after 10 seconds")]]
        view_layout = [[sg.Table(values=table_data, headings=["Service", "Mail/User", "Password"], key='-TABLE-',
                                 auto_size_columns=True, alternating_row_color="lightgreen", font=("", 17),
                                 bind_return_key=True)],
                       [sg.Frame("Clipboard", clip_frame, title_color='red')],
                       [sg.Button('Update', size=(7, 1), font=("", 12)), sg.B("Remove", size=(7, 1), font=("", 12))]]
        view_window = sg.Window("View", view_layout)
        while True:
            evt, val = view_window.read()

            if evt == None:
                view_window_active = False
                view_window.close()
                window.UnHide()
                break

            if evt in '-TABLE-':
                if (len(val['-TABLE-']) == 1):
                    ref_data = data[int(val['-TABLE-'][0])]
                    pyperclip.copy(ref_data['password'])
                    sg.Popup(
                        "Password copied to clipboard\nPassword will be automatically cleared from the keyboard after 10 seconds", keep_on_top=True)
                    t = threading.Timer(10.0, clear)
                    t.start()
                else:
                    sg.PopupError("select atleast and atmost one row", title="Error", keep_on_top=True)

            if evt in 'Update' and not upd_window_active:
                if (len(val['-TABLE-']) == 1):
                    upd_window_active = True
                    view_window.hide()
                    rnd_pass_frame = [[sg.T("Click here to generate a strong password : ", font=("", 14),
                                            text_color='blue')],
                                      [sg.Button("Generate", font=("", 12))]]
                    ref_data = data[int(val['-TABLE-'][0])]
                    upd_layout = [[sg.T("Update the selected entry : ", font=("", 15), size=(39, 1), text_color='green',
                                        relief=sg.RELIEF_RIDGE)],
                                  [sg.T("Service     : ", size=(12, 0), font=("", 14), text_color='orange'),
                                   sg.InputText(ref_data['aservice'], key='serv', font=(10, 0), size=(30, 0))],
                                  [sg.T("User/Mail  : ", size=(12, 0), font=("", 14), text_color='orange'),
                                   sg.InputText(ref_data['mail'], key='mail', font=(10, 0), size=(30, 0))],
                                  [sg.T("Password  : ", size=(12, 0), font=("", 14), text_color='orange'),
                                   sg.InputText(ref_data['password'], key='pwd', font=(10, 0), size=(30, 0))],
                                  [sg.T("=" * 65, text_color='lightblue')],
                                  [sg.Frame("Generate Password", rnd_pass_frame, title_color='purple')],
                                  [sg.T("=" * 65, text_color='lightblue')],
                                  [sg.B("Submit", size=(7, 1), font=("", 12), pad=(10, 5))]]
                    upd_window = sg.Window("Update", upd_layout)
                    while True:
                        e, v = upd_window.read()
                        if e == None:
                            upd_window_active = False
                            upd_window.close()
                            view_window.UnHide()
                            break

                        if e in 'Submit':
                            if(v['pwd'] != ''):
                                update_db(val['-TABLE-'][0], v['serv'], v['mail'], v['pwd'])
                                update_table()
                                sg.Popup("Data successfully updated", title="Success")
                                view_window['-TABLE-'](values=table_data)
                                view_window.refresh()
                                upd_window_active = False
                                upd_window.close()
                                view_window.UnHide()
                                break
                            else:
                                sg.PopupError("Password field should not be empty!", title='Error', keep_on_top=True)

                        if e in 'Generate':
                            size = sg.PopupGetText("Enter the length of the password : ", keep_on_top=True)
                            try:
                                pwd = pass_gen(int(size))
                                upd_window['pwd'](pwd)
                            except:
                                pass
                else:
                    sg.PopupError("select atleast and atmost one row", title="Error", keep_on_top=True)

            if evt in 'Remove':
                if (len(val['-TABLE-']) == 1):
                    confirm = sg.PopupYesNo("Do you want to remove the entry from the database?", title='confirmation', keep_on_top=True)
                    if confirm == 'Yes':
                        remove_db(val['-TABLE-'][0])
                        update_table()
                        view_window['-TABLE-'](values=table_data)
                        view_window.refresh()
                    else:
                        pass
                else:
                    sg.PopupError("select atleast and atmost one row", title="Error", keep_on_top=True)
    
    if event == 'Vault' and not vault_window_active:
        vault_window_active = True
        window.hide()

        vault_pass = sg.PopupGetText("Enter your password : ", keep_on_top=True, password_char='*')
        if vault_pass == pwdKey:
            pass
        else:
            sg.PopupError("Wrong password!", keep_on_top=True, title='Error')
            vault_window_active = False
            window.UnHide()
            continue

        get_file_db()

        filesDF = pd.DataFrame(filesData)
        filesTableData = filesDF.values.tolist()

        accessLimit = int(db.child("access").get().val())

        vault_layout = [[sg.Table(values=filesTableData, headings=["File", "Size"], key='FileTable',
           auto_size_columns=True, alternating_row_color="lightgreen", max_col_width=50,
           font=("", 17),bind_return_key=True)],
          [sg.Button("Add", size=(7, 1), font=("", 12)),
           sg.Button("Download", size=(7, 1), font=("", 12)),
           sg.Button("Remove", size=(7, 1), font=("", 12))]]
        vault_window = sg.Window(layout=vault_layout,title='Vault')

        while True:
            evt, val = vault_window.read()

            if evt == None:
                vault_window.close()
                vault_window_active = False
                window.UnHide()
                break

            if evt in 'Add':
                filepath = sg.PopupGetFile("Select the file : ")
                try:
                    filename = os.path.basename(filepath)
                    filenameWithExt = filename+'.aes'
                    filesize = os.path.getsize(filepath)
                    if filesize <= (accessLimit - dataUsed):
                        if filesize <= 30*(1024**2):
                            try:
                                add_file(filepath, filenameWithExt, filesize)
                                update_file_table()
                                vault_window['FileTable'](values=filesTableData)
                                vault_window.refresh()
                                sg.Popup("File added successfully", title='Success', keep_on_top=True)
                            except:
                                sg.PopupError('problem occurred!', title='Error', keep_on_top=True)
                        else:
                            sg.PopupError("Select a file less than 30MB", title='Error', keep_on_top=True)
                    else:
                        sg.PopupError("Storage limit reached! Only {} left".format(size_conv(int(accessLimit - dataUsed))))
                except:
                    sg.PopupError("Error encrypting file!", title='Error', keep_on_top=True)

            if evt in 'Download':
                if (len(val['FileTable'])==1):
                    filenameWithExt = filesData[int(val['FileTable'][0])]['filename']
                    filename = filenameWithExt[:-4]
                    dlPath = sg.PopupGetFolder("Choose the download location : ", keep_on_top=True)
                    dlPath = os.path.abspath(dlPath)
                    if os.name == 'nt':
                        dlPath += '\\'
                    else:
                        dlPath += '/'
                    try:
                        storage.child('users/' + uid).child(filenameWithExt).download(path='/', filename=dlPath+filenameWithExt, token=user['idToken'])
                        try:
                            pyAesCrypt.decryptFile(dlPath+filenameWithExt, dlPath+filename, vault_key.decode(), buffer_size)
                            sg.Popup('File Downloaded Successfully', title='Success', keep_on_top=True)
                            os.remove(dlPath+filenameWithExt)
                        except:
                            sg.PopupError('problem occurred!', title='Error', keep_on_top=True)
                    except:
                        sg.PopupError('File does not exist!', title='Error', keep_on_top=True)
                else:
                    sg.PopupError("Select only one file at a time!", title='Error', keep_on_top=True)

            if evt in 'Remove':
                if (len(val['FileTable']) == 1):
                    confirm = sg.PopupYesNo("Are you sure to delete this file? You cannot undo this process", keep_on_top=True)
                    if confirm == "Yes":
                        filenameWithExt = filesData[int(val['FileTable'][0])]['filename']
                        try:
                            storage.delete(name="users/{}/{}".format(uid,filenameWithExt), token=user['idToken'])
                            remove_file_db(val['FileTable'][0])
                            sg.Popup("File successfully removed", title="Success", keep_on_top=True)
                            update_file_table()
                            vault_window['FileTable'](values=filesTableData)
                            vault_window.refresh()
                        except:
                            sg.PopupError("File delete unsuccessful!Try again!", title='Error', keep_on_top=True)
                else:
                    sg.PopupError("Select only one file at a time!", title='Error', keep_on_top=True)

    if event == 'Reset' and not res_window_active:
        res_window_active = True
        window.hide()
        emailVerified = id['users'][0]['emailVerified']
        if (emailVerified):
            mailText = "Mail Verified"
            mail_ver_col = 'green'
        else:
            mailText = "Please verify your email!"
            mail_ver_col = 'red'

        reset_note_frame = [[sg.T("After resetting the password, you have to restart the program and wait for\n a min or 2 as the program decrypts and re-encrypts all of your existing\n data using your new password")]]
        res_layout = [[sg.Text(mailText, font=("", 16), text_color=mail_ver_col)],
                      [sg.Button("Verify Email", font=("", 12))],
                      [sg.Text("=" * 60, text_color='lightblue')],
                      [sg.Text("Click below to get a link to reset your password", font=("", 16), text_color='red')],
                      [sg.Button("Reset", size=(7, 1), font=("", 12))],
                      [sg.Frame("Note:", reset_note_frame, title_color='red', element_justification='center')]]
        res_window = sg.Window("Password Settings", res_layout)
        while True:
            ev2, val2 = res_window.Read()
            if ev2 is None:
                res_window.Close()
                res_window_active = False
                window.UnHide()
                break

            if ev2 == 'Verify Email':
                auth.send_email_verification(user['idToken'])
                sg.Popup("Mail has been sent to your respective account", title="Verify Email", keep_on_top=True)
                res_window.Close()
                res_window_active = False
                window.UnHide()
                break

            if ev2 == "Reset":
                auth.send_password_reset_email(email)
                temp_key = generate_key(uid)
                temp_fernet = Fernet(temp_key)
                enc_uid = temp_fernet.encrypt(db_key)
                temp_data = {'key':enc_uid.decode()}
                enc_vault = temp_fernet.encrypt(vault_key)
                vault_data = {'key':enc_vault.decode()}
                db.child('temp/'+uid).child('key').set(temp_data, user['idToken'])
                db.child('temp/'+uid).child('vaultkey').set(vault_data, user['idToken'])
                sg.Popup("Mail has been sent to your respective account. Now the program will close automatically!", title="Reset Password", keep_on_top=True)
                exit()
                break


# MIT (c) Maneesh Pradeep
