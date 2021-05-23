# PasswordManager
A fully functional Password Manager made in python

[![Support me!](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/maneeshpradeep)

## Overview
This is my first ever python project and kinda my best and my most favourite project I've ever done.

Basically This is a fully functional Password Manager that possesses almost all the features an ideal Password Manager should have (except a very few).

<img src="/images/Main-Screen.png" alt="Main Screen" width="500"/>

## Some Main Features of the project
Here are some of the key features of this Password Manager : 
### 1. It stores all your passwords in the **cloud**
  I have integrated this project with my Firebase Console developed by Google to store all the user's data
### 2. All your passwords stored in the cloud are encrypted
  All your passwords in the cloud are stored as encrypted text and not plain text and the key is generated using User Identity based key generation algorithm, so only you can view your data. Not even the admin of the cloud server (me) can view your passwords.
### 3. Secure File Encryption Vault
  I have added a new File encryption Vault feature, where users can store their important documents safe in the cloud. The files will be encrypted before storing in the cloud, so users don't have to worry about the security of their documents.
### 4. It has a fully functional Graphical User Interface
  I have used the [**PySimpleGUI**](https://pysimplegui.readthedocs.io/en/latest/) library to create a fully functional GUI for a seamless experience for the user.
### 5. Secure User authentication
  The user is authenticated using an email and password powered by the Firebase console itself, so users don't have to worry about others accessing their account.
### 6. In-built Password Generator
  I have also added an in-built Password Generator to generate strong and secure passwords. The user has the freedom to choose the output Password length.
### 7. Email verification and Reset Password
  Since the user is authenticated using their email, they will receive a mail link to reset their password in case of forgotten password. This is really useful since only the respective email address owners can change thier passwords making their account more secure from others.
### 8. Clipboard access
  While viewing your passwords, double clicking on them will automatically copy the respective passwords to your device's clipboard. And the best part is that the clipboard will be cleared automatically after 10s after copying.Making your passwords more secure and not easily accessible to others.
  
## Installation
```
# clone this repository
git clone https://github.com/Maneesh-Pradeep/PasswordManager.git

# Change directory
cd PasswordManager

# Execute the python file
python3 PasswordManager.py
```

The program will automatically install all the necessary libraries(dependencies) needed.

But if you are more concerned about the dependencies then you can always create a virtual-env and just do 

`pip3 install -r requirements.txt` to first download all the necessary packages and then run the main program.

## Dependencies
The program depends on the following third party libraries
  * **PySimpleGUI** (for GUI)
  * **pyrebase** (firebase API)
  * **requests** (for firebase error handling)
  * **pandas** (to create a table from the data)
  * **pyperclip** (to copy the passwords to the clipboard)
  * **cryptography** (for encryption and decryption)
  
  You can just refer to the **requirements.txt** file included in the repository

## Future Updates
I will try my best to add new features and remove bugs if any.
Some of the current limitations of the program are :
### 1. Lack of Master Password
  * As I use the Firebase email and password login, I didn't find any way to implement the master password feature. But sure in the future I will.
### 2. Auto-Fill
  * Currently you have the freedom to only copy the password to your clipboard, but the program can't auto fill the passwords if you visit the respective website. For that feature to be implemented, I should have a fully functional **Browser Extension**, which I'm planning to do in the future.
