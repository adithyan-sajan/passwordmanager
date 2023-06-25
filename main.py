#--------------------Requirements------------------------
# pip install google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client
# pip install pyperclip cryptography

#--------------------Imports-----------------------------
import sqlite3, hashlib
from tkinter import *
from tkinter import simpledialog
from functools import partial
import pyperclip
import random
import string
import tkinter as tk
from tkinter import ttk
from cryptography.fernet import Fernet
import base64
import os
from google.oauth2 import credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

# -----------------------------DB-----------------------------------------

with sqlite3.connect("vault.db") as db:
    cursor = db.cursor()

cursor.execute(
    """
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL
);
"""
)

cursor.execute(
    """
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL
);
"""
)
#---------------------------Backup-------------------------------------------
SCOPES = ['https://www.googleapis.com/auth/drive.file']

def authenticate():
    flow = InstalledAppFlow.from_client_secrets_file(
        r'D:\Code rep\pythonProject\client_secret.json', SCOPES)
    creds = flow.run_local_server(port=0)
    return creds

def upload_file_to_drive(file_path, drive_service):
    file_name = os.path.basename(file_path)
    metadata = {'name': file_name}
    media = MediaFileUpload(file_path, resumable=True)
    drive_service.files().create(body=metadata, media_body=media).execute()

def backup():
    credentials = authenticate()
    drive_service = build('drive', 'v3', credentials=credentials)
    file_path = 'vault.db'  # Replace with the path to the file you want to upload
    upload_file_to_drive(file_path, drive_service)

# ------------------------PassKey_Gen----------------------------------------
def gen_pass():
    password = ""
    characters = string.ascii_letters + string.digits
    for i in range(12):
        password += random.choice(characters)
    return password


# ------------------------------Pop-up---------------------------------------


def popUp(text):
    answer = simpledialog.askstring("input String", text)
    return answer


def create_popup_window():
    popup_window = tk.Toplevel()
    popup_window.geometry("300x150")
    tk.Label(popup_window, text="Enter Password:").pack()
    input_entry = tk.Entry(popup_window)
    input_entry.pack()

    def submit_text():
        text = input_entry.get()
        popup_window.destroy()
        popup_window.result = text

    submit_button = tk.Button(popup_window, text="Submit", command=submit_text)
    submit_button.pack(pady=10)

    def autofill_textbox():
        text = gen_pass()
        input_entry.delete(0, "end")
        input_entry.insert(0, text)

    autofill_button = tk.Button(popup_window, text="Autofill", command=autofill_textbox)
    autofill_button.pack(pady=5)

    popup_window.wait_window()

    return popup_window.result


# ----------------------------GUI--------------------------------------------

cipher=""
window = Tk()
window.title("vault")


def hashPassword(input):
    hash = hashlib.md5(input)
    hash = hash.hexdigest()

    return hash


def firstScreen():
    window.geometry("300x200")
    lbl1 = Label(window, text="Create a MasterKey")
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    txt1 = Entry(window, width=20, show="*")
    txt1.pack(pady=10)
    txt1.focus()

    lbl2 = Label(window, text="Re-enter MasterKey")
    lbl2.pack()

    txt2 = Entry(window, width=20, show="*")
    txt2.pack(pady=10)

    lbl3 = Label(window, text="")
    lbl3.pack()

    def savePassword():
        if txt1.get() == txt2.get():
            hashedPassword = hashPassword(txt1.get().encode("utf-8"))
            insert_password = """INSERT INTO masterpassword(password)
            VALUES(?)"""
            cursor.execute(insert_password, [(hashedPassword)])
            db.commit()
            global cipher
            keyroot = txt1.get()
            key = keyroot.encode("utf-8")
            hashed_key = hashlib.sha256(key).digest()[:32]
            base64_encoded_key = base64.urlsafe_b64encode(hashed_key)
            cipher = Fernet(base64_encoded_key)
            passwordVault()
        else:
            txt1.delete(0, "end")
            txt2.delete(0, "end")
            lbl3.config(text="Keys don't match")

    btn1 = Button(window, text="Submit", command=savePassword)
    btn1.pack()


def loginScreen():
    window.geometry("300x150")
    lbl1 = Label(window, text="Enter MasterKey")
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    txt1 = Entry(window, width=20, show="*")
    txt1.pack(pady=10)
    txt1.focus()

    lbl2 = Label(window)
    lbl2.pack()

    def getMasterKey():
        checkHashedPassword = hashPassword(txt1.get().encode("utf-8"))
        cursor.execute(
            "SELECT * FROM masterpassword WHERE id = 1 AND password = ?",
            [(checkHashedPassword)],
        )
        return cursor.fetchall()

    def checkPassword():
        match = getMasterKey()
        if match:
            global cipher
            keyroot = txt1.get()
            key = keyroot.encode("utf-8")
            hashed_key = hashlib.sha256(key).digest()[:32]
            base64_encoded_key = base64.urlsafe_b64encode(hashed_key)
            cipher = Fernet(base64_encoded_key)
            passwordVault()
        else:
            lbl2.config(text="wrong password")

    btn1 = Button(window, text="Login", command=checkPassword)
    btn1.pack()


def passwordVault():
    for widget in window.winfo_children():
        widget.destroy()

    def addEntry():
        text1 = "Website"
        text2 = "Username"
        website = popUp(text1)
        username = popUp(text2)
        password = create_popup_window()

        encrypted_website = cipher.encrypt(website.encode())
        encrypted_username = cipher.encrypt(username.encode())
        encrypted_password = cipher.encrypt(password.encode())

        insert_fields = """
        INSERT INTO vault(website,username,password)
        VALUES(?,?,?)
        """

        cursor.execute(insert_fields, (encrypted_website, encrypted_username, encrypted_password))

        db.commit()

        passwordVault()

    def removeEntry(input):
        cursor.execute("DELETE FROM VAULT WHERE id = ?", (input,))
        db.commit()

        passwordVault()

    window.geometry("800x400")

    lbl1 = Label(window, text="website")
    lbl1.grid(row=3, column=0, padx=80)
    lbl1 = Label(window, text="username")
    lbl1.grid(row=3, column=1, padx=80)
    lbl1 = Label(window, text="password")
    lbl1.grid(row=3, column=2, padx=80)
    txts = Entry(window, width=30)
    txts.grid(row=0, column=1, sticky="w")

    global tosearch
    tosearch = ""

    def search():
        def savetosearch():
            global tosearch
            tosearch = txts.get()
            search()

        if cursor.fetchall() != None:
            i = 0
            labels = []

            for widget in window.winfo_children():
                widget.destroy()

            nf = Frame(window)
            nf.grid(row=4, column=0, columnspan=1)

            lbl1 = Label(nf, text="Vault")
            lbl1.grid(column=1, pady=10)
            btn = Button(nf, text="Search", command=lambda: savetosearch())
            btn.grid(row=1, column=0)
            btn = Button(nf, text="Add New Entry", command=addEntry)
            btn.grid(row=1, column=2,  padx=10, pady=10)
            btn2 = Button(nf, text="BackUp", command=backup)
            btn2.grid(row=1, column=3, pady=10)


            main_frame = Frame(window)
            main_frame.grid(row=5, column=0, columnspan=3)

            canvas = Canvas(main_frame, width=750)
            canvas.pack(side=LEFT, expand=1, fill=BOTH, padx=0)
            contents_frame = Frame(canvas)
            canvas.create_window((0, 0), window=contents_frame, anchor="nw")
            scrollbar = ttk.Scrollbar(main_frame, orient=VERTICAL, command=canvas.yview)
            scrollbar.pack(side=RIGHT, fill=Y)

            canvas.configure(yscrollcommand=scrollbar.set)
            canvas.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all")),
            )


            lbl1 = Label(contents_frame, text="website")
            lbl1.grid(row=0, column=0, padx=50)
            lbl1 = Label(contents_frame, text="username")
            lbl1.grid(row=0, column=1, padx=40)
            lbl1 = Label(contents_frame, text="password")
            lbl1.grid(row=0, column=2, padx=40)
            txts = Entry(nf, width=30)
            txts.grid(row=1, column=1, padx=10 ,sticky="w")
            while True:
                print(tosearch)
                if tosearch == "":
                    cursor.execute("SELECT * FROM vault")
                else:
                    cursor.execute(
                        "SELECT * FROM vault WHERE website LIKE ?",
                        ("%{}%".format(tosearch),),
                    )

                array = cursor.fetchall()
                status = [0] * len(array)

                def shpass(array, j):
                    if status[j] == 0:
                        status[j] = 1
                        labels[j].config(text=cipher.decrypt(array[j][3]).decode())
                    elif status[j] == 1:
                        status[j] = 0
                        labels[j].config(text="*******")

                def cpypass(array, j):
                    decrypted_password = cipher.decrypt(array[j][3]).decode()
                    pyperclip.copy(decrypted_password)

                lbl2 = Label(contents_frame, text=cipher.decrypt(array[i][1]).decode())
                lbl2.grid(column=0, row=i+1, padx=(50, 50))

                lbl2 = Label(contents_frame, text=cipher.decrypt(array[i][2]).decode())
                lbl2.grid(column=1, row=i+1, padx=(70, 70))
                lblp = Label(contents_frame, text="*******")
                lblp.grid(column=2, row=i+1, padx=(75, 75))
                labels.append(lblp)


                btns = Button(
                    contents_frame,
                    text="show/hide",
                    command=lambda index=i: shpass(array, index),
                )
                btns.grid(column=3, row=i+1)

                btnc = Button(
                    contents_frame,
                    text="copy",
                    command=lambda index=i: cpypass(array, index),
                )
                btnc.grid(column=4, row=i+1)

                btn = Button(
                    contents_frame,
                    text="delete",
                    command=partial(removeEntry, array[i][0]),
                )
                btn.grid(column=5, row=i+1, pady=10)

                i = i + 1
                cursor.execute("SELECT * FROM vault")
                if len(cursor.fetchall()) <= i:
                    break

    search()


cursor.execute("SELECT * FROM masterpassword ")
if cursor.fetchall():
    loginScreen()
else:
    firstScreen()
window.mainloop()
