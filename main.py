import sqlite3, hashlib
from tkinter import *


#-----------------------------DB-----------------------------------------

with sqlite3.connect("vault.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL
);
""")









# ----------------------------GUI--------------------------------------------


window = Tk()

window.title("vault")


def firstScreen():
    window.geometry("300x200")
    lbl1 = Label(window, text="Create MasterKey")
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
            hashedPassword = txt1.get()
            insert_password = """INSERT INTO masterpassword(password)
            VALUES(?)"""
            cursor.execute(insert_password,[(hashedPassword)])
            db.commit()
            passwordVault()
        else:
            txt1.delete(0,'end')
            txt2.delete(0, 'end')
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
        checkHashedPassword = txt1.get()
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?",[(checkHashedPassword)])
        return cursor.fetchall()

    def checkPassword():
        match = getMasterKey()
        if match:
            passwordVault()
        else:
            lbl2.config(text="wrong password")

    btn1 = Button(window, text="Login", command=checkPassword)
    btn1.pack()


def passwordVault():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("700x400")

    lbl1 = Label(window, text="Vault")
    lbl1.config(anchor=CENTER)
    lbl1.pack()


cursor.execute("SELECT * FROM masterpassword ")
if cursor.fetchall():
    loginScreen()
else:
    firstScreen()
window.mainloop()
