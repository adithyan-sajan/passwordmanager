import sqlite3, hashlib
from tkinter import *
from tkinter import simpledialog
from functools import partial
import pyperclip

# -----------------------------DB-----------------------------------------
#testing git
with sqlite3.connect("vault.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL
);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL
);
""")


# ------------------------------Pop-up---------------------------------------

def popUp(text):
    answer = simpledialog.askstring("input String", text)
    return answer


# ----------------------------GUI--------------------------------------------


window = Tk()
window.title("vault")


def hashPassword(input):
    hash = hashlib.md5(input)
    hash = hash.hexdigest()

    return hash


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
            hashedPassword = hashPassword(txt1.get().encode('utf-8'))
            insert_password = """INSERT INTO masterpassword(password)
            VALUES(?)"""
            cursor.execute(insert_password, [(hashedPassword)])
            db.commit()
            passwordVault()
        else:
            txt1.delete(0, 'end')
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
        checkHashedPassword = hashPassword(txt1.get().encode('utf-8'))
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [(checkHashedPassword)])
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

    def addEntry():
        text1 = "Website"
        text2 = "Username"
        text3 = "Password"
        website = popUp(text1)
        username = popUp(text2)
        password = popUp(text3)

        insert_fields = """
        INSERT INTO vault(website,username,password)
        VALUES(?,?,?)
        """

        cursor.execute(insert_fields, (website, username, password))

        db.commit()

        passwordVault()

    def removeEntry(input):
        cursor.execute("DELETE FROM VAULT WHERE id = ?", (input,))
        db.commit()

        passwordVault()

    window.geometry("700x400")

    lbl1 = Label(window, text="Vault")
    lbl1.grid(column=1, pady=10)

    btn = Button(window, text="Add", command=addEntry)
    btn.grid(column=2, pady=10)

    lbl1 = Label(window, text="website")
    lbl1.grid(row=3, column=0, padx=80)
    lbl1 = Label(window, text="username")
    lbl1.grid(row=3, column=1, padx=80)
    lbl1 = Label(window, text="password")
    lbl1.grid(row=3, column=2, padx=80)
    txts = Entry(window, width=30)
    txts.grid(row=1, column=1, sticky='w')

    global tosearch
    tosearch = ""

    def search():

        if (cursor.fetchall() != None):
            i = 0
            labels = []
            while True:
                print(tosearch)
                if tosearch == "":
                    cursor.execute("SELECT * FROM vault")
                else:
                    cursor.execute("SELECT * FROM vault WHERE website LIKE ?", ('%{}%'.format(tosearch),))

                array = cursor.fetchall()
                status = [0] * len(array)

                def shpass(array, j):
                    print(j)
                    if status[j ] == 0:
                        status[j ] = 1
                        labels[j].config(text=(array[j][3]))
                    elif status[j ] == 1:
                        status[j ] = 0
                        labels[j].config(text="*******")


                lbl2 = Label(window, text=(array[i][1]))
                lbl2.grid(column=0, row=i + 4)
                lbl2 = Label(window, text=(array[i][2]))
                lbl2.grid(column=1, row=i + 4)
                lblp = Label(window, text='*******')
                lblp.grid(column=2, row=i + 4)
                labels.append(lblp)

                btns = Button(window, text='show/hide', command=lambda index = i: shpass(array, index))
                btns.grid(column=3, row=i + 4)

                btnc = Button(window, text="copy", command=pyperclip.copy(array[i][3]))
                btnc.grid(column=4, row=i + 4)
                btn = Button(window, text="delete", command=partial(removeEntry, array[i][0]))
                btn.grid(column=5, row=i + 4, pady=10)

                i = i + 1
                cursor.execute("SELECT * FROM vault")
                if (len(cursor.fetchall()) <= i):
                    break

    def savetosearch():
        global tosearch
        tosearch = txts.get()
        search()

    btn = Button(window, text="search", command=lambda: savetosearch())
    btn.grid(row=1, column=0)


cursor.execute("SELECT * FROM masterpassword ")
if cursor.fetchall():
    loginScreen()
else:
    firstScreen()
window.mainloop()
