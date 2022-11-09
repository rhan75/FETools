import tkinter as tk
from tkinter import ttk
from tkinter.filedialog import askopenfilename
import fireeyepy
import configparser
import os
from datetime import datetime

config = configparser.ConfigParser()
config.read('./config.ini')
API_KEY = config['DEFAULT']['API_Key']
filename = None
result = None

def insert_text(textbox, contents): #Change textbox from readonly to normal, clear, insert contents if exists, and disable edit
    textbox.configure(state='normal')
    textbox.delete('1.0', 'end')
    if contents:
        textbox.insert('1.0', contents)
    textbox.configure(state='disabled')

def select_file(): #Select the file for testing
    global filename
    filename = askopenfilename()
    insert_text(text_file, filename)

def check_file(): #Check for malicious code from a selected file, then get the report back
    global result
    result = None
    conn = fireeyepy.Detection(key=API_KEY)
    if filename:
        report = get_report(filename, conn)
        basic_result = (
            f"Report ID: {report['report_id']}\n"
            f"Submitted: {report['started_at']}\n"
            f"File Name: {filename}\n"
            f"Malcious: {report['is_malicious']}\n"
            f"SHA256: {report['sha256']}"
        )
        if report['is_malicious']:
            result = (
                "Verdict: Malicious\n"
                f'{basic_result}'
                f"Signature Name: {report['signature_name']}\n"
                f"Miter Mapping: {report['mitre_mapping']}\n"
            )
        else:
            result = (
                "Verdict: Not Malicious\n"
                f'{basic_result}'
            )
    else: 
        result = 'Failed - Select a file to submit first'
    insert_text(text_result, result)
        
def get_report(filename, conn): #Submit filename and return the report
    response = conn.submit_file(
        files={
            'file':('filename', open(filename, 'rb'))
        }
    )
    return conn.get_report(response['report_id'])

def save_result(): #Save result into a text file
    if not result:
        save_status = 'Cannot Save the result - No result found'

    else:
        current_date_time = datetime.now()
        now = current_date_time.strftime("%b-%d-%Y-%H-%M-%S")
        cur_dir = os.getcwd()
        save_file = os.path.join(cur_dir, f'{filename}-{now}.txt')
        with open(save_file, 'w') as file:
            file.write(result)
        save_status = f'{save_file} created'
    insert_text(text_result, save_status)

def clear_text(): #Clear all textboxes
    global result
    global filename
    filename = None
    result = None
    insert_text(text_file, filename)
    insert_text(text_result, result)

root = tk.Tk()
frame = ttk.Frame(root, padding=10)
frame.grid()
root.title('Detection on Demand')
button_frame = ttk.Frame(frame)
button_frame.grid(column=0, row=2, sticky='W')

#Textbox for file and result
text_file = tk.Text(frame, state='disabled', height=1)
text_file.grid(column=0, row=0, columnspan=3, sticky='W', pady=5, ipadx=2, ipady=2)

text_result = tk.Text(frame, state='disabled')
text_result.grid(column=0, row=1, columnspan=4, sticky='W', pady=10)

#Adding Browse Button
button_browse = ttk.Button(frame, text="Browse", command=select_file)
button_browse.grid(column=3, row=0, sticky='W')

#Adding Submit / Export / Clear / Close buttons
button_submit = ttk.Button(button_frame, text='Submit', command=check_file)
button_submit.grid(column=0, row=2, sticky='W')

button_export = ttk.Button(button_frame, text='Export', command=save_result)
button_export.grid(column=1, row=2, sticky='W')

button_clear = ttk.Button(button_frame, text='Clear', command=clear_text)
button_clear.grid(column=2, row=2, sticky='W')

button_close = ttk.Button(frame, text='Close', command=root.destroy)
button_close.grid(column=3, row=2, sticky='E')

root.mainloop()