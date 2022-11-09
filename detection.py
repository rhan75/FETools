import tkinter as tk
from tkinter import ttk
from tkinter.filedialog import askopenfilename
import fireeyepy
import configparser
import os
from datetime import datetime

config = configparser.ConfigParser()
config.read('./config.ini')
api_key = config['DEFAULT']['API_Key']
conn = None

filename = None
result = None

def select_file():
    global filename
    filename = askopenfilename()
    text_file.configure(state='normal')
    text_file.delete('1.0','end')
    text_file.insert('1.0',filename)
    text_file.configure(state='disabled')

def check_file():
    global conn
    global result
    global filename
    result = None
    if filename:
        if not conn:
            #Todo: Try except to handle error
            conn = fireeyepy.Detection(key=api_key)
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
    text_result.configure(state='normal')
    text_result.delete('1.0', 'end')
    text_result.insert('1.0', result)
    text_result.configure(state='disabled')
        
def get_report(filename, conn):
    response = conn.submit_file(
        files={
            'file':('filename', open(filename, 'rb'))
        }
    )
    #label_submit_status.configure(text='Submitted: Success')
    return conn.get_report(response['report_id'])
    #return report['is_malicious']

def save_result():
    global result
    global filename
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
    text_result.configure(state='normal')
    text_result.delete('1.0', 'end')
    text_result.insert('1.0', save_status)
    text_result.configure(state='disabled')

def clear_text():
    global result
    global filename
    filename = None
    result = None
    text_file.configure(state='normal')
    text_file.delete('1.0','end')
    text_file.configure(state='disabled')
    text_result.configure(state='normal')
    text_result.delete('1.0','end')
    text_result.configure(state='disabled')
root = tk.Tk()
frame = ttk.Frame(root, padding=10)
frame.grid()
root.title('Detection on Demand')
button_frame = ttk.Frame(frame)
button_frame.grid(column=0, row=2, sticky='W')

text_file = tk.Text(frame, state='disabled', height=1)
text_file.grid(column=0, row=0, columnspan=3, sticky='W', pady=5, ipadx=2, ipady=2)
button_browse = ttk.Button(frame, text="Browse", command=select_file)
button_browse.grid(column=3, row=0, sticky='W')

text_result = tk.Text(frame, state='disabled')
text_result.grid(column=0, row=1, columnspan=4, sticky='W', pady=10)
button_submit = ttk.Button(button_frame, text='Submit', command=check_file)
button_submit.grid(column=0, row=2, sticky='W')
button_export = ttk.Button(button_frame, text='Export', command=save_result)
button_export.grid(column=1, row=2, sticky='W')
button_clear = ttk.Button(button_frame, text='Clear', command=clear_text)
button_clear.grid(column=2, row=2, sticky='W')
button_close = ttk.Button(frame, text='Close', command=root.destroy)
button_close.grid(column=3, row=2, sticky='E')

root.mainloop()