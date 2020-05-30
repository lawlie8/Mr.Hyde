#!/usr/bin/python3
import tkinter as tk
from tkinter import *
from tkinter.ttk import *
from Crypto import Random
from Crypto.Cipher import AES
import os
import os.path
from os import listdir
from os.path import isfile, join
import time
import ctypes
import threading
def main():
    
    def initilise():
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
        global label,window
        
        window = tk.Tk() #creates window    
        window.tk.call('tk', 'scaling', 2.0)
        window.geometry("1050x380")
        window.resizable(width=False,height=False)
        window.title("Mr. Hyde")
        try:
            window.iconbitmap('hyde.ico')
        except:
            pass
        window.configure(bg='#333338')
        label = tk.Label(text = "Mr. Hyde" ,fg="#d6d6c2",bg="#333338")
        label.place(relx=.5,rely=.5,anchor="c")
        
    def clear_label():
        
        label.place_forget()
        label1 = tk.Label(text = "Encrypt Your Files with 'AES-256'" ,fg="white",bg="#333338")
        label1.pack()
        open_files_button = tk.Button(text='Select Files',activebackground='black',highlightcolor='black',bd=1,relief='flat',height=0,width=12,fg='white',bg='#338237',command=open_files,master=window)
        open_files_button.pack(anchor='nw',pady=50,padx=10,side='left')
        encrypt_button = tk.Button(text='Encrypt',activebackground='black',highlightcolor='black',bd=1,relief='flat',height=0,width=12,fg='white',bg='#338237',command=encrypt_section,master=window)
        encrypt_button.place(x=910,y=82)   
        decrypt_button = tk.Button(text='Decrypt',activebackground='black',highlightcolor='black',bd=1,relief='flat',height=0,width=12,fg='white',bg='#338237',command=decrypt_section,master=window)
        decrypt_button.place(x=770,y=82)
        password_label = tk.Label(text='Password',fg='#d6d6c2',bg='#333338')
        password_label.place(x=500,y=85)
        password_entry = tk.Entry(width=15,show='*')
        password_entry.place(x=600,y=82,height=42)
        
        setting_button = tk.Button(text='setting',activebackground='black',highlightcolor='black',bd=1,relief='flat',height=0,width=5,fg='white',bg='#338237',command=lambda :setting_window(check_file))#,master=window)
        setting_button.place(x=980,y=12,height=30)
        
    
    def open_files():
        from tkinter import filedialog
        
        global window_filename,enc_file_list
        enc_file_list = []
        window_filename =  filedialog.askopenfilenames(initialdir = "/",title = "Select file",filetypes = (("jpeg files","*.jpg"),("all files","*.*")))
        enc_file_list.append(window_filename)
        file_to_encrypt_label = tk.Label(text='Files to Encrypt',justify='left',fg='#d6d6c2',bg='#333338')
        file_to_encrypt_label.place(x=70,y=130)
        enc_file_scroll = tk.Scrollbar(window,width=16,elementborderwidth=0,highlightcolor='green',bg='green',bd=0,activebackground='green')
        enc_file_scroll.place(x='975',y='170',height=185)#anchor='w',fill='y',side='right',pady=50,padx=20)
        mylist = Listbox(window,width='90',height='7',yscrollcommand=enc_file_scroll.set,bg='green',bd=0,fg='#d6d6c2')
        for i in window_filename:
            mylist.insert(END,'   ' + i)
        mylist.place(x='65',y='170')
        enc_file_scroll.config(command=mylist.yview)
        mainloop()
    
    def setting_window(check_file):
        check_file = open('hyde.law','r+')
        check_file_lines = check_file.readlines()
        setting_flag = check_file_lines[0]
        if setting_flag == 'setting_window_off':
            setting = tk.Tk()
            setting.tk.call('tk', 'scaling', 2.0)
            setting.geometry("450x300")
            setting.resizable(width=False,height=False)
            setting.title('Setting')
            setting.configure(bg='#333338')
            try:
                setting.iconbitmap('setting.ico')
            except:
                pass
            setting_info_label = tk.Label(bg='#333338',fg='#d6d6c2',text='Mr.Hyde uses AES-256 bit Encryption algorithm \n Users be advised',master=setting)
            setting_info_label.pack()
            default_password_label = tk.Label(bg='#333338',fg='#d6d6c2',text='default password',master=setting)
            default_password_label.place(x=30,y=80)
            default_password_entry = tk.Entry(width='15',show='*',master=setting)
            default_password_entry.place(x=140,y=80)
            default_password_warning = tk.Label(bg='white',fg='red',text='The use of default password is not recommended. Remember password instead. \n 2: If you decide to use default password,\n there is no need to set a password in the main window.',master=setting)
            default_password_warning.place(x=10,y=150)
            set_default_password = tk.Button(text='set password',activebackground='black',highlightcolor='black',bd=1,relief='flat',height=0,width=10,fg='white',bg='#338237',command=set_default_password_section,master=setting)#,master=window)
            set_default_password.place(x=250,y=80,height=20)
            check_file = open('hyde.law','w+')
            check_file.write('setting_window_on')
            check_file.close()
            def on_closing(): #jugad pe jugad
                check_file = open('hyde.law','w+')
                check_file.write('setting_window_off')
                check_file.close()
                setting.destroy()
            def close_everything():
                window.destroy()
                setting.destroy()
            setting.protocol('WM_DELETE_WINDOW',on_closing)
            window.protocol('WM_DELETE_WINDOW',close_everything)

            
    def set_default_password_section():
        print('setting default password')
    def encrypt_section():#Encrypt Files
        print(window_filename)
    def decrypt_section():#Decrypt Files
        print(window_filename)
    initilise() #initialise window 
    label.after(3000,clear_label) #app_name label intro
    
    window.mainloop()

check_file = open('hyde.law','w+')
check_file.write('setting_window_off')
check_file.close()    
main()
    





    #enc = Encryptor(key)
