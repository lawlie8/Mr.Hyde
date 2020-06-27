#!/usr/bin/python3
import tkinter as tk
from tkinter import *
from tkinter.ttk import *
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import os
import os.path
from os import listdir
from os.path import isfile, join
#import time
import ctypes
#import threading
import hashlib
import random
import binascii
#add admin to read write C: Files
try:
    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    if is_admin():

        def initilise():
            os.system('mkdir .hydefiles')
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
            password_entry = tk.Entry(width=15,show='*')
            password_entry.place(x=600,y=82,height=42)

            encrypt_button = tk.Button(text='Encrypt',activebackground='black',highlightcolor='black',bd=1,relief='flat',height=0,width=12,fg='white',bg='#338237',command=lambda:encrypt_section(password_entry,select_files_label),master=window)
            encrypt_button.place(x=910,y=82)
            decrypt_button = tk.Button(text='Decrypt',activebackground='black',highlightcolor='black',bd=1,relief='flat',height=0,width=12,fg='white',bg='#338237',command=lambda:decrypt_section(password_entry,select_files_label),master=window)
            decrypt_button.place(x=770,y=82)
            password_label = tk.Label(text='Password',fg='#d6d6c2',bg='#333338')
            password_label.place(x=500,y=85)
            select_files_label = tk.Label(text='files not selected',fg='#d6d6c2',bg='#333338')
            select_files_label.place(x=460,y=220)
            setting_button = tk.Button(text='setting',activebackground='black',highlightcolor='black',bd=1,relief='flat',height=0,width=5,fg='white',bg='#338237',command=lambda :setting_window(check_file))#,master=window)
            setting_button.place(x=980,y=12,height=30)


        def open_files():
            from tkinter import filedialog

            global window_filename,enc_file_list,mylist,enc_file_scroll,file_to_encrypt_label
            enc_file_list = []
            window_filename =  filedialog.askopenfilenames(initialdir = "/",title = "Select file",filetypes = (("all files","*.*"),("enc files","*.enc"),("jpeg files","*.jpg")))
            enc_file_list.append(window_filename)
            file_to_encrypt_label = tk.Label(text='Files to Encrypt',justify='left',fg='#d6d6c2',bg='#333338')

            enc_file_scroll = tk.Scrollbar(window,width=16,elementborderwidth=0,highlightcolor='green',bg='green',bd=0,activebackground='green')
            mylist = Listbox(window,width='90',height='7',yscrollcommand=enc_file_scroll.set,bg='green',bd=0,fg='#d6d6c2')
            if window_filename:
                for i in window_filename:
                    mylist.insert(END,'   ' + i)
                mylist.place(x='65',y='160')
                enc_file_scroll.place(x='975',y='160',height=185)#anchor='w',fill='y',side='right',pady=50,padx=20)
                file_to_encrypt_label.place(x=70,y=125)
            enc_file_scroll.config(command=mylist.yview)
            mainloop()

        def setting_window(check_file):
            global default_password_entry,setting
            check_file = open('hyde.law','r+')
            check_file_lines = check_file.readlines()
            setting_flag = check_file_lines[0]
            if setting_flag == 'setting_window_off':
                setting = tk.Tk()
                setting.tk.call('tk', 'scaling', 2.0)
                setting.geometry("570x300")
                setting.resizable(width=False,height=False)
                setting.title('Setting')
                setting.configure(bg='#333338')
                try:
                    setting.iconbitmap('setting.ico')
                except:
                    pass
                setting_info_label = tk.Label(bg='#333338',fg='#d6d6c2',text='Mr.Hyde uses AES-256 bit Encryption algorithm \n Users be advised',master=setting)
                setting_info_label.pack()
                default_password_label = tk.Label(bg='#333338',fg='#d6d6c2',text='Default password',master=setting)
                default_password_label.pack(anchor='w',padx='10',pady='30')#place(x=30,y=80)
                default_password_entry = tk.Entry(width='15',show='*',master=setting)
                default_password_entry.place(x=140,y=80)
                default_password_warning = tk.Label(bg='white',fg='red',text='1:The use of default password is not recommended. Remember password instead. \n 2: If you decide to use default password,\n there is no need to set a password in the main window.',master=setting)
                default_password_warning.place(x=10,y=150)
                set_default_password = tk.Button(text='set password',activebackground='black',highlightcolor='black',bd=1,relief='flat',height=0,width=13,fg='white',bg='#338237',command=set_default_password_section,master=setting)#,master=window)
                set_default_password.place(x=280,y=80,height=25)
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

        def get_default_password_section(default_password_file_list):
            global default_key
            default_key = ''
            for file,sun in zip(default_password_file_list,range(0,8)):
                file_extract = open(file,'r+')
                file_extract = file_extract.readlines()
                bun= sun * 8
                default_key = default_key  + file_extract[0][bun:bun+8]
            return default_key
            #print(key)


        def set_default_password_section():
            os.system('mkdir .hydefiles')
            global default_password_file_list
            default_password_file_list = ['.hydefiles/0okq7sgzt00emuwr.law','.hydefiles/dz5a0l17zehztni8.law','.hydefiles/uv8wbbi1zylip4v6.law','.hydefiles/0pk588qx1m1m5bf2.law','.hydefiles/nzlcnrcv88rrnghh.law','.hydefiles/kcf609aheo3rksm4.law','.hydefiles/q05y5cmdos60n58s.law','.hydefiles/5kcsxvpb5srx24vz.law']
            default_password = default_password_entry.get()
            if default_password != '':
                salt_value = ''
                hex_list = ['a','b','c','d','e','f','1','2','3','4','5','6','7','8','9','0']
                for salt_char in range(0,8):
                    salt_value += random.choice(hex_list)
                    #salt_value += salt_value
                #print(salt_value)
                salt_file = open('.hydefiles/default_salt.law','w+')
                salt_file.write(salt_value)
                salt_file.close()
                default_password = str(default_password+salt_value)
                default_key = hashlib.sha256(default_password.encode('utf-8')).hexdigest()

                #print(default_key)
                #print(default_password)
                for file,sun in zip(default_password_file_list,range(0,8)):
                    seti = ''
                    for bill in range(0,65):
                        seti = random.choice(hex_list) + seti

                    #print(seti)
                    seti2 = seti
                    #for sun in range(0,8):
                    if sun == 0:
                        bun = sun * 7
                        seti = default_key[bun:bun+8] + seti2[9:65]
                        default_password_file = open(file,'w+')
                        default_password_file.write(seti)
                        default_password_file.close()
                        #print(seti)
                    else:
                        bun2 = sun * 8
                        seti = seti2[0:bun2]+ default_key[bun2:bun2+8] + seti2[bun2+9:65]
                        #print(seti)
                        default_password_file = open(file,'w+')
                        default_password_file.write(seti)
                        default_password_file.close()
                #print('setting default password')

            else:
                try:
                    import shutil
                    shutil.rmtree('.hydefiles')
                    MessageBox = ctypes.windll.user32.MessageBoxW
                    MessageBox(None, 'Blank Password Not Allowed','Error', 0)
                except:
                    pass
            check_file = open('hyde.law','w+')
            check_file.write('setting_window_off')
            check_file.close()
            setting.destroy()
            get_default_password_section(default_password_file_list)
        def encrypt_section(password_entry,select_files_label):#Encrypt Files
            try:
                default_password_file_list = ['.hydefiles/0okq7sgzt00emuwr.law','.hydefiles/dz5a0l17zehztni8.law','.hydefiles/uv8wbbi1zylip4v6.law','.hydefiles/0pk588qx1m1m5bf2.law','.hydefiles/nzlcnrcv88rrnghh.law','.hydefiles/kcf609aheo3rksm4.law','.hydefiles/q05y5cmdos60n58s.law','.hydefiles/5kcsxvpb5srx24vz.law']
                #IV = 16 * '\x00'
                #mode = AES.MODE_CBC

                password_entry_for_encryption = password_entry.get()

                def pad(s):
                    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)



                if password_entry_for_encryption == '':
                    key = get_default_password_section(default_password_file_list)
                    check_sum_key = key.lower()

                    key = binascii.unhexlify(key)
                    #print(key)
                else:
                    hex_list = ['a','b','c','d','e','f','1','2','3','4','5','6','7','8','9','0']
                    salt_value = ''
                    for salt_char in range(0,8):
                        salt_value += random.choice(hex_list)
                    password_entry_for_encryption = password_entry_for_encryption + salt_value
                    not_defalt_salt = open('.hydefiles/salt.law','a')

                    key = hashlib.sha256(password_entry_for_encryption.encode('utf-8')).digest()
                    check_sum_key = hashlib.sha256(password_entry_for_encryption.encode('utf-8')).hexdigest()
                    not_defalt_salt.write(check_sum_key[30:36]+'---'+salt_value+'\n')
                    not_defalt_salt.close()
                hex_list = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
                #print(a)
                num = check_sum_key[30:36]
                '''
                for hex_i in check_sum_key:
                    for hex_b in hex_list:
                        if hex_i == hex_b:
                            num += hex_list.index(hex_b)# * check_sum_key.index(hex_i)
                '''
                #print(str(num))
                enc_counter = 0
                progress = Progressbar(window,orient=HORIZONTAL,length=926,mode='determinate')
                progress.place(anchor='w',x=65,y=360)
                prog = 100 / len(window_filename)
                for file_to_encrypt in window_filename:
                    if file_to_encrypt.endswith('.enc'):
                        enc_counter+=1

                    else:
                        progress['value'] = prog
                        window.update_idletasks()
                        prog = prog + prog
                        fh = open(file_to_encrypt,'rb')
                        message = fh.read()
                        fh.close()
                        message = pad(message)
                        iv = Random.new().read(AES.block_size)
                        cipher = AES.new(key,AES.MODE_CBC,iv)
                        encrypted_text = iv + cipher.encrypt(message)
                        fh = open(file_to_encrypt + str(num) + '.enc','wb')
                        fh.write(encrypted_text)
                        fh.close()
                        os.remove(file_to_encrypt)
                        #print(file_to_encrypt)
                if enc_counter !=0:
                    MessageBox = ctypes.windll.user32.MessageBoxW
                    MessageBox(None, 'Already encrypted', 'Error', 0)
                mylist.delete(0,END)
                enc_file_scroll.place_forget()
                mylist.place_forget()
                progress.place_forget()
                file_to_encrypt_label.place_forget()
                password_entry.delete(0,END)
                MessageBox = ctypes.windll.user32.MessageBoxW
                MessageBox(None, 'Selected Files Encrypted','Success', 0)
                #window_filename = {}
            except:
                progress.place_forget()
                try:
                    mylist.place_forget()
                except:
                    pass
                MessageBox = ctypes.windll.user32.MessageBoxW
                MessageBox(None, 'Select Files First', 'Error', 0)
                password_entry.delete(0,END)
            finally:
                pass
        def decrypt_section(password_entry,select_files_label):#Decrypt Files
            try:
                def unpad(s):
                    return s[:-ord(s[len(s)-1:])]

                default_password_file_list = ['.hydefiles/0okq7sgzt00emuwr.law','.hydefiles/dz5a0l17zehztni8.law','.hydefiles/uv8wbbi1zylip4v6.law','.hydefiles/0pk588qx1m1m5bf2.law','.hydefiles/nzlcnrcv88rrnghh.law','.hydefiles/kcf609aheo3rksm4.law','.hydefiles/q05y5cmdos60n58s.law','.hydefiles/5kcsxvpb5srx24vz.law']
                password_entry_for_encryption = password_entry.get()
                if password_entry_for_encryption == '':
                    key = get_default_password_section(default_password_file_list)
                    check_sum_key = key.lower()
                    key = binascii.unhexlify(key)
                    #print(key)
                else:
                    not_defalt_salt = open('.hydefiles/salt.law','r+')
                    salt_lines = not_defalt_salt.readlines()
                    #salt_lines = salt_lines[0].strip(' ')
                    #print(salt_lines)
                    for check_salt_value in salt_lines:
                        for file_to_check in window_filename:
                            if str(check_salt_value[0:6]) == str(file_to_check[-10:-4]):
                                #print('here')
                                salt_lines = check_salt_value[-9:-1]
                                #print(salt_lines)

                        #print(check_salt_value)
                    #ashdkjahsdjh = input("inpput here")
                    #print(str(file_to_check[-10:-4])+'---'+check_salt_value[0:6])
                    password_entry_for_encryption2 = password_entry_for_encryption

                    password_entry_for_encryption = password_entry_for_encryption + salt_lines

                    key = hashlib.sha256(password_entry_for_encryption.encode('utf-8')).digest()
                    check_sum_key = hashlib.sha256(password_entry_for_encryption.encode('utf-8')).hexdigest()

                hex_list = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
                #print(a)
                num = str(check_sum_key[30:36]).strip(' ')
                #print(num+'---'+salt_lines)
                #asdasdasrca = input('here2')
                '''
                for hex_i in check_sum_key:
                    for hex_b in hex_list:
                        if hex_i == hex_b:
                            num += hex_list.index(hex_b)
                '''
                invalid_counter = 0
                progress = Progressbar(window,orient=HORIZONTAL,length=926,mode='determinate')
                progress.place(anchor='w',x=65,y=360)
                prog = 100 / len(window_filename)

                for file_to_decrypt in window_filename:
                    #print(str(file_to_decrypt[-10:-4]))

                    if num == str(file_to_decrypt[-10:-4]):
                        progress['value'] = prog
                        window.update_idletasks()
                        prog = prog + prog
                        fd = open(file_to_decrypt,'rb')
                        message = fd.read()
                        fd.close()
                        iv = message[:AES.block_size]
                        cipher = AES.new(key,AES.MODE_CBC,iv)
                        plaintext = cipher.decrypt(message[AES.block_size:])
                        write_message = plaintext.rstrip(b"\0")
                        remove_file = file_to_decrypt
                        file_to_decrypt = file_to_decrypt[0:-10]
                        fd = open(file_to_decrypt,'wb')
                        fd.write(write_message)
                        fd.close()
                        os.remove(remove_file)
                    else:
                        #print('key_invalid')
                        invalid_counter +=1
                        #entry1.delete(0,tk.END)

                if invalid_counter != 0 :
                    MessageBox = ctypes.windll.user32.MessageBoxW
                    MessageBox(None, 'Invalid key used for '+str(invalid_counter)+' files','Error', 0)
                    progress.place_forget()
                    password_entry.delete(0,END)
                else:
                    file_to_encrypt_label.place_forget()
                    enc_file_scroll.place_forget()
                    mylist.place_forget()
                    progress.place_forget()
                    password_entry.delete(0,END)
                    MessageBox = ctypes.windll.user32.MessageBoxW
                    MessageBox(None, 'Selected Files Decrypted','Success', 0)
            except:
                progress.place_forget()
                try:
                    mylist.place_forget()
                except:
                    pass
                MessageBox = ctypes.windll.user32.MessageBoxW
                MessageBox(None, 'Select Files First', 'Error', 0)
                password_entry.delete(0,END)
            finally:
                pass
            #window_filename = {}

            #print(window_filename)
        initilise() #initialise window
        label.after(3000,clear_label) #app_name label intro

        window.mainloop()

    else:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)

    check_file = open('hyde.law','w+')
    check_file.write('setting_window_off')
    check_file.close()
    is_admin()

except IOError as e:
    error_file = open('error.log','a+')
    error_file.write(e+'\n')
    error_file.close()
