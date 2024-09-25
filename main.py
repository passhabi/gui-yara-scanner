import customtkinter as ctk
from tkinter import *
from tkinter import ttk
from forms import Form1, Form2

class UserIterface(ctk.CTk):    
    
    def __init__(self):
        super().__init__()
        print(self.__dir__())
        
        self.title("Hoorad CyberSecurity")
        self.geometry("650x200")
        self.minsize(650, 200)
        ctk.set_appearance_mode("Dark")  # default
        self.default_font = ctk.CTkFont('Tahoma')
        
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        # Initialize forms.py
        self.form1 = Form1(self)
        self.form2 = Form2(self)

        # Show Form 1 initially
        self.show_form1()

    def show_form1(self):
        self.form2.grid_remove()
        self.form1.grid()

    def show_form2(self):
        self.form1.grid_remove()
        self.form2.grid()


if __name__ == "__main__":
    ui = UserIterface()
    ui.mainloop()
