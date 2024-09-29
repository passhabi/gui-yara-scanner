import customtkinter as ctk
from tkinter import *
from tkinter import ttk
from forms import Form1, Form2
from PIL import Image


class UserIterface(ctk.CTk):

    def __init__(self):
        super().__init__()

        # treat windows, app or root as self!
        
        window_size = 400, 500
        self.geometry(f'{window_size[0]}x{window_size[1]}') # eg."600x800"
        self.minsize(*window_size)
        
        self.title("HOORAD CyberSecurity")
        ctk.set_appearance_mode("system")  # default
        self.iconbitmap("./media/tiny_icon.ico")
            
        self.default_font = ctk.CTkFont("Tahoma")

        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self.rowconfigure(1, weight=5)

        # HOORAD image:
        logo = ctk.CTkImage(
            dark_image=Image.open("./media/logo.png"), light_image=Image.open("./media/logo.png"), size=(256, 61)
        )
        logo_label = ctk.CTkLabel(
            self, image=logo, text=""
        )  # display image with a CTkLabel
        
        logo_label.grid(row=0, column=0, sticky='sn', pady=10)


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
