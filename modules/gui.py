import customtkinter as ctk
from tkinter import *
from tkinter import ttk
from forms import *
from PIL import Image

class UserIterface(ctk.CTk):

    def __init__(self):
        super().__init__()
        # treat windows, app or root as self!
        
        # Window Appearance:
        window_size = 900, 670
        self.geometry(f'{window_size[0]}x{window_size[1]}') # eg."600x800"
        self.minsize(*window_size)
        self.center_window(window_size)

        
        self.title("HOORAD CyberSecurity")
        ctk.set_appearance_mode("Dark")  # default
        self.iconbitmap("./media/tiny_icon.ico")
            
        self.default_font = ctk.CTkFont("Tahoma")

        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self.rowconfigure(1, weight=5)

        # HOORAD Logo:
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
        

    def center_window(self, window_size):
        width, height = window_size
        
        print(self.winfo_width())
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')

    def show_form1(self):
        self.form2.grid_remove()
        self.form1.grid()

    def show_form2(self):
        self.form1.grid_remove()
        self.form2.grid()


if __name__ == "__main__":
    ui = UserIterface()
    ui.mainloop()
