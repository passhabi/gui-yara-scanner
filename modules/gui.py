import customtkinter as ctk
from tkinter import *
from tkinter import ttk
# from forms import * # it will loaded with importlib
from PIL import Image
import importlib
import inspect

class UserInterface(ctk.CTk):

    def __init__(self):
        super().__init__()
        # treat windows, app or root as self!
        
        window_size = 900, 670
        self.window_layout(window_size, "Tahoma")
        
        self.frames = {} # this is to store forms (tk frames)
        self.initialize_forms()

    def window_layout(self, window_size, font):
        """Config Window Appearance and layout.

        Args:
            window_size (_type_): _description_
        """
        
        self.geometry(f'{window_size[0]}x{window_size[1]}') # eg."600x800"
        self.minsize(*window_size)
        self.centers_windows(window_size)
        
        self.title("HOORAD CyberSecurity")
        
        ctk.set_appearance_mode("Dark")  # default
        
        self.iconbitmap("./media/tiny_icon.ico")
            
        self.font = ctk.CTkFont(font)

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
    
    def centers_windows(self, window_size):
        width, height = window_size
        
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')
    
    def initialize_forms(self) -> None:
        # load all forms(tk frames):
        module_forms = importlib.import_module('forms')
        
        for form_name, form_class in inspect.getmembers(module_forms, inspect.isclass):
            if issubclass(form_class, ctk.CTkFrame):
                if form_name != "Form":
                    self.frames[form_name] = form_class(self) # it dose the first entty of frames with .grid(), idk why! but good!
    
    def switch_between_forms(self, current_form:str,  next_form:str):
        self.frames[current_form].grid_remove()
        self.frames[next_form].grid()
        

if __name__ == "__main__":
    ui = UserInterface()
    ui.mainloop()
