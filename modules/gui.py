import customtkinter as ctk
import tkinter as tk
from PIL import Image
from forms import * # Form, Sidebar
from concurrently import RunWithSysCheck
from scanner import YaraScanner
from pathlib import Path
import os

class UserInterface(ctk.CTk):

    def __init__(self, run_with_syscheck: RunWithSysCheck):
        super().__init__()
        # treat windows, app or root as self!

        window_size = 800, 500
        font = 'Tahoma'

        self.font = ctk.CTkFont(font, size=13)
        self.font_bold = ctk.CTkFont(font, 14, "bold")

        self.window_layout(window_size)
        
        # set run_with_syscheck:
        Form.set_run_with_syscheck(run_with_syscheck)
        
        # loads all forms:
        frames = Form.load_forms(self)  # store forms (tk frames)
        
        # Add sidebar to root window:
        sidebar = Sidebar(self, frames)
        Form.set_sidebar(sidebar)
        
        Form.next_form()  # show the Form1
        Form.jump_to_form(form_to_switch='Form1')
        
    def window_layout(self, window_size, font="Tahoma"):
        """Config Window Appearance and layout.

        Args:
            window_size (_type_): _description_
        """

        self.geometry(f"{window_size[0]}x{window_size[1]}")  # eg."600x800"
        self.minsize(*window_size)
        self.centers_windows(window_size)

        self.title("HOORAD CyberSecurity")

        ctk.set_appearance_mode("Dark")  # default

        self.iconbitmap("./media/tiny_icon.ico")

        self.columnconfigure(0, weight=20)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)
        self.rowconfigure(1, weight=20)

        # HOORAD Logo:
        logo = ctk.CTkImage(
            dark_image=Image.open("./media/logo.png"),
            light_image=Image.open("./media/logo.png"),
            size=(256, 61),
        )
        logo_label = ctk.CTkLabel(
            self, image=logo, text=""
        )  # display image with a CTkLabel

        logo_label.grid(row=0, column=1, sticky="snew", pady=10)

    def centers_windows(self, window_size):
        width, height = window_size

        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")


if __name__ == "__main__":
    
    directory = Path("C:/Program Files/Git")
    rule_path = Path("./rules.yar")

    scanner = YaraScanner(directory, rule_path, console_print=False)
    # scanner.start()

    run_with_syscheck = RunWithSysCheck(scanner, os.getpid())
    # run_with_syscheck.start_task()
    
    ui = UserInterface(run_with_syscheck)
    ui.mainloop()
    