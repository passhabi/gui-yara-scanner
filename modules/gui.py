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

        window_size = 800, 500
        self.window_layout(window_size, "Tahoma")

        self.frames = {}  # this is to store forms (tk frames)
        self.initialize_forms()

    def window_layout(self, window_size, font):
        """Config Window Appearance and layout.

        Args:
            window_size (_type_): _description_
        """

        self.geometry(f'{window_size[0]}x{window_size[1]}')  # eg."600x800"
        self.minsize(*window_size)
        self.centers_windows(window_size)

        self.title("HOORAD CyberSecurity")

        ctk.set_appearance_mode("Dark")  # default

        self.iconbitmap("./media/tiny_icon.ico")

        self.font = ctk.CTkFont(font)

        self.columnconfigure(0, weight=4)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)
        self.rowconfigure(1, weight=4)

        # HOORAD Logo:
        logo = ctk.CTkImage(
            dark_image=Image.open("./media/logo.png"), light_image=Image.open("./media/logo.png"), size=(256, 61)
        )
        logo_label = ctk.CTkLabel(
            self, image=logo, text=""
        )  # display image with a CTkLabel~~

        logo_label.grid(row=0, column=1, sticky='sne', pady=10)
        self.add_sidebar()

    def centers_windows(self, window_size):
        width, height = window_size

        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')

    def add_sidebar(self, font=('Tahoma', 12)):
        sidebar = ctk.CTkFrame(self, width=150, corner_radius=0)
        sidebar.grid(row=1, column=1, padx=0, pady=0, sticky="nesw")
        
        # Define the steps with icons and labels
        steps = [
            {"text": "توافقنامه", "icon": "📝"},
            {"text": "تنظیمات اسکن", "icon": "⚙️"},
            {"text": "اسکن", "icon": "🔍"},
            {"text": "نتیجه", "icon": "📊"},
            {"text": "درباره", "icon": "ℹ"},
        ]

        # Create labels for each step in the sidebar
        step_labels = []
        for step in steps:
            frame = ctk.CTkFrame(sidebar, fg_color="transparent")
            frame.pack(pady=5, padx=10, anchor="w", fill="x")

            text_label = ctk.CTkLabel(frame, text=step["text"], font=font)
            text_label.pack(side="left", padx=(0, 5))

            icon_label = ctk.CTkLabel(frame, text=step["icon"], font=font)
            icon_label.pack(side="right")

            # Add hover and click effect for "درباره"
            if step["text"] == "درباره":
                text_label.bind("<Button-1>", lambda e: self.on_about_click())
                text_label.bind("<Enter>", lambda e, lbl=text_label: self.on_enter(e, lbl))
                text_label.bind("<Leave>", lambda e, lbl=text_label: self.on_leave(e, lbl))

            step_labels.append({"text_label": text_label, "icon_label": icon_label})

        # Highlight the first step as the current step
        self.update_step_label(step_labels[0])
    
    def update_step_label(self, label):
        # Function to update the current step's label to bold
        # for lbl in step_labels:
        #     lbl['text_label'].configure(font=("Arial", 12, "normal"), text_color="white")
        # label['text_label'].configure(font=("Arial", 12, "bold"), text_color="white")
        print("update")

    # Function to handle the hover effect for the "درباره" step
    def on_enter(event, label):
        label.configure(font=("Arial", 12, "underline"), text_color="#00ccff")  # Underline and change color

    def on_leave(event, label):
        label.configure(font=("Arial", 12), text_color="white")  # Remove underline and restore color
    
    # Function to handle the click on the "درباره" step
    def on_about_click():
        print("درباره clicked!")
        
        
        
        
        
    def initialize_forms(self) -> None:
        # load all forms(tk frames):
        module_forms = importlib.import_module('forms')

        for form_name, form_class in inspect.getmembers(module_forms, inspect.isclass):
            if issubclass(form_class, ctk.CTkFrame):
                if form_name != "Form":
                    self.frames[form_name] = form_class(
                        self)  # it dose the first entty of frames with .grid(), idk why! but good!

    def switch_between_forms(self, current_form: str, next_form: str):
        self.frames[current_form].grid_remove()
        self.frames[next_form].grid()


if __name__ == "__main__":
    ui = UserInterface()
    ui.mainloop()
