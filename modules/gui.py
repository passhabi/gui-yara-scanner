import customtkinter as ctk
from tkinter import *
from tkinter import ttk

# from forms import * # it will loaded with importlib
from PIL import Image
import importlib
import inspect
from exceptions import DependencyError


class UserInterface(ctk.CTk):

    def __init__(self):
        super().__init__()
        # treat windows, app or root as self!

        window_size = 800, 500
        self.window_layout(window_size)

        self.frames = {}  # this is to store forms (tk frames)
        self.initialize_forms()
        self.add_sidebar()

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

        self.font = ctk.CTkFont(font)
        self.font_bold = ctk.CTkFont(font, 15, "bold")

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

    def add_sidebar(self, font=("Tahoma", 14)):

        if self.frames == {}:
            raise DependencyError(
                "The function initialize_forms should be called beforehand."
            )

        # make a sidebar frame. a place that each step will be added:
        self.sidebar = ctk.CTkFrame(self, fg_color="transparent", width=200)
        self.sidebar.grid(row=1, column=1, padx=(0, 50), pady=30, sticky="nse")

        # get labels and icon for each step and put them on the sidebar:
        step_tk_labels = []
        for i, form in enumerate(reversed(self.frames.values())):
            
            text_label, icon_label = form.set_sidebar_widget(self.sidebar)
            
            # place each step (Form) inside the sidebar:
            text_label.grid(row=i, column=0, pady=10, padx=(0, 20), sticky="e")
            icon_label.grid(row=i, column=1)
                
            step_tk_labels.append({"text_label": text_label, "icon_label": icon_label})

        # Highlight the first step as the current step
        self.update_step_label(step_tk_labels[0])

    def update_step_label(self, label):
        # Function to update the current step's label to bold
        label["text_label"].configure(font=self.font_bold, text_color="white")
        label["icon_label"].configure(font=self.font_bold, text_color="white")

        print("درباره clicked!")

    def initialize_forms(self) -> None:
        # load all forms(tk frames):
        module_forms = importlib.import_module("forms")

        # Each Form class girds.() itself; hence we initialize from last to the first Form
        #    the Form1 one will be grid() at last:
        for form_name, form_class in reversed(
            inspect.getmembers(module_forms, inspect.isclass)
        ):
            if issubclass(form_class, ctk.CTkFrame):
                if form_name != "Form":  # not the abstract class From
                    # save the Forms in frames and initialize it with root app:
                    self.frames[form_name] = form_class(self)

    def switch_between_forms(self, current_form: str, next_form: str):
        self.frames[current_form].grid_remove()
        self.frames[next_form].grid()


if __name__ == "__main__":
    ui = UserInterface()
    ui.mainloop()
