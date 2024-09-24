import customtkinter as ctk
from forms import Form1, Form2

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.title("Hoorad CyberSecurity")
        self.geometry("500x300")

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
    app = App()
    app.mainloop()
