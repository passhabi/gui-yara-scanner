import customtkinter as ctk


class Form1(ctk.CTkFrame):
    def __init__(self, app):
        super().__init__(app)
        self.master = app

        self.label = ctk.CTkLabel(self, text="This is Form 1")
        self.label.grid(row=0, column=0, pady=12, padx=10)

        self.button1 = ctk.CTkButton(self, text="Go to Form 2", command=self.master.show_form2)
        self.button1.grid(row=1, column=0, pady=12, padx=10)


class Form2(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master

        self.label = ctk.CTkLabel(self, text="This is Form 2")
        self.label.grid(row=0, column=0, pady=12, padx=10)

        self.button2 = ctk.CTkButton(self, text="Back", command=self.master.show_form1)
        self.button2.grid(row=1, column=0, pady=12, padx=10)
