import customtkinter as ctk


class Form1(ctk.CTkFrame):
    def __init__(self, app):
        super().__init__(app)
        self.master = app
        self.grid(padx=0, pady=0, sticky='nsew')
        self.grid_rowconfigure((0,1), weight=1)
        self.grid_columnconfigure((0,1,2), weight=1)
        
        print(app)
        print(app)
        
        self.welcome_label = ctk.CTkLabel(self,
                                          font=app.default_font,
                                          text="به سیستم بررسی امنیتی هووراد خوش‌امدید. برای آغاز بررسی روی کلید شروع کلیک کنید.")
        self.welcome_label.grid(row=0, column=2, pady=12, padx=10)

        self.btn_ready = ctk.CTkButton(self, text="شروع", command=self.master.show_form2)
        self.btn_ready.grid(row=1, column=0, pady=12, padx=10)
        
        self.btn_ready = ctk.CTkButton(self, text="انصراف", command=lambda: exit())
        self.btn_ready.grid(row=1, column=1, pady=12, padx=10)


class Form2(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master

        self.label = ctk.CTkLabel(self, text="This is Form 2")
        self.label.grid(row=0, column=0, pady=12, padx=10)

        self.button2 = ctk.CTkButton(self, text="Back", command=self.master.show_form1)
        self.button2.grid(row=1, column=0, pady=12, padx=10)
