import customtkinter as ctk
from ctk_widget import CTkMeter

class Form1(ctk.CTkFrame):
    def __init__(self, app):
        super().__init__(app)
        self.master = app

        self.grid(row=1, column=0, padx=0, pady=0, sticky="esw")
        self.grid_rowconfigure((0, 1), weight=1)
        self.grid_columnconfigure((0, 1, 2), weight=1)

        welcome_label = ctk.CTkLabel(
            self,
            justify="right",
            font=app.default_font,
            text=".به سیستم بررسی امنیتی هووراد خوش‌امدید. برای آغاز بررسی روی کلید شروع کلیک کنید",
            anchor='e'
            # wraplength=350
        )

        self.bind('<Configure>', lambda x: welcome_label.configure(wraplength=x.width - 250))

        welcome_label.grid(row=0, column=2, pady=12, padx=20)

        btn_ready = ctk.CTkButton(self, text="شروع", command=self.master.show_form2)
        btn_ready.grid(row=1, column=0, pady=12, padx=10)

        btn_ready = ctk.CTkButton(self, text="انصراف", command=lambda: exit())
        btn_ready.grid(row=1, column=1, pady=12, padx=10)


class Form2(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master

        progress_wgt = CTkMeter(self, background='#282424')
        progress_wgt.grid(row=0, column=0)
        
        progress_wgt.set(20)
        
        button2 = ctk.CTkButton(self, text="Back", command=self.master.show_form1)
        button2.grid(row=1, column=0, pady=12, padx=10)
