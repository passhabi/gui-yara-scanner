import customtkinter as ctk
from widgets.ctk_widget import CTkMeter
from tkinter import Text, END, RIGHT


class Form1(ctk.CTkFrame):
    def __init__(self, app):
        super().__init__(app)
        self.master = app

        self.grid(row=1, column=0, padx=0, pady=0, sticky="nesw")
        self.grid_rowconfigure((1, 2), weight=1)
        self.grid_rowconfigure(0, weight=100)
        self.grid_columnconfigure((0, 1), weight=1)

        #### row 0, agreement text:

        agreement_textbox = ctk.CTkTextbox(
            master=self,
            font=self.master.default_font,
            corner_radius=2,
        )
        agreement_textbox.grid(row=0, column=0, columnspan=2, sticky="nsew")
        agreement_textbox.tag_config("rtl", justify="right")

        # use FixTxt to insert the rtl text, https://fixtxt.co/
        agreement_textbox.insert(
            END,
            """
            ‫البته! در اینجا یک متن نمونه به زبان فارسی برای شما آورده‌ام:‬
‫در یک روستای آرام که بین تپه‌های سرسبز قرار داشت، یک کتابخانه کوچک وجود داشت که اسرار جهان را در خود جای داده بود. کتابدار، زنی مسن با چشمانی پر از درخشش، هر کتاب را از بر می‌دانست. او اغلب داستان‌هایی را با کودکان بازدیدکننده به اشتراک می‌گذاشت و قصه‌های ماجراجویی و رمز و راز را می‌بافت که تخیل آن‌ها را مجذوب می‌کرد.‬
‫روزی، پسری جوان به نام امیر یک کتاب قدیمی و پر از گرد و غبار را در گوشه‌ای از کتابخانه کشف کرد. وقتی آن را باز کرد، صفحات با نوری جادویی درخشیدند. کتاب داستان گنجی پنهان را روایت می‌کرد که قرن‌ها گم شده بود و منتظر کسی بود که به اندازه کافی شجاع باشد تا آن را جستجو کند. امیر با الهام از این داستان، سفری را آغاز کرد که زندگی‌اش را برای همیشه تغییر داد.‬
‫امیدوارم این متن برای شما مفید باشد! اگر موضوع یا سبک خاصی مد نظر دارید، لطفاً بگویید تا متن را بر اساس آن تنظیم کنم.‬
            """
            * 3,
            tags="rtl",
        )

        # row 1, guiding label:
        guide_label = ctk.CTkLabel(
            self,
            justify="right",
            font=app.default_font,
            text=".برای آغاز متن توافقنامه را مطالعه نموده و روی کلید موافقم کلیک کنید",
            anchor="e",
            # wraplength=350
        )

        self.bind(
            "<Configure>", lambda x: guide_label.configure(wraplength=x.width - 100)
        )  # Sets an auto wraper based on the windows width for been responsive

        guide_label.grid(row=1, column=1, pady=20, padx=10, sticky="e")

        # row 2, buttons:
        btn_ready = ctk.CTkButton(self, text="موافقم", command=self.master.show_form2)
        btn_ready.grid(row=2, column=0, pady=12, padx=15, sticky="nw")


class Form2(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master

        progress_wgt = CTkMeter(self, background="#242424")
        progress_wgt.grid(row=0, column=0)

        progress_wgt.set(20)

        button2 = ctk.CTkButton(self, text="Back", command=self.master.show_form1)
        button2.grid(row=1, column=0, pady=12, padx=10)
