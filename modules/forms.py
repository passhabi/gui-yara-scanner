import customtkinter as ctk
from widgets.ctk_widget import CTkMeter
from tkinter import END, filedialog
from abc import ABC, abstractmethod


class Form(ABC, ctk.CTkFrame):
    def __init__(self, parent: ctk.CTk, **kwargs):
        super().__init__(master=parent, width=500, **kwargs)

        self.set_layout()
        self.load_widgets(parent)

    def show_form(self, switch_to: str):
        current_form = self.__class__.__name__
        next_form = switch_to
        self.master.switch_between_forms(current_form, next_form)

    def set_layout(self):
        self.grid(row=1, column=0, padx=0, pady=0, sticky="nesw")

    @abstractmethod
    def load_widgets(self, parent):
        pass

    @abstractmethod
    def get_step_name(self):
        """This function returns the Form name.
        the name is dict{text, icon}
        """
        pass
     ## todo: addd step icon

class Form1(Form):
    def __init__(self, parent: ctk.CTk):
        super().__init__(parent)
        
    def get_step_name(self):
        return 'توافقنامه'
    
    
    def get_step_icon(self):
        return '📝'

    def set_layout(self):
        self.grid(row=1, column=0, padx=0, pady=0, sticky="nesw")
        self.grid_rowconfigure((1, 2), weight=1)
        self.grid_rowconfigure(0, weight=100)
        self.grid_columnconfigure((0, 1), weight=1)

    def load_widgets(self, parent):
        #### row 0, agreement text:
        agreement_textbox = ctk.CTkTextbox(
            master=self,
            font=self.master.font,
            corner_radius=2,
        )
        agreement_textbox.grid(row=0, column=0, columnspan=2, sticky="nsew", padx=(10, 0))
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
            font=parent.font,
            text=".برای آغاز متن توافقنامه را مطالعه نموده و روی کلید موافقم کلیک کنید",
            anchor="e",
            # wraplength=350
        )

        self.bind(
            "<Configure>", lambda x: guide_label.configure(wraplength=x.width - 100)
        )  # Sets an auto wraper based on the windows width for been responsive

        guide_label.grid(row=1, column=1, pady=20, padx=10, sticky="e")

        # row 2, buttons:
        btn_ready = ctk.CTkButton(self, text="موافقم", command=lambda: self.show_form('Form2'))
        btn_ready.grid(row=2, column=0, pady=12, padx=15, sticky="nw")


class Form2(Form):
    def __init__(self, parent):
        super().__init__(parent)

    def get_step_name(self):
        return 'تنظیمات اسکن'
    
    
    def get_step_icon(self):
        return '⚙️'

    
    def set_layout(self):
        return super().set_layout()
        
    def load_widgets(self, parent):
        next_button = ctk.CTkButton(self, text="ادامه", command=lambda: self.show_form('Form3'))
        next_button.grid(row=1, column=0, pady=12, padx=10)
        
        back_button = ctk.CTkButton(self, text="بازشگت", command=lambda: self.show_form('Form1'))
        back_button.grid(row=1, column=1, pady=12, padx=10)


class Form3(Form):
    def __init__(self, parent):
        super().__init__(parent)

    def get_step_name(self):
        return 'جستوجو و بررسی'
    
    
    def get_step_icon(self):
        return '🔍'

    
    def load_widgets(self, parent):
        back_button = ctk.CTkButton(self, text="بازشگت", command=lambda: self.show_form('Form2'))
        back_button.grid(row=1, column=1, pady=12, padx=10)




# # Define the steps with icons and labels
# steps = [
#     {"text": "توافقنامه", "icon": "📝"},
#     {"text": "تنظیمات اسکن", "icon": "⚙️"},
#     {"text": "اسکن", "icon": "🔍"},
#     {"text": "نتیجه", "icon": "📊"},
#     {"text": "درباره", "icon": "ℹ️"},
# ]