import customtkinter as ctk
from widgets.ctk_widget import CTkMeter
from tkinter import END, filedialog
from abc import ABC, abstractmethod
import typing


class Form(ABC, ctk.CTkFrame):
    # class attributes:
    @property
    @abstractmethod
    def step_name(self):
        """Abstract variable that must be implemented in child classes."""
        pass

    @step_name.setter
    @abstractmethod
    def step_name(self, value):
        pass

    @property
    @abstractmethod
    def step_icon(self):
        pass

    @step_icon.setter
    @abstractmethod
    def step_icon(self, value):
        pass

    def __init__(self, parent: ctk.CTk, **kwargs):
        super().__init__(master=parent, width=500, **kwargs)

        self.set_layout()
        self.load_widgets(parent)
        self.sidebar_widget = None

    def show_form(self, switch_to: str):
        current_form = self.__class__.__name__
        next_form = switch_to
        self.master.switch_between_forms(current_form, next_form)

    def set_layout(self):
        self.grid(row=1, column=0, padx=0, pady=0, sticky="nesw")

    @abstractmethod
    def load_widgets(self, parent):
        pass

    def set_sidebar_widget(self, sidebar: ctk.CTkFrame):
        if self.sidebar_widget:
            raise FileExistsError(
                f"sidebar widget for the {self.__class__.__name__} has been called before. try getting the widget by calling get_sidebar_widget()"
            )

        text_label = ctk.CTkLabel(sidebar, text=self.step_name, font=self.master.font)
        icon_label = ctk.CTkLabel(sidebar, text=self.step_icon, font=self.master.font)
        self.sidebar_widget = text_label, icon_label

        return self.get_sidebar_widget()

    def get_sidebar_widget(self) -> typing.Tuple[ctk.CTkLabel, ctk.CTkLabel]:
        if self.sidebar_widget:
            return self.sidebar_widget

        raise ValueError("sidebar_widget hasn't been set.")


class Form1(Form):
    step_name = "توافقنامه"
    step_icon = "📝"

    def __init__(self, parent: ctk.CTk):
        super().__init__(parent)

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
        agreement_textbox.grid(
            row=0, column=0, columnspan=2, sticky="nsew", padx=(10, 0)
        )
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
        btn_ready = ctk.CTkButton(
            self, text="موافقم", command=lambda: self.show_form("Form2")
        )
        btn_ready.grid(row=2, column=0, pady=12, padx=15, sticky="nw")


class Form2(Form):
    step_name = "تنظیمات اسکن"
    step_icon = "⚙️"

    def __init__(self, parent):
        super().__init__(parent)

    def set_layout(self):
        return super().set_layout()

    def load_widgets(self, parent):
        next_button = ctk.CTkButton(
            self, text="ادامه", command=lambda: self.show_form("Form3")
        )
        next_button.grid(row=1, column=0, pady=12, padx=10)

        back_button = ctk.CTkButton(
            self, text="بازشگت", command=lambda: self.show_form("Form1")
        )
        back_button.grid(row=1, column=1, pady=12, padx=10)


class Form3(Form):
    step_name = "بررسی"
    step_icon = "🔍"

    def __init__(self, parent):
        super().__init__(parent)

    def load_widgets(self, parent):
        back_button = ctk.CTkButton(
            self, text="بازشگت", command=lambda: self.show_form("Form2")
        )
        back_button.grid(row=1, column=1, pady=12, padx=10)


class Form4(Form):
    step_name = "نتیجه"
    step_icon = "📊"

    def __init__(self, parent):
        super().__init__(parent)

    def load_widgets(self, parent):
        pass


class Form5(Form):
    step_name = "درباره"
    step_icon = "ℹ "

    def __init__(self, parent):
        super().__init__(parent)

    def set_sidebar_widget(self, sidebar: ctk.CTkFrame):
        sidebar_widget = super().set_sidebar_widget(sidebar)
        self.click_effect()
        return sidebar_widget

    def click_effect(self):
        # Add hover and click effect for "درباره"
        text_tklabel, icon_tklabel = self.get_sidebar_widget()

        # for the text:
        text_tklabel.bind("<Button-1>", self.on_about_click)
        text_tklabel.bind(
            "<Enter>", lambda e, lbl=(text_tklabel, icon_tklabel): self.on_enter(e, lbl)
        )
        text_tklabel.bind(
            "<Leave>", lambda e, lbl=(text_tklabel, icon_tklabel): self.on_leave(e, lbl)
        )

        # for the icon:
        icon_tklabel.bind(
            "<Enter>", lambda e, lbl=(text_tklabel, icon_tklabel): self.on_enter(e, lbl)
        )
        icon_tklabel.bind(
            "<Leave>", lambda e, lbl=(text_tklabel, icon_tklabel): self.on_leave(e, lbl)
        )

        # Function to handle the hover effect for the "درباره" step

    def on_enter(self, event, label):
        # label[0] is text and label[1] is the icon:
        label[0].configure(text_color="#00ccff")  # Underline and change color
        label[1].configure(text_color="#00ccff")  # Underline and change color

    def on_leave(self, event, label):
        # label[0] is text and label[1] is the icon:
        label[0].configure(text_color="white")  # Remove underline and restore color
        label[1].configure(text_color="white")  # Remove underline and restore color

    # Function to handle the click on the "درباره" step
    def on_about_click(self, event):
        print("about clicked!")

    def load_widgets(self, parent):
        pass
