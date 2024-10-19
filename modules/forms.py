import customtkinter as ctk
from widgets.ctk_widget import CTkMeter
from tkinter import END, filedialog
from abc import ABC, abstractmethod
import typing


class Form(ABC, ctk.CTkFrame):
    # static variables:
    curr_form_num = 0  # keep track of active Form
    frames = {}  # keep all forms here.
    sidebar = None

    @staticmethod
    def load_forms(root_window: ctk.CTk):
        """
        load all Forms and add them to the static class attribute, frames.
        """
        Form.frames = {cls.__name__: cls(root_window) for cls in Form.__subclasses__()}
        return Form.frames

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
        # if Form.frames:
        super().__init__(master=parent, width=500, **kwargs)

        self.load_widgets(parent)
        self.sidebar_widget = None  # tk widget holders. which will be grid() later by GUI class.
        # else:
        #     raise ValueError("Forms are not loaded. Load the frames using Form.load_forms() method")

    @staticmethod
    def update_indexes(form_num: int):
        # update the current form number:
        Form.curr_form_num = form_num

        # update the sidebar:
        if Form.sidebar:
            Form.sidebar.update_step(form_num)

    def get_grid_kwargs(self):
        return {'row': 1, 'column': 0, 'padx': 5, 'pady': 0, 'sticky': "nesw"}

    @staticmethod
    def jump_to_form(switch_to: str):
        # get kwargs grid parameters of the next From:
        grid_kwargs = Form.frames[switch_to].get_grid_kwargs()
        
        curr = Form.curr_form_num
        
        Form.frames["Form" + str(curr)].grid_remove()
        Form.frames[switch_to].grid(**grid_kwargs)

        Form.update_indexes(int(switch_to[4]))
    
    @staticmethod
    def next_form():        
        curr = Form.curr_form_num
        next = curr + 1
        
        curr_name = "Form" + str(curr) # "Form2"
        next_name = "Form" + str(next)
        
        # get kwargs grid parameters of the next From:
        grid_kwargs = Form.frames[next_name].get_grid_kwargs()

        if Form.curr_form_num:  # if it's not the fist time we show a Form (or if a Form has been grided before):
            Form.frames[curr_name].grid_remove()

        Form.frames[next_name].grid(**grid_kwargs)

        Form.update_indexes(next)

    @staticmethod
    def previous_form():
        curr = Form.curr_form_num
        next = curr - 1

        curr_name = "Form" + str(curr) # "Form2"
        next_name = "Form" + str(next)
        
        # get kwargs grid parameters of the next From:
        grid_kwargs = Form.frames[next_name].get_grid_kwargs()

        
        Form.frames[curr_name].grid_remove()
        Form.frames[next_name].grid(**grid_kwargs)

        Form.update_indexes(next)


    @staticmethod
    def set_sidebar(sidebar: 'Sidebar'):
        Form.sidebar = sidebar


    @abstractmethod
    def load_widgets(self, parent):
        pass

    @abstractmethod
    def set_layout(self):
        pass

    def generate_tk_wgt_for_sidebar(
            self, sidebar: ctk.CTkFrame
    ) -> typing.Tuple[ctk.CTkLabel, ctk.CTkLabel]:
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


class Sidebar(ctk.CTkFrame):
    def __init__(self, root_window: ctk.CTk, frames: typing.Dict[str, ctk.CTkFrame]):
        super().__init__(root_window, fg_color="transparent", width=200)

        self.grid(row=1, column=1, padx=(0, 50), pady=30, sticky="nse")

        self.font = root_window.font
        self.font_bold = root_window.font_bold

        self.active_num: int = 0  # keep track of active(current) From number

        # get labels and icon for each step and put them on the sidebar:
        self.sidebar_wgts = []  # store each Form sidebar widget
        for i, form in enumerate(frames.values()):
            # place each step (each Form) inside the sidebar, and get the objs:
            form.generate_tk_wgt_for_sidebar(self)
            text_label_wgt, icon_label_wgt = form.get_sidebar_widget()

            text_label_wgt.grid(row=i, column=0, pady=10, padx=(0, 20), sticky="e")
            icon_label_wgt.grid(row=i, column=1)

            self.sidebar_wgts.append(
                {
                    "text": text_label_wgt,
                    "icon": icon_label_wgt
                }
            )

        # Highlight the first step as the current step
        self.update_step(1)  # passing the first item.

    def update_step(self, form_num: int):
        # update the active index:
        form_num -= 1

        # remove the visual form previous item:
        self.sidebar_wgts[self.active_num]['text'].configure(font=self.font)
        self.sidebar_wgts[self.active_num]['icon'].configure(font=self.font)

        # add visuals to active form(label and icon tk widget in the sidebar):
        self.sidebar_wgts[form_num]['text'].configure(font=self.font_bold)
        self.sidebar_wgts[form_num]['icon'].configure(font=self.font_bold)

        self.active_num = form_num


class Form1(Form):
    step_name = "توافقنامه"
    step_icon = "📝"

    def __init__(self, parent: ctk.CTk):
        super().__init__(parent)

        self.set_layout()

    def set_layout(self):
        self.grid_rowconfigure((1, 2), weight=1)
        self.grid_rowconfigure(0, weight=100)
        self.grid_columnconfigure((0, 1), weight=1)

    def load_widgets(self, parent):
        # row 0, agreement text:
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
        )  # Sets an auto warper based on the windows width for been responsive

        guide_label.grid(row=1, column=1, pady=20, padx=10, sticky="e")

        # row 2, buttons:
        btn_ready = ctk.CTkButton(self, font=parent.font, text="موافقم", command=self.next_form)
        btn_ready.grid(row=2, column=0, pady=12, padx=15, sticky="nw")
        

class Form2(Form):
    step_name = "تنظیمات اسکن"
    step_icon = "⚙️"

    def __init__(self, parent):
        super().__init__(parent)

    
    def get_grid_kwargs(self):
        return {'row': 1, 'column': 0, 'padx': 0, 'pady': 0, 'sticky': "nse"}

    
    def set_layout(self):
        pass

    def browse_path(self):
        path = filedialog.askdirectory()
        if path:
            self.path_entry.delete(0, ctk.END)
            self.path_entry.insert(0, path)

    def load_widgets(self, parent):
        font = ('Tahoma', 12, 'normal')

        # Row 1 , 2: Radio buttons for scanning options

        row01 = ctk.CTkFrame(self, bg_color='transparent')
        row01.grid(row=0, column=3)

        scan_mode_var = ctk.StringVar(value="system")

        system_label = ctk.CTkLabel(row01, text="اسکن کل سیستم", font=font, anchor='e')
        specific_path_label = ctk.CTkLabel(row01, text="اسکن یک مسیر خاص", font=font, anchor='e')

        radio_system = ctk.CTkRadioButton(row01, text="", variable=scan_mode_var, value="system", font=font)
        radio_specific_path = ctk.CTkRadioButton(row01, text="", variable=scan_mode_var, value="path", font=font)

        radio_system.pack()
        system_label.pack(anchor='e', side='left')

        radio_specific_path.pack(side='bottom')
        # specific_path_label.grid(row=1, column=3, sticky="e", pady=10)

        # # Row 3: Path input for specific path scan
        # path_label = ctk.CTkLabel(self, text=":مسیر")
        # self.path_entry = ctk.CTkEntry(self, width=300)
        # browse_button = ctk.CTkButton(self, text="مرور", command=self.browse_path)

        # path_label.grid(row=3, column=2, sticky="e", padx=10, pady=10)
        # self.path_entry.grid(row=3, column=1, sticky="e", padx=10, pady=10)
        # browse_button.grid(row=3, column=0, sticky="e", padx=10, pady=10)

        # # Row 4: Deep scan check button
        # deep_scan_var = ctk.BooleanVar()
        # deep_scan_check = ctk.CTkCheckBox(self, text="اسکن عمیق", variable=deep_scan_var)
        # deep_scan_check.grid(row=4, column=3, sticky="e", padx=10, pady=10)

        # # Row 5: Dropdown for resource allocation
        # resource_label = ctk.CTkLabel(self, text="میزان اختصاص منابع:")
        # resource_var = ctk.StringVar(value="متوسط")
        # resource_dropdown = ctk.CTkOptionMenu(self, values=["کم", "متوسط", "زیاد"], variable=resource_var)

        # resource_label.grid(row=5, column=3, sticky="e", padx=10, pady=10)
        # resource_dropdown.grid(row=5, column=2, sticky="e", padx=10, pady=10)

        # Row 6: Navigation buttons

        next_button = ctk.CTkButton(self, font=font, text="ادامه", command=self.next_form)
        next_button.grid(row=6, column=0, pady=12)

        back_button = ctk.CTkButton(self, font=font, text="بازشگت", command=self.previous_form)
        back_button.grid(row=6, column=1, pady=12)


class Form3(Form):
    step_name = "بررسی"
    step_icon = "🔍"

    def __init__(self, parent):
        super().__init__(parent)

    def load_widgets(self, parent):
        info_lbl = ctk.CTkLabel(self, text=f"{self.__class__.__name__}")
        info_lbl.grid(row=0, column=0)

        back_button = ctk.CTkButton(self, text="بازشگت", command=self.previous_form)
        back_button.grid(row=1, column=1, pady=12, padx=10)

    def set_layout(self):
        pass


class Form4(Form):
    step_name = "نتیجه"
    step_icon = "📊"

    def __init__(self, parent):
        super().__init__(parent)

    def load_widgets(self, parent):
        info_lbl = ctk.CTkLabel(self, text=f"{self.__class__.__name__}")
        info_lbl.grid(row=0, column=0)

    def set_layout(self):
        pass


class Form5(Form):
    step_name = "درباره"
    step_icon = "ℹ "

    def __init__(self, parent):
        super().__init__(parent)

    def generate_tk_wgt_for_sidebar(self, sidebar: ctk.CTkFrame):
        sidebar_widget = super().generate_tk_wgt_for_sidebar(sidebar)
        self.add_sidebar_mouse_effect()
        return sidebar_widget

    def add_sidebar_mouse_effect(self):
        # Add hover and click effect for "درباره"
        text_tklabel, icon_tklabel = self.get_sidebar_widget()

        # for the text:
        text_tklabel.bind("<Button-1>", self.on_about_click)
        icon_tklabel.bind("<Button-1>", self.on_about_click)

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
        # print(Form.current_form_num)
        self.jump_to_form("Form5")

    def load_widgets(self, parent):
        info_lbl = ctk.CTkLabel(self, text=f"{self.__class__.__name__}")
        info_lbl.grid(row=0, column=0)

    def set_layout(self):
        pass
