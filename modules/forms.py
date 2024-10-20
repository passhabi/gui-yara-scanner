import customtkinter as ctk
from ctkdlib.custom_widgets import CTkMeter
import tkinter as tk
from tkinter import END, filedialog
from abc import ABC, abstractmethod
import typing
import tkinter as tk
from datetime import datetime


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

        self.font = parent.font
        self.font_bold = parent.font_bold

        self.load_widgets(parent)
        self.sidebar_widget = (
            None  # tk widget holders. which will be grid() later by GUI class.
        )

        self.set_layout()

    @staticmethod
    def update_indexes(form_num: int):
        # update the current form number:
        Form.curr_form_num = form_num

        # update the sidebar:
        if Form.sidebar:
            Form.sidebar.update_step(form_num)

    def get_grid_kwargs(self):
        return {"row": 1, "column": 0, "padx": 5, "pady": 0, "sticky": "nesw"}

    @classmethod
    def next_form(cls):
        cls.jump_to_form(mode="+")

    @classmethod
    def previous_form(cls):
        cls.jump_to_form(mode="-")

    @staticmethod
    def jump_to_form(mode: str = "+", form_to_switch: str = None):
        """it switch to the next (+) or previous (-) Form.

        Args:
            mode (str, optional): If minus (-) has passed it goes to the previous Form if plus (+) has passed it goes to the next Form. Defaults to '+'.
            form_to_switch (str, optional):Regardless of mode, it jumps to the Form that has been passed through form_to_switch. Defaults to None
        """
        curr = Form.curr_form_num

        if mode == "+":
            next = curr + 1
        elif mode == "-":
            next = curr - 1

        if form_to_switch:
            next = int(form_to_switch[4])

        curr_name = "Form" + str(curr)  # "e.g. Form2"
        next_name = "Form" + str(next)

        # get kwargs grid parameters of the next From:
        grid_kwargs = Form.frames[next_name].get_grid_kwargs()

        if Form.curr_form_num:  # if a Form has been grid() before: remove it.
            Form.frames[curr_name].grid_remove()

        Form.frames[next_name].grid(**grid_kwargs)

        Form.update_indexes(next)

    @staticmethod
    def set_sidebar(sidebar: "Sidebar"):
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

        text_label = ctk.CTkLabel(sidebar, text=self.step_name, font=self.font)
        icon_label = ctk.CTkLabel(sidebar, text=self.step_icon, font=self.font)
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

            self.sidebar_wgts.append({"text": text_label_wgt, "icon": icon_label_wgt})

    def update_step(self, form_num: int):
        # update the active index:
        form_num -= 1

        # remove the visual form previous item:
        self.sidebar_wgts[self.active_num]["text"].configure(font=self.font)
        self.sidebar_wgts[self.active_num]["icon"].configure(font=self.font)

        # add visuals to active form(label and icon tk widget in the sidebar):
        self.sidebar_wgts[form_num]["text"].configure(font=self.font_bold)
        self.sidebar_wgts[form_num]["icon"].configure(font=self.font_bold)

        self.active_num = form_num


class Form1(Form):
    step_name = "توافقنامه"
    step_icon = "📝"

    def __init__(self, parent: ctk.CTk):
        super().__init__(parent)

    def set_layout(self):
        self.grid_rowconfigure((1, 2), weight=1)
        self.grid_rowconfigure(0, weight=100)
        self.grid_columnconfigure((0, 1), weight=1)

    def load_widgets(self, parent):
        # row 0, agreement text:
        agreement_textbox = ctk.CTkTextbox(
            master=self,
            font=self.font,
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
        btn_ready = ctk.CTkButton(
            self, font=parent.font, text="موافقم", command=self.next_form
        )
        btn_ready.grid(row=2, column=0, pady=12, padx=15, sticky="nw")


class Form2(Form):
    step_name = "تنظیمات اسکن"
    step_icon = "⚙️"

    def __init__(self, root):
        super().__init__(root)

    def set_layout(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure((0, 1, 2, 3, 4, 5), weight=1)

    def browse_path(self):
        path = filedialog.askdirectory()
        if path:
            self.path_entry.delete(0, ctk.END)
            self.path_entry.insert(0, path)

    def load_widgets(self, parent):

        # Row 1 , 2: Radio buttons for scanning options:
        scan_mode_var = ctk.StringVar(value="whole_system")
        self.row_0(scan_mode_var)
        self.row_1(scan_mode_var)

        # Row 3: Path input for specific path scan:
        self.row_2()

        # Row 4: Deep scan check button:
        deep_scan_var = ctk.BooleanVar()
        self.row_3(deep_scan_var)

        # Row 5: Dropdown for resource allocation
        self.row_4()

        # Row 6: Navigation buttons:
        self.row_5()

    def row_0(self, scan_mode_var):
        # Create a frame:
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=0, column=0, sticky="wsen")

        # Create the radio buttons with labels in Persian and place them using pack
        radio = ctk.CTkRadioButton(
            frame,
            text="",
            variable=scan_mode_var,
            value="whole_system",
            width=2,
        )

        # Align the labels to the right (Persian design)
        label = ctk.CTkLabel(frame, text="اسکن کل سیستم", anchor="e", font=self.font)

        # Use pack instead of grid
        radio.pack(side="right", padx=(0, 5), pady=(20, 0))
        label.pack(side="right", padx=(0, 5), pady=(20, 0))

    def row_1(self, scan_mode_var):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=1, column=0, sticky="wsen")

        # Create the radio buttons with labels in Persian and place them in the grid
        radio = ctk.CTkRadioButton(
            frame,
            text="",
            variable=scan_mode_var,
            value="specific_path",
            # bg_color="blue",
            width=2,
        )

        # Align the labels to the right (Persian design)
        label = ctk.CTkLabel(
            frame, text="اسکن یک پوشه یا یک مسیر خاص", anchor="e", font=self.font
        )

        radio.pack(side="right", padx=(0, 5))
        label.pack(side="right", padx=(0, 5))

    def row_2(self):
        # Row 3: Path input for specific path scan:
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=2, column=0, sticky="wsen")

        path_label = ctk.CTkLabel(
            frame, text=":مسیر", anchor="e", font=self.font, text_color="gray"
        )
        self.path_entry = ctk.CTkEntry(frame, width=300, state="disabled")
        browse_button = ctk.CTkButton(
            frame,
            text="مرور",
            command=self.browse_path,
            width=40,
            # state='disabled',
        )

        # Use pack instead of grid
        path_label.pack(side="right", padx=(0, 30), pady=10)
        self.path_entry.pack(side="right", padx=10, pady=10)
        browse_button.pack(side="right", padx=10, pady=10)

    def row_3(self, deep_scan_var):
        # Row 4: Deep scan check button:
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=3, column=0, sticky="wsen")

        checkbox = ctk.CTkCheckBox(frame, text="", variable=deep_scan_var, width=1, checkbox_height=20, checkbox_width=20)
        label = ctk.CTkLabel(frame, text="اسکن عمیق", anchor="e", font=self.font)

        checkbox.pack(side="right", pady=10)
        label.pack(side="right", padx=(0, 5), pady=10)

    def row_4(self):
        # Row 5: Dropdown for resource allocation
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=4, column=0, sticky="wsen")

        label = ctk.CTkLabel(
            frame, text=": میزان اختصاص منابع به برنامه", anchor="e", font=self.font
        )
        resource_var = ctk.StringVar(value="متوسط")
        dropdown = ctk.CTkOptionMenu(
            frame,
            anchor="e",
            dropdown_font=self.font,
            font=self.font,
            values=["کم", "متوسط", "زیاد"],
            variable=resource_var,
        )

        label.pack(side="right", padx=(0, 5), pady=10)
        dropdown.pack(side="right", padx=(0, 5), pady=10)

    def row_5(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=5, column=0, sticky="wsen")

        # Row 6: Navigation buttons
        next_button = ctk.CTkButton(
            frame, font=self.font, text="شروع اسکن", command=self.next_form
        )

        back_button = ctk.CTkButton(
            frame, font=self.font, text="بازگشت", command=self.previous_form, width=80
        )

        next_button.pack(side="left", pady=10, padx=5)
        back_button.pack(side="left", pady=12, padx=5)


class Form3(Form):
    step_name = "بررسی"
    step_icon = "🔍"

    def __init__(self, parent):
        self.padx = 5
        self.pady = 5
        self.padx_staring_line = (5, 15)
        self.padx_staring_line_ltr = (15, 5)

        super().__init__(parent)

    def set_layout(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure((0, 1, 2, 3, 4), weight=1)

    def load_widgets(self, parent):
        # overal info + progressbar:
        # checkbox:
        deep_scan_var = ctk.BooleanVar()
        is_show_files = ctk.BooleanVar()
        self.row_0(is_show_files, deep_scan_var)

        # scan info:
        self.row_1()


        # self.row_2(deep_scan_var)

        # filelist vs resoures TkMeter:
        # self.row_3_yara_output()

        self.row_3_visual_sysinfo()

        # self.row_3(deep_scan_var)

        # buttons:
        self.row_4()


    def row_0(self, is_show_files, deep_scan_var):
        # general info
        frame = ctk.CTkFrame(
            self,
            #  height=10
        )
        frame.grid(row=0, column=0, sticky="wsen")

        frame.columnconfigure(0, weight=10)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure((0, 1, 2, 3), weight=1)

        # defining labels:
        label_scanning = ctk.CTkLabel(
            frame, text=":در حال اسکن", anchor="e", font=self.font
        )
        label_status = ctk.CTkLabel(frame, text=":وضعیت", anchor="e", font=self.font)

        # defining values:
        label_scanning_value = ctk.CTkLabel(
            frame, text="D:/", anchor="w", font=self.font_bold
        )
        label_status_value = ctk.CTkLabel(
            frame, text="D:/stepu/makeithappen/afile.txt", anchor="w", font=self.font
        )

        # placing labels:
        label_scanning.grid(
            row=0, column=1, sticky="e", padx=self.padx_staring_line,
        )
        label_status.grid(
            row=1, column=1, sticky="e", padx=self.padx_staring_line,
        )

        # placing values:
        label_scanning_value.grid(row=0, column=0, sticky="e", padx=self.padx)
        label_status_value.grid(row=1, column=0, sticky="e", padx=self.padx)

        # progressbar:
        progressbar_frame = ctk.CTkFrame(frame, fg_color="transparent")
        progressbar_frame.grid(row=2, column=0, columnspan=2, sticky="wsen", pady=self.pady)

        progressbar = ctk.CTkProgressBar(progressbar_frame, orientation="horizontal")
        label_precent = ctk.CTkLabel(progressbar_frame, text=f"{30}%")

        # put label and progress bar in the middle and add same padding to both side (left and right):
        progressbar_frame.columnconfigure((1), weight=7)
        progressbar_frame.columnconfigure((2, 3), weight=1)
        progressbar_frame.columnconfigure(0, weight=2)
        progressbar_frame.rowconfigure(0, weight=1)

        progressbar.grid(row=0, column=1, sticky="we", padx=self.padx)
        label_precent.grid(row=0, column=2, sticky="w", padx=self.padx)
        
        # checkbox (toggle yara ouputs):
        
        checkbox_frame = ctk.CTkFrame(frame, fg_color="transparent")
        checkbox_frame.grid(row=3, column=0, columnspan=2, sticky="wsen")
        
        checkbox = ctk.CTkCheckBox(
            checkbox_frame,
            text="",
            variable=deep_scan_var,
            width=0,
            checkbox_width=20,
            checkbox_height=20,
        )
        label = ctk.CTkLabel(checkbox_frame, text="نمایش فایل‌ها", anchor="e", font=self.font)

        checkbox.pack(side="right", padx=self.padx_staring_line, pady=self.pady)
        label.pack(side="right", padx=self.padx, pady=self.pady)

    def row_1(self):
        # scan info:
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=1, column=0, sticky="wsen")

        frame.columnconfigure((0, 2), weight=1)
        frame.columnconfigure((1, 3), weight=1)
        frame.rowconfigure((0, 1), weight=1)

        # defining labels:
        label_start_time = ctk.CTkLabel(
            frame, text=":زمان شروع", anchor="e", font=self.font
        )
        label_duration = ctk.CTkLabel(
            frame, text=":زمان سپری شده", anchor="e", font=self.font
        )
        label_num_scaned = ctk.CTkLabel(
            frame, text=":فایل‌های اسکن شده", anchor="e", font=self.font
        )
        label_threats_found = ctk.CTkLabel(
            frame, text=":تهدیدهای شناسایی شده", anchor="e", font=self.font
        )

        # defining values:
        label_start_time_value = ctk.CTkLabel(
            frame,
            text=f"{datetime.now().strftime("%H:%M:%S")}",
            anchor="w",
            font=self.font_bold,
        )
        label_duration_value = ctk.CTkLabel(
            frame, text="00:27:13", anchor="w", font=self.font
        )
        label_num_scaned_value = ctk.CTkLabel(
            frame, text="241", anchor="w", font=self.font
        )
        label_threats_found_value = ctk.CTkLabel(
            frame, text="5", anchor="w", font=self.font, text_color="red"
        )

        # placing labels:
        label_start_time.grid(
            row=0, column=3, sticky="e", padx=self.padx_staring_line, pady=self.pady
        )
        label_duration.grid(
            row=1, column=3, sticky="e", padx=self.padx_staring_line, pady=self.pady
        )
        label_num_scaned.grid(
            row=0, column=1, sticky="e", padx=self.padx_staring_line, pady=self.pady
        )
        label_threats_found.grid(
            row=1, column=1, sticky="e", padx=self.padx_staring_line, pady=self.pady
        )

        # placing values:
        label_start_time_value.grid(row=0, column=2, padx=self.padx)
        label_duration_value.grid(row=1, column=2, padx=self.padx)
        label_num_scaned_value.grid(row=0, column=0, padx=self.padx)
        label_threats_found_value.grid(row=1, column=0, padx=self.padx)

    def row_2(self, deep_scan_var):
        # checkbox, Is it a deep scan?
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=2, column=0, sticky="wsen")

    def row_3_yara_output(self):
        # textbox for yara ouput:
        textbox_yara_output = ctk.CTkTextbox(self)
        textbox_yara_output.grid(row=3, column=0, sticky="wsen", padx=self.padx)
        textbox_yara_output.insert("0.0", "Some example text!\n" * 50)

    def row_3_visual_sysinfo(self):
        # cpu vs ram vs disk visual info:
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=3, column=0, sticky="wsen")

        frame.columnconfigure((0, 1, 2, 3, 4), weight=1)
        frame.rowconfigure((0, 1), weight=1)
        # cpu:
        cpu_meter = CTkMeter(frame, background='transparent', size=70, value=80,)
        cpu_meter.grid(row=0, column=1, sticky='wesn')
        cpu_meter.textvariable.set('80%')  # To set the text
        
        # ram:
        ram_meter = CTkMeter(frame, background='transparent', size=70, value=20)
        ram_meter.grid(row=0, column=2, sticky='nswe')
        ram_meter.textvariable.set('20%')  # To set the text

        # disk:
        disk_meter = CTkMeter(frame, background='transparent', size=70, value=10)
        disk_meter.grid(row=0, column=3, sticky='nswe')
        disk_meter.textvariable.set('10%')  # To set the text
        
        # set labels:
        cpu_meter_label = ctk.CTkLabel(frame, text="CPU")
        ram_meter_label = ctk.CTkLabel(frame, text="RAM")
        disk_meter_label = ctk.CTkLabel(frame, text="DISK")
        
        # place the labels:
        cpu_meter_label.grid(row=1, column=1, sticky='wesn')
        ram_meter_label.grid(row=1, column=2, sticky='nswe')
        disk_meter_label.grid(row=1, column=3, sticky='nswe')

        
    def row_4(self):
        # buttons:
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=4, column=0, sticky="wsen")
        
        next_button = ctk.CTkButton(frame, font=self.font, text="ادامه", command=self.next_form, width=90, hover_color='#36b98f')
        pause_button = ctk.CTkButton(frame, font=self.font, text="مکث", hover_color='orange', width=10)

        back_button = ctk.CTkButton(
            frame, font=self.font, text="انصراف", command=self.previous_form,
            hover_color='red',
            width=10
        )

        next_button.pack(side="left", padx=self.padx, pady=self.pady)
        pause_button.pack(side="left", padx=self.padx, pady=self.pady)
        back_button.pack(side="left", padx=self.padx, pady=self.pady)


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
        self.jump_to_form(form_to_switch="Form5")

    def load_widgets(self, parent):
        info_lbl = ctk.CTkLabel(self, text=f"{self.__class__.__name__}")
        info_lbl.grid(row=0, column=0)

    def set_layout(self):
        pass
