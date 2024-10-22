from functools import WRAPPER_UPDATES
import customtkinter as ctk
from ctkdlib.custom_widgets import CTkMeter
import tkinter as tk
from tkinter import END, filedialog
from abc import ABC, abstractmethod
import typing
import tkinter as tk
from datetime import datetime
from functools import wraps
import inspect


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

    def annotate_rows(self, row: int, fg_color: str = "transparent", *args, **kwargs):
        """
        Args:
            row (int): row number to place it in the Form.
            fg_color (str, optional): fg_color tkinter color; sets for background of frame. Defaults to "transparent".
        """
        # this function just make sure we have correct parameter signature for defining each row.
        pass

    def frame_decorator(func):
        
        # check if the function that uses the frame_decorator has arg named 'frame':
        sig = inspect.signature(func)
        if 'frame' not in sig.parameters:
            raise ValueError(f"The function {func.__name__} must have an argument named 'frame'.")
    
        
        def inner_func(self, row: int, fg_color: str = "transparent", *args, **kwargs):
            try:
                if fg_color:
                    frame = ctk.CTkFrame(self, fg_color=fg_color)
                    frame.grid(row=row, column=0, sticky="wsen", pady=10)
                else:
                    frame = ctk.CTkFrame(self, corner_radius=0)
                    frame.grid(row=row, column=0, sticky="wsen")
                return func(self, frame, *args, **kwargs)
                
            except ValueError and tk.TclError  as e:
                # takes all inner_func parameters instead of 'self', 'args' and 'kwargs':
                inner_func_signature = list(inspect.signature(inner_func).parameters)[1:-2]
                # takes all func parameters except 'self' and 'frame':
                func_signature = list(inspect.signature(func).parameters)[2:]
                
                # making sure we dont lost track of errors with our decorator:
                #   tangle the inner_func_signature and func_signature together to make an overall custom message:
                custom_msg = f"The {func.__name__} function"
                if inner_func_signature: # add positional arguments to the message:
                    custom_msg += f" it takes {len(inner_func_signature)} positional arguments: " + ", ".join(inner_func_signature)
                    
                if inner_func_signature and func_signature: # add and &
                    custom_msg += " and"
                    
                if func_signature: # add keywords arguments to message:
                    custom_msg += f" it takes {len(func_signature)} keywords arguments: " + " , ".join(func_signature)
                    
                    
                # Add your custom message using to inner_func_signature and func_signature and add that to the original error message:
                raise ValueError(f"{custom_msg}\n{str(e)}")

        return inner_func

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
    def set_layout(self: ctk.CTkFrame):
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

    # other methods:
    def browse_path(self):
        path = filedialog.askdirectory()
        if path:
            self.path_entry.delete(0, ctk.END)
            self.path_entry.insert(0, path)


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
        self.padx = 5
        self.pady = 5
        self.padx_staring_line = (5, 15)
        self.padx_staring_line_ltr = (15, 5)

        super().__init__(root)

    def set_layout(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(list(range(5)), weight=1)

    def load_widgets(self, parent):

        # Row 1 , 2: Radio buttons for scanning options:
        scan_mode_var = ctk.StringVar(value="whole_system")
        self.row_radio_whole_system(0, scan_mode_var=scan_mode_var)

        self.row_radio_specific_path(1, scan_mode_var=scan_mode_var)

        # Row 4: Deep scan check button:
        deep_scan_var = ctk.BooleanVar()
        self.row_3(deep_scan_var)

        # Row 5: Dropdown for resource allocation
        self.row_4()

        # Row 6: Navigation buttons:
        self.row_5()

    @wraps(Form.annotate_rows)
    @Form.frame_decorator
    def row_radio_whole_system(self, frame, scan_mode_var):
        # Create the radio buttons with labels in Persian and place them using pack
        radio = ctk.CTkRadioButton(
            frame,
            text="",
            variable=scan_mode_var,
            value="whole_system",
            width=2,
        )

        # Align the labels to the right (Persian design)
        label = ctk.CTkLabel(frame, text="اسکن کل سیستم", anchor="e", font=self.font) #bug:!!!!!!

        # Use pack instead of grid
        radio.pack(side="right", padx=(0, 5), pady=(20, 0))
        label.pack(side="right", padx=(0, 5), pady=(20, 0))

    @wraps(Form.annotate_rows)
    @Form.frame_decorator
    def row_radio_specific_path(self, frame, scan_mode_var):

        frame.columnconfigure(0, weight=1)
        frame.rowconfigure((0, 1), weight=1)

        # Create the radio buttons with labels:
        row_01_frame = ctk.CTkFrame(frame, bg_color="transparent")
        row_01_frame.grid(
            row=0,
            column=0,
            sticky="swen",
            padx=self.padx_staring_line,
            pady=(0, self.pady),
        )

        radio = ctk.CTkRadioButton(
            row_01_frame,
            text="",
            variable=scan_mode_var,
            value="specific_path",
            width=2,
        )
        radio.pack(side="right")

        label = ctk.CTkLabel(
            row_01_frame, text="اسکن یک پوشه یا یک مسیر خاص", anchor="e", font=self.font
        )
        label.pack(side="right", padx=self.padx)

        # label مسیر:
        row_02_frame = ctk.CTkFrame(frame, bg_color="transparent")
        row_02_frame.grid(
            row=1,
            column=0,
            sticky="snwe",
            padx=self.padx_staring_line,
            pady=(0, self.pady),
        )
        row_02_frame.rowconfigure(0, weight=1)
        row_02_frame.columnconfigure(0, weight=1)
        row_02_frame.columnconfigure(1, weight=8)
        row_02_frame.columnconfigure(2, weight=1)

        path_label = ctk.CTkLabel(
            row_02_frame, text=":مسیر", anchor="e", font=self.font, text_color="grey"
        )
        path_label.grid(row=0, column=2, sticky="w", padx=self.padx, pady=self.pady)

        #   path textbox:
        self.path_entry = ctk.CTkEntry(row_02_frame, state="disabled")
        self.path_entry.grid(
            row=0, column=1, sticky="we", padx=self.padx, pady=self.pady
        )

        #   browse button:
        browse_button = ctk.CTkButton(
            row_02_frame,
            text="مرور",
            command=self.browse_path,
            width=40,
        )
        browse_button.grid(row=0, column=0, sticky="e", padx=self.padx, pady=self.pady)

    def row_3(self, deep_scan_var):
        # Row 4: Deep scan check button:
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=3, column=0, sticky="wsen")

        checkbox = ctk.CTkCheckBox(
            frame,
            text="",
            variable=deep_scan_var,
            width=1,
            checkbox_height=20,
            checkbox_width=20,
        )
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
        self.rowconfigure(list(range(5)), weight=1)

    def load_widgets(self, parent):
        self.row_overalinfo(0, None)
        self.row_checkbox(1, None, ctk.BooleanVar())
        self.row_progressbar(2)
        # should replace the following two rows to have enough space for row_yara_output!:
        self.row_scan_info(3)
        self.row_visual_sysinfo(4)

        # self.row_yara_output(4)
        self.row_nav_buttons(5)

    @wraps(Form.annotate_rows)
    @Form.frame_decorator
    def row_overalinfo(self, frame):
        frame.columnconfigure(0, weight=10)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure((0, 1), weight=1)

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
            row=0,
            column=1,
            sticky="e",
            padx=self.padx_staring_line,
        )
        label_status.grid(
            row=1,
            column=1,
            sticky="e",
            padx=self.padx_staring_line,
        )

        # placing values:
        label_scanning_value.grid(row=0, column=0, sticky="e", padx=self.padx)
        label_status_value.grid(row=1, column=0, sticky="e", padx=self.padx)

    @wraps(Form.annotate_rows)
    @Form.frame_decorator
    def row_progressbar(self, frame):
        progressbar = ctk.CTkProgressBar(frame, orientation="horizontal")
        label_precent = ctk.CTkLabel(frame, text=f"{30}%")

        # put label and progress bar in the middle and add same padding to both side (left and right):
        frame.columnconfigure((1), weight=7)
        frame.columnconfigure((2, 3), weight=1)
        frame.columnconfigure(0, weight=2)
        frame.rowconfigure(0, weight=1)

        progressbar.grid(row=0, column=1, sticky="we", padx=self.padx)
        label_precent.grid(row=0, column=2, sticky="w", padx=self.padx)

    @wraps(Form.annotate_rows)
    @Form.frame_decorator
    def row_checkbox(self, frame, is_show_file=None):
        checkbox = ctk.CTkCheckBox(
            frame,
            text="",
            variable=is_show_file,
            width=0,
            checkbox_width=20,
            checkbox_height=20,
        )
        label = ctk.CTkLabel(frame, text="نمایش فایل‌ها", anchor="e", font=self.font)

        label.pack(side="left", padx=self.padx_staring_line_ltr, pady=self.pady)
        checkbox.pack(side="left", padx=self.padx_staring_line, pady=self.pady)

    @wraps(Form.annotate_rows)
    @Form.frame_decorator
    def row_scan_info(self, frame):
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

    @wraps(Form.annotate_rows)
    @Form.frame_decorator
    def row_yara_output(self, frame):
        # textbox for yara ouput:
        textbox_yara_output = ctk.CTkTextbox(frame)
        textbox_yara_output.pack(padx=self.padx, fill="both", expand=True)
        textbox_yara_output.insert("0.0", "Some example text!\n" * 50)

    @wraps(Form.annotate_rows)
    @Form.frame_decorator
    def row_visual_sysinfo(self, frame):
        # cpu vs ram vs disk visual info:
        frame.columnconfigure((0, 1, 2, 3, 4), weight=1)
        frame.rowconfigure((0, 1), weight=1)
        # cpu:
        cpu_meter = CTkMeter(
            frame,
            background="transparent",
            size=70,
            value=80,
        )
        cpu_meter.grid(row=0, column=1, sticky="wesn")
        cpu_meter.textvariable.set("80%")  # To set the text

        # ram:
        ram_meter = CTkMeter(frame, background="transparent", size=70, value=20)
        ram_meter.grid(row=0, column=2, sticky="nswe")
        ram_meter.textvariable.set("20%")  # To set the text

        # disk:
        disk_meter = CTkMeter(frame, background="transparent", size=70, value=10)
        disk_meter.grid(row=0, column=3, sticky="nswe")
        disk_meter.textvariable.set("10%")  # To set the text

        # set labels:
        cpu_meter_label = ctk.CTkLabel(frame, text="CPU")
        ram_meter_label = ctk.CTkLabel(frame, text="RAM")
        disk_meter_label = ctk.CTkLabel(frame, text="DISK")

        # place the labels:
        cpu_meter_label.grid(row=1, column=1, sticky="wesn")
        ram_meter_label.grid(row=1, column=2, sticky="nswe")
        disk_meter_label.grid(row=1, column=3, sticky="nswe")

    @wraps(Form.annotate_rows)
    @Form.frame_decorator
    def row_nav_buttons(self, frame):
        # buttons_height = 35

        next_button = ctk.CTkButton(
            frame,
            font=self.font,
            text="ادامه",
            command=self.next_form,
            width=90,
            # height=buttons_height,
            hover_color="#36b98f",
        )
        pause_button = ctk.CTkButton(
            frame,
            font=self.font,
            text="مکث",
            hover_color="orange",
            width=10,
            # height=buttons_height,
        )
        back_button = ctk.CTkButton(
            frame,
            font=self.font,
            text="انصراف",
            command=self.previous_form,
            hover_color="red",
            width=10,
            # height=buttons_height,
        )

        next_button.pack(side="left", padx=self.padx, pady=self.pady)
        pause_button.pack(side="left", padx=self.padx, pady=self.pady)
        back_button.pack(side="left", padx=self.padx, pady=self.pady)


class Form4(Form):
    step_name = "نتیجه"
    step_icon = "📊"

    def __init__(self, parent):
        self.padx = 5
        self.pady = 5
        self.padx_staring_line = (5, 15)
        self.padx_staring_line_ltr = (15, 5)
        super().__init__(parent)

    def set_layout(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(list(range(3)), weight=1)

    def load_widgets(self, parent):
        self.row_result_summary(0, None)
        self.row_list_of_files(1)
        self.row_save_outputs(2)
        self.row_nav_buttons(3)

    @wraps(Form.annotate_rows)
    @Form.frame_decorator
    def row_result_summary(self, frame):

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

    @wraps(Form.annotate_rows)
    @Form.frame_decorator
    def row_list_of_files(self, frame):
        # textbox for yara ouput:
        text_box = ctk.CTkTextbox(frame)
        text_box.pack(padx=self.padx, expand=True, fill="both")
        text_box.insert(
            "0.0",
            "/sys/genuine_above_despite.pkg\n/sbin/but_victim.war\n/usr/libexec/next_irritably.abw"
            * 10,
        )

    @wraps(Form.annotate_rows)
    @Form.frame_decorator
    def row_save_outputs(self, frame: ctk.CTkFrame):
        root_frame = frame
        root_frame.rowconfigure((0, 1), weight=1)
        root_frame.columnconfigure(0, weight=1)

        # label decription:
        frame_row_0 = ctk.CTkFrame(root_frame, bg_color="transparent")
        frame_row_0.grid(row=0, column=0, sticky="ewsn", padx=self.padx, pady=self.pady)

        description_label = ctk.CTkLabel(
            frame_row_0,
            text=":یک مسیر برای ذخیره تهدیدهای شناسایی شده تعیین کنید",
            anchor="e",
            font=self.font,
        )
        description_label.pack(
            side="right", padx=self.padx_staring_line, pady=self.pady
        )

        # label مسیر:
        frame_row_1 = ctk.CTkFrame(root_frame, bg_color="transparent")
        frame_row_1.grid(row=1, column=0, sticky="snwe", padx=self.padx, pady=self.pady)
        frame_row_1.rowconfigure(0, weight=1)
        frame_row_1.columnconfigure(0, weight=1)
        frame_row_1.columnconfigure(1, weight=8)
        frame_row_1.columnconfigure(2, weight=1)

        path_label = ctk.CTkLabel(frame_row_1, text=":مسیر", anchor="e", font=self.font)
        path_label.grid(
            row=0, column=2, sticky="w", padx=self.padx_staring_line, pady=self.pady
        )

        #   path textbox:
        self.path_entry = ctk.CTkEntry(frame_row_1)
        self.path_entry.grid(
            row=0, column=1, sticky="we", padx=self.padx, pady=self.pady
        )

        #   browse button:
        browse_button = ctk.CTkButton(
            frame_row_1,
            text="مرور",
            command=self.browse_path,
            width=40,
        )
        browse_button.grid(row=0, column=0, sticky="e", padx=self.padx, pady=self.pady)

    @wraps(Form.annotate_rows)
    @Form.frame_decorator
    def row_nav_buttons(self, frame):
        buttons_height = 30

        next_button = ctk.CTkButton(
            frame,
            font=self.font,
            text="بستن",
            command=exit,
            width=90,
            height=buttons_height,
            hover_color="red",
        )
        next_button.pack(side="left", padx=self.padx, pady=self.pady)

        save_button = ctk.CTkButton(
            frame,
            font=self.font,
            text="ذخیره",
            command=self.previous_form,
            width=90,
            height=buttons_height,
            fg_color="green",
        )
        save_button.pack(side="left", padx=self.padx, pady=self.pady)


class Form5(Form):
    step_name = "درباره"
    step_icon = "ℹ "

    def __init__(self, parent):
        self.padx = 5
        self.pady = 5
        self.padx_staring_line = (5, 15)
        self.padx_staring_line_ltr = (15, 5)

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

    def set_layout(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

    def load_widgets(self, parent):
        self.row_address(0)

    @Form.frame_decorator
    def row_address(self, frame):
        info_lbl_line1 = ctk.CTkLabel(
            frame,
            text="نوآوران فناور هوراد",
            anchor="e",
            font=self.font,
        )
        info_lbl_line2 = ctk.CTkLabel(
            frame,
            text=":آدرس",
            anchor="e",
            font=self.font,
        )
        info_lbl_line3 = ctk.CTkLabel(
            frame,
            text="فناوری پردیس، مرکز رشد نخبگان، طبقه دوم، واحد 1205",
            anchor="e",
            font=self.font,
        )
        info_lbl_line1.pack(fill="x", padx=self.padx_staring_line)
        info_lbl_line2.pack(fill="x", padx=self.padx_staring_line)
        info_lbl_line3.pack(fill="x", padx=self.padx_staring_line)
