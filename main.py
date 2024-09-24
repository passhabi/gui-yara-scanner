# import tkinter as tk
import customtkinter as customtk


class EventHandler:
    def __init__(self):
        pass

    def click_ready(self):
        print("btn ready has been clicked!")

    def click_cancel(self):
        print("btn cancel has been clicked!")
        exit()


class UIMaker:
    def __init__(self, event_handler: EventHandler):
        self.event_handler = event_handler
        self.start_form = customtk.CTk()
        self.start_form.mainloop()

    def make_form1(self):
        # form1:
        self.start_form.title('Hoorad CyberSecurity')
        self.start_form.geometry("600x300")
        self.start_form.grid_rowconfigure((0, 1), weight=1)
        self.start_form.grid_columnconfigure((0, 1, 2), weight=1)
        self.make_labels()
        self.make_buttons()

        #form2


    def make_buttons(self):
        # cancel button:
        btn_cancel = customtk.CTkButton(self.start_form, text="Cancel", command=self.event_handler.click_cancel)
        btn_cancel.grid(row=1, column=1, padx=20, pady=20, sticky='e')

        # ready button:
        btn_ready = customtk.CTkButton(self.start_form, text="ready!", command=self.event_handler.click_ready)
        btn_ready.grid(row=1, column=2, padx=20, pady=20)

    def make_labels(self):
        welcome_label = customtk.CTkLabel(self.start_form, text="Welcome to Hoorad cybersecurity system check.",
                                          fg_color="transparent")
        welcome_label.grid(row=0, column=0, padx=20, pady=20, columnspan=2)


if __name__ == '__main__':
    ui_maker = UIMaker(EventHandler())
