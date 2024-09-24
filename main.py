# import tkinter as tk
import customtkinter as customtk


class EventHandler:
    def __init__(self):
        pass

    def click_ready(self):
        print("btn 'ready' has been clicked!")


class UIMaker:
    def __init__(self, event_handler: EventHandler):
        self.event_handler = event_handler
        self.app = customtk.CTk()
        self.app.title('Hoorad System Check')
        self.app.geometry("400x150")
        self.make_buttons()
        self.app.mainloop()

    def make_buttons(self):
        button = customtk.CTkButton(self.app, text="ready!", command=self.event_handler.click_ready())
        button.grid(row=0, column=0, padx=20, pady=20)


if __name__ == '__main__':
    ui_maker = UIMaker(EventHandler())
