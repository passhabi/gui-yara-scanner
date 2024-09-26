import tkinter as tk

root = tk.Tk()
text_widget = tk.Text(root)
text_widget.pack()

# Configure the tag for right-to-left text
text_widget.tag_configure("rtl", justify='right')

# Insert text with the RTL tag
text_widget.insert(tk.END, "سلام این یک امتحانه... .", "rtl")

root.mainloop()