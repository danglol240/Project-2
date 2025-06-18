import os
import requests
import webbrowser
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, Toplevel, scrolledtext, simpledialog

def run_PE():
    file_path = filedialog.askopenfilename(
        title="Chọn file PE",
        filetypes=[("Executable files", "*.exe *.dll"), ("All files", "*.*")]
    )
    if file_path:
        try:
            # Lấy output từ PE_main.py
            result = subprocess.run(
                ["python3", "Extract/PE_main.py", file_path],
                capture_output=True, text=True
            )
            # Tạo cửa sổ mới để hiển thị kết quả
            result_window = Toplevel()
            result_window.title("Kết quả PE Scanner")
            result_window.geometry("600x300")
            result_window.resizable(True, True)
            result_window.rowconfigure(0, weight=1)
            result_window.columnconfigure(0, weight=1)

            text_box = scrolledtext.ScrolledText(result_window, wrap=tk.WORD, font=("Courier", 10))
            text_box.grid(row=0, column=0, sticky="nsew")
            text_box.pack(padx=10, pady=10)
            text_box.tag_configure("left", justify='left')

            # Hiển thị output (stdout hoặc stderr)
            if result.stdout:
                text_box.insert(tk.END, result.stdout)
            if result.stderr:
                text_box.insert(tk.END, "\nLỗi:\n" + result.stderr)
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể chạy PE scanner:\n{str(e)}")


VT_API_KEY = "00790b1307e3907a2c3d7e754a362d397b9844f27239f6af750411d8852400c0" 
def run_URL():
    url = simpledialog.askstring("Nhập URL", "Nhập URL cần kiểm tra:")
    if not url:
        return
    try:
        result = subprocess.run(
            ["python3", "Extract/url_main.py", url, VT_API_KEY],
            capture_output=True, text=True
        )
        result_window = Toplevel()
        result_window.title("Kết quả URL Scanner")
        result_window.geometry("600x300")
        result_window.resizable(True, True)
        result_window.rowconfigure(0, weight=1)
        result_window.columnconfigure(0, weight=1)
        text_box = scrolledtext.ScrolledText(result_window, wrap=tk.WORD, font=("Courier", 11))
        text_box.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        text_box.insert(tk.END, result.stdout)
        if result.stderr:
            text_box.insert(tk.END, "\nLỗi:\n" + result.stderr)
    except Exception as e:
        messagebox.showerror("Lỗi", f"Không thể kiểm tra URL:\n{str(e)}")

def on_exit():
    root.destroy()

# Tạo cửa sổ chính
root = tk.Tk()
root.title("Malware Detector")
root.geometry("400x300")
root.resizable(True,True)

# Tiêu đề
title = tk.Label(root, text="Malware Detector", font=("Courier", 20, "bold"))
title.pack(pady=20)

# Nút PE Scanner
btn_pe = tk.Button(root, text="🛡️ PE Scanner", width=25, height=2, command=run_PE)
btn_pe.pack(pady=10)

# Nút URL Scanner
btn_url = tk.Button(root, text="🌐 URL Scanner", width=25, height=2, command=run_URL)
btn_url.pack(pady=10)

# Nút Thoát
btn_exit = tk.Button(root, text="❌ Exit", width=25, height=2, command=on_exit)
btn_exit.pack(pady=10)

root.mainloop()
