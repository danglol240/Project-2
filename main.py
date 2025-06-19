import os
import requests
import webbrowser
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, Toplevel, scrolledtext, simpledialog, Label, Button, Entry


VT_API_KEY = "00790b1307e3907a2c3d7e754a362d397b9844f27239f6af750411d8852400c0" 
def run_PE():
    file_path = filedialog.askopenfilename(
        title="Chọn file PE",
        filetypes=[("Executable files", "*.exe *.dll"), ("All files", "*.*")]
    )
    if file_path:
        api_key = VT_API_KEY
        if not api_key:
            return
        try:
            result = subprocess.run(
                ["python3", "Extract/PE_main.py", file_path, api_key],
                capture_output=True, text=True
            )
            result_window = Toplevel()
            result_window.title("Kết quả PE Scanner")
            result_window.geometry("600x400")
            result_window.resizable(True, True)
            result_window.rowconfigure(0, weight=1)
            result_window.columnconfigure(0, weight=1)
            text_box = scrolledtext.ScrolledText(result_window, wrap=tk.WORD, font=("Courier", 10))
            text_box.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
            text_box.tag_configure("left", justify='left')
            if result.stdout:
                text_box.insert(tk.END, result.stdout, "left")
            if result.stderr:
                text_box.insert(tk.END, "\nLỗi:\n" + result.stderr, "left")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể chạy PE scanner:\n{str(e)}")


def custom_url_dialog(parent, title="Nhập URL", prompt="Nhập URL cần kiểm tra:"):
    dialog = Toplevel(parent)
    dialog.title(title)
    dialog.geometry("600x150")  # Kích thước rộng hơn mặc định
    dialog.resizable(True, False)

    Label(dialog, text=prompt, font=("Courier", 14)).pack(pady=10)
    entry = Entry(dialog, font=("Courier", 14), width=60)
    entry.pack(padx=20, pady=10)
    entry.focus_set()

    result = {"url": None}

    def on_ok():
        url = entry.get().strip()
        if url:
            result["url"] = url
            dialog.destroy()
        else:
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập URL!")

    def on_cancel():
        dialog.destroy()

    btn_frame = tk.Frame(dialog)
    btn_frame.pack(pady=10)
    Button(btn_frame, text="OK", font=("Courier", 12), width=10, command=on_ok).pack(side="left", padx=10)
    Button(btn_frame, text="Hủy", font=("Courier", 12), width=10, command=on_cancel).pack(side="right", padx=10)

    dialog.transient(parent)
    dialog.grab_set()
    parent.wait_window(dialog)
    return result["url"]

def run_URL():
    url = custom_url_dialog(root)
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
root.geometry("1000x450")
root.resizable(True,True)

# Tiêu đề
title = tk.Label(root, text="Malware Detector", font=("Courier", 30, "bold"))
title.pack(pady=20)

# Nút PE Scanner
btn_pe = tk.Button(root, text="🛡️ PE Scanner",font=("Courier", 20, "bold"), width=25, height=2, command=run_PE)
btn_pe.pack(pady=10)

# Nút URL Scanner
btn_url = tk.Button(root, text="🌐 URL Scanner",font=("Courier", 20, "bold"), width=25, height=2, command=run_URL)
btn_url.pack(pady=10)

# Nút Thoát
btn_exit = tk.Button(root, text="❌ Exit",font=("Courier", 20, "bold"), width=25, height=2, command=on_exit)
btn_exit.pack(pady=10)

root.mainloop()
