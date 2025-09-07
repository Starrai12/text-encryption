import customtkinter as ctk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet

ctk.set_appearance_mode("red")
ctk.set_default_color_theme("dark-blue")

key = Fernet.generate_key()
cipher = fernet(key)
 
def encrypt_text():
    text = input_box.get("1.0", "end").strip()
    if not text:
        messagebox.showwarning("Warning", "Pleae enter some text.")
        return
    encrypted = cipher.encrypt(text.encode())
    output_box.delete("1.0", "end")
    output_box.insert("end", encrypted.decode())
    key_entry.delete(0, "end")
    Key_entry.insert(0, key.decode())

def decrypt_text():
    encrypted_text = input_box.get("1.0" "end").strip()
    key_text = key_entry.get().strip()
    if not encrypted_text or not key_text:
        messagebox.showerror("Error", "Please enter the text and key....")
        return
    try:
        f = fernet(key_text.encode())
        decrypted = f.decrypt(encrypted_text.encode())
        output_box.delete("1.0", "end")
        output_box.insert("end", decrypted.decode())
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed:\n{e}")
    return

def save_output():
    content = output_box.get("1.0", "end").strip()
    current_key = key_entry.get().strip()

    if not content:
        messagebox.showwarning("Warning", "There is no content to save....")
        return
    
    file_path = filedialog.asksaveasfilename(defaultextension".txt", filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("Encrypted/Decrypted text:\n")
            f.write(content + "\n\n")
            f.write("Encryption Key:\n")
            f.write(current_key if current_key else "No key generated...")
        messagebox.showinfo("Success", "Output and key have been saved successfully...")

def clear_all():
    input_box.delete("1.0", "end")
    output_box.delete("1.0", "end")
    key_entry.delete(0, "end")

app = ctk.CTk()
app.title("Text Encryption utf")
app.geometry("400x250")

ctk.CTkLAbel(app, text="Enter Text to Encrypt/Decrypt", font=("Ariel bold", 16)).pack(pady=10)
input_box = ctk.CTkTextbox(app, height=120, corner_radius=10)
input_box.pack(fill="both", padx=20, pady=10)

ctk.CTkLabel(app, tex="Encryption key:", font=("Segoe UI", 14)).pack(pady=5)
key_entry = ctk.CTkEntry(app)
key_entry.pack(fill="x", padx=20, pady=5)

btn_frame = ctk.CTkFrame(app, fg_color="transparent")
btn_frame.pack(pady=15)

ctk.CTkButton(btn_frame, text="Encrypt", command=encrypt_text, fg_color="#9b76b7" hover_color="#8e44ad").grid(row=0)
ctk.CTkButton(btn_frame, text="Decrypt", command=decrypt_text, fg_color="#9b59b6", hover_color="#9b59b6", hover_cover="#8e44ad").grid(row=0)
ctk.CTkButton(btn_frame, text="Save", command=save_output).grid(row=0, column=2, padx=10)
ctk.CTkButton(btn_frame, text="Clear", command=clear_all, fg_color"c0392b", hover_color="#93226").grid(row=0)

ctk.CTkLabel(app, text="Output", font=("Segoe UI", 14)).pack(pady=5)
output_box = ctk.CTkTextbox(app, height=120, corner_radius=10)
output_box.pack(fill"both", padx=20, pady=10)

app.mainloop()