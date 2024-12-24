import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib
import itertools
import string
import threading
import random
import math

# Global stop event for threads
stop_event = threading.Event()

class PasswordCrackingApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Cracking Tool")
        self.geometry("600x600")
        self.configure(bg="#2b2b2b")
        
        self.frames = {}
        
        # Initialize frames
        for F in (MainPage, DictionaryAttackPage, BruteForceAttackPage, PasswordGeneratorPage, WordlistGeneratorPage,PasswordAnalyzerPage):
            page_name = F.__name__
            frame = F(parent=self, controller=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        
        self.show_frame("MainPage")
    
    def show_frame(self, page_name):
        '''Show a frame for the given page name'''
        frame = self.frames[page_name]
        frame.tkraise()

class MainPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg="#2b2b2b")

        tk.Label(self, text="Password Cracking Tool", font=("Helvetica", 20), bg="#2b2b2b", fg="#ffffff").pack(pady=20)

        tk.Button(self, text="Dictionary Attack", command=lambda: controller.show_frame("DictionaryAttackPage"),
                  bg="#007acc", fg="#ffffff", font=("Helvetica", 14)).pack(fill='x', pady=10)
        tk.Button(self, text="Brute Force Attack", command=lambda: controller.show_frame("BruteForceAttackPage"),
                  bg="#007acc", fg="#ffffff", font=("Helvetica", 14)).pack(fill='x', pady=10)
        tk.Button(self, text="Password Generator", command=lambda: controller.show_frame("PasswordGeneratorPage"),
                  bg="#007acc", fg="#ffffff", font=("Helvetica", 14)).pack(fill='x', pady=10)
        tk.Button(self, text="Wordlist Generator", command=lambda: controller.show_frame("WordlistGeneratorPage"),
                  bg="#007acc", fg="#ffffff", font=("Helvetica", 14)).pack(fill='x', pady=10)
        tk.Button(self, text="Password Analyzer", command=lambda: controller.show_frame("PasswordAnalyzerPage"),
                  bg="#007acc", fg="#ffffff", font=("Helvetica", 14)).pack(fill='x', pady=10)

class DictionaryAttackPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg="#2b2b2b")
        
        tk.Label(self, text="Dictionary Attack", font=("Helvetica", 20), bg="#2b2b2b", fg="#ffffff").pack(pady=20)
        
        tk.Label(self, text="Hash:", bg="#2b2b2b", fg="#ffffff", font=("Helvetica", 14)).pack(pady=10)
        self.entry_hash = tk.Entry(self, font=("Helvetica", 14))
        self.entry_hash.pack(pady=10)

        tk.Label(self, text="Dictionary File:", bg="#2b2b2b", fg="#ffffff", font=("Helvetica", 14)).pack(pady=10)
        self.entry_dictionary = tk.Entry(self, font=("Helvetica", 14))
        self.entry_dictionary.pack(pady=10)
        tk.Button(self, text="Browse", command=self.browse_file, bg="#007acc", fg="#ffffff", font=("Helvetica", 14)).pack(pady=10)
        
        tk.Label(self, text="Hash Function:", bg="#2b2b2b", fg="#ffffff", font=("Helvetica", 14)).pack(pady=10)
        self.hash_options = ['MD5', 'SHA1', 'SHA256', 'SHA3-256', 'BLAKE2b', 'SHA224', 'SHA384', 'SHA512', 'BLAKE2s']
        self.combo_hash_function = ttk.Combobox(self, values=self.hash_options, font=("Helvetica", 14))
        self.combo_hash_function.current(0)
        self.combo_hash_function.pack(pady=10)
        
        tk.Button(self, text="Start Dictionary Attack", command=self.start_dictionary_attack,
                  bg="#007acc", fg="#ffffff", font=("Helvetica", 14)).pack(pady=20)
        tk.Button(self, text="Back to Main Menu", command=lambda: controller.show_frame("MainPage"),
                  bg="#007acc", fg="#ffffff", font=("Helvetica", 14)).pack(pady=20)
        
    def browse_file(self):
        filename = filedialog.askopenfilename()
        self.entry_dictionary.delete(0, tk.END)
        self.entry_dictionary.insert(0, filename)
    
    def start_dictionary_attack(self):
        target_hash = self.entry_hash.get()
        dictionary_file = self.entry_dictionary.get()
        hash_function = self.combo_hash_function.get()
        
        def run_attack():
            result = dictionary_attack(target_hash, dictionary_file, hash_function)
            if result:
                messagebox.showinfo("Result", f"Password found: {result}")
            else:
                messagebox.showinfo("Result", "Password not found")
        
        threading.Thread(target=run_attack).start()

class BruteForceAttackPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg="#2b2b2b")
        
        tk.Label(self, text="Brute Force Attack", font=("Helvetica", 20), bg="#2b2b2b", fg="#ffffff").pack(pady=20)
        
        tk.Label(self, text="Hash:", bg="#2b2b2b", fg="#ffffff", font=("Helvetica", 14)).pack(pady=10)
        self.entry_hash = tk.Entry(self, font=("Helvetica", 14))
        self.entry_hash.pack(pady=10)

        tk.Label(self, text="Max Length:", bg="#2b2b2b", fg="#ffffff", font=("Helvetica", 14)).pack(pady=10)
        self.entry_max_length = tk.Entry(self, font=("Helvetica", 14))
        self.entry_max_length.pack(pady=10)
        
        tk.Label(self, text="Hash Function:", bg="#2b2b2b", fg="#ffffff", font=("Helvetica", 14)).pack(pady=10)
        self.hash_options = ['MD5', 'SHA1', 'SHA256', 'SHA3-256', 'BLAKE2b', 'SHA224', 'SHA384', 'SHA512', 'BLAKE2s']
        self.combo_hash_function = ttk.Combobox(self, values=self.hash_options, font=("Helvetica", 14))
        self.combo_hash_function.current(0)
        self.combo_hash_function.pack(pady=10)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(pady=20)
        
        tk.Button(self, text="Start Brute Force Attack", command=self.start_brute_force_attack,
                  bg="#007acc", fg="#ffffff", font=("Helvetica", 14)).pack(pady=20)
        tk.Button(self, text="Stop", command=self.stop_attack,
                  bg="#007acc", fg="#ffffff", font=("Helvetica", 14)).pack(pady=10)
        tk.Button(self, text="Back to Main Menu", command=lambda: controller.show_frame("MainPage"),
                  bg="#007acc", fg="#ffffff", font=("Helvetica", 14)).pack(pady=20)
        
    def start_brute_force_attack(self):
        stop_event.clear()
        target_hash = self.entry_hash.get()
        max_length = int(self.entry_max_length.get())
        hash_function = self.combo_hash_function.get()
        
        def update_progress(progress):
            self.progress_var.set(progress)
            self.update_idletasks()
        
        def run_attack():
            result = brute_force_attack(target_hash, max_length, hash_function, update_progress)
            if result:
                messagebox.showinfo("Result", f"Password found: {result}")
            else:
                if not stop_event.is_set():
                    messagebox.showinfo("Result", "Password not found")
        
        threading.Thread(target=run_attack).start()
    
    def stop_attack(self):
        stop_event.set()

class PasswordGeneratorPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg="#2b2b2b")
        
        tk.Label(self, text="Password Generator", font=("Helvetica", 20), bg="#2b2b2b", fg="#ffffff").pack(pady=20)
        
        tk.Label(self, text="Length:", bg="#2b2b2b", fg="#ffffff", font=("Helvetica", 14)).pack(pady=10)
        self.entry_password_length = tk.Entry(self, font=("Helvetica", 14))
        self.entry_password_length.pack(pady=10)

        self.var_uppercase = tk.BooleanVar(value=True)
        self.var_lowercase = tk.BooleanVar(value=True)
        self.var_digits = tk.BooleanVar(value=True)
        self.var_special = tk.BooleanVar(value=True)

        tk.Checkbutton(self, text="Include Uppercase", variable=self.var_uppercase, bg="#2b2b2b", fg="#ffffff", font=("Helvetica", 14), selectcolor="#444444").pack(anchor="w", padx=10)
        tk.Checkbutton(self, text="Include Lowercase", variable=self.var_lowercase, bg="#2b2b2b", fg="#ffffff", font=("Helvetica", 14), selectcolor="#444444").pack(anchor="w", padx=10)
        tk.Checkbutton(self, text="Include Digits", variable=self.var_digits, bg="#2b2b2b", fg="#ffffff", font=("Helvetica", 14), selectcolor="#444444").pack(anchor="w", padx=10)
        tk.Checkbutton(self, text="Include Special Characters", variable=self.var_special, bg="#2b2b2b", fg="#ffffff", font=("Helvetica", 14), selectcolor="#444444").pack(anchor="w", padx=10)

        tk.Button(self, text="Generate Password", command=self.generate_password, bg="#007acc", fg="#ffffff", font=("Helvetica", 14)).pack(pady=20)

        self.entry_generated_password = tk.Entry(self, font=("Helvetica", 14))
        self.entry_generated_password.pack(pady=10)

        tk.Button(self, text="Back to Main Menu", command=lambda: controller.show_frame("MainPage"),
                  bg="#007acc", fg="#ffffff", font=("Helvetica", 14)).pack(pady=20)
    
    def generate_password(self):
        try:
            length = int(self.entry_password_length.get())
        except ValueError:
            messagebox.showerror("Input Error", "Password length must be a valid number.")
            return
        
        characters = ''
        if self.var_uppercase.get():
            characters += string.ascii_uppercase
        if self.var_lowercase.get():
            characters += string.ascii_lowercase
        if self.var_digits.get():
            characters += string.digits
        if self.var_special.get():
            characters += string.punctuation

        if characters:
            password = ''.join(random.choice(characters) for _ in range(length))
            self.entry_generated_password.delete(0, tk.END)
            self.entry_generated_password.insert(0, password)
        else:
            messagebox.showerror("Input Error", "Please select at least one character set.")

class WordlistGeneratorPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg="#2b2b2b")
        
        tk.Label(self, text="Wordlist Generator", font=("Helvetica", 20), bg="#2b2b2b", fg="#ffffff").pack(pady=20)
        
        tk.Label(self, text="Min Length:", bg="#2b2b2b", fg="#ffffff", font=("Helvetica", 14)).pack(pady=10)
        self.entry_min_length = tk.Entry(self, font=("Helvetica", 14))
        self.entry_min_length.pack(pady=10)
        
        tk.Label(self, text="Max Length:", bg="#2b2b2b", fg="#ffffff", font=("Helvetica", 14)).pack(pady=10)
        self.entry_max_length = tk.Entry(self, font=("Helvetica", 14))
        self.entry_max_length.pack(pady=10)

        tk.Label(self, text="Max Words:", bg="#2b2b2b", fg="#ffffff", font=("Helvetica", 14)).pack(pady=10)
        self.entry_max_words = tk.Entry(self, font=("Helvetica", 14))
        self.entry_max_words.pack(pady=10)

        self.var_uppercase = tk.BooleanVar(value=True)
        self.var_lowercase = tk.BooleanVar(value=True)
        self.var_digits = tk.BooleanVar(value=True)
        self.var_special = tk.BooleanVar(value=True)

        tk.Checkbutton(self, text="Include Uppercase", variable=self.var_uppercase, bg="#2b2b2b", fg="#ffffff", font=("Helvetica", 14), selectcolor="#444444").pack(anchor="w", padx=10)
        tk.Checkbutton(self, text="Include Lowercase", variable=self.var_lowercase, bg="#2b2b2b", fg="#ffffff", font=("Helvetica", 14), selectcolor="#444444").pack(anchor="w", padx=10)
        tk.Checkbutton(self, text="Include Digits", variable=self.var_digits, bg="#2b2b2b", fg="#ffffff", font=("Helvetica", 14), selectcolor="#444444").pack(anchor="w", padx=10)
        tk.Checkbutton(self, text="Include Special Characters", variable=self.var_special, bg="#2b2b2b", fg="#ffffff", font=("Helvetica", 14), selectcolor="#444444").pack(anchor="w", padx=10)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(pady=20)
        
        tk.Button(self, text="Generate Wordlist", command=self.start_wordlist_generation,
                  bg="#007acc", fg="#ffffff", font=("Helvetica", 14)).pack(pady=20)
        tk.Button(self, text="Stop", command=self.stop_wordlist_generation,
                  bg="#007acc", fg="#ffffff", font=("Helvetica", 14)).pack(pady=10)
        tk.Button(self, text="Back to Main Menu", command=lambda: controller.show_frame("MainPage"),
                  bg="#007acc", fg="#ffffff", font=("Helvetica", 14)).pack(pady=20)
    
    def start_wordlist_generation(self):
        stop_event.clear()
        try:
            min_length = int(self.entry_min_length.get())
            max_length = int(self.entry_max_length.get())
            max_words = int(self.entry_max_words.get())
        except ValueError:
            messagebox.showerror("Input Error", "Lengths and max words must be valid numbers.")
            return
        
        charset = ''
        if self.var_uppercase.get():
            charset += string.ascii_uppercase
        if self.var_lowercase.get():
            charset += string.ascii_lowercase
        if self.var_digits.get():
            charset += string.digits
        if self.var_special.get():
            charset += string.punctuation
        
        if not charset:
            messagebox.showerror("Input Error", "Please select at least one character set.")
            return
        
        output_file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if output_file:
            def update_progress(progress):
                self.progress_var.set(progress)
                self.update_idletasks()

            def run_generation():
                generate_wordlist(min_length, max_length, max_words, charset, output_file, update_progress)
                messagebox.showinfo("Result", "Wordlist generation completed.")

            threading.Thread(target=run_generation).start()
    
    def stop_wordlist_generation(self):
        stop_event.set()

class PasswordAnalyzerPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg="#2b2b2b")

        tk.Label(self, text="Password Analyzer", font=("Helvetica", 20), bg="#2b2b2b", fg="#ffffff").pack(pady=20)
        
        tk.Label(self, text="Password:", bg="#2b2b2b", fg="#ffffff", font=("Helvetica", 14)).pack(pady=10)
        self.entry_password = tk.Entry(self, font=("Helvetica", 14), show="*")
        self.entry_password.pack(pady=10)
        
        tk.Button(self, text="Analyze", command=self.analyze_password,
                  bg="#007acc", fg="#ffffff", font=("Helvetica", 14)).pack(pady=20)
        
        self.result_label = tk.Label(self, text="", font=("Helvetica", 14), bg="#2b2b2b", fg="#ffffff")
        self.result_label.pack(pady=10)
        
        tk.Button(self, text="Back to Main Menu", command=lambda: controller.show_frame("MainPage"),
                  bg="#007acc", fg="#ffffff", font=("Helvetica", 14)).pack(pady=20)

    def analyze_password(self):
        password = self.entry_password.get()
        result = analyze_password(password)
        self.result_label.config(text=f"Strength: {result}")

# Utility functions

def dictionary_attack(target_hash, dictionary_file, hash_function):
    with open(dictionary_file, 'r') as f:
        for word in f:
            word = word.strip()
            if hash_password(word, hash_function) == target_hash:
                return word
    return None

def brute_force_attack(target_hash, max_length, hash_function, update_progress):
    characters = string.ascii_letters + string.digits + string.punctuation
    total_combinations = sum(len(characters) ** length for length in range(1, max_length + 1))
    current_combination = 0

    for length in range(1, max_length + 1):
        for guess in itertools.product(characters, repeat=length):
            if stop_event.is_set():
                return None
            guess = ''.join(guess)
            current_combination += 1
            progress = (current_combination / total_combinations) * 100
            update_progress(progress)

            if hash_password(guess, hash_function) == target_hash:
                return guess
    return None

def generate_wordlist(min_length, max_length, max_words, charset, output_file, update_progress):
    total_combinations = sum(len(charset) ** length for length in range(min_length, max_length + 1))
    current_combination = 0
    word_count = 0

    with open(output_file, 'w') as f:
        for length in range(min_length, max_length + 1):
            for word in itertools.product(charset, repeat=length):
                if stop_event.is_set() or word_count >= max_words:
                    return
                f.write(''.join(word) + '\n')
                word_count += 1
                current_combination += 1
                progress = (current_combination / total_combinations) * 100
                update_progress(progress)

def hash_password(password, hash_function):
    if hash_function == 'SHA3-256':
        return hashlib.sha3_256(password.encode()).hexdigest()
    elif hash_function == 'BLAKE2b':
        return hashlib.blake2b(password.encode()).hexdigest()
    elif hash_function == 'SHA224':
        return hashlib.sha224(password.encode()).hexdigest()
    elif hash_function == 'SHA384':
        return hashlib.sha384(password.encode()).hexdigest()
    elif hash_function == 'SHA512':
        return hashlib.sha512(password.encode()).hexdigest()
    elif hash_function == 'BLAKE2s':
        return hashlib.blake2s(password.encode()).hexdigest()
    else:
        return hashlib.new(hash_function.lower(), password.encode()).hexdigest()

def analyze_password(password):
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)

    score = length
    if has_upper:
        score += 2
    if has_lower:
        score += 2
    if has_digit:
        score += 2
    if has_special:
        score += 2

    if score >= 10:
        return "Strong"
    elif score >= 6:
        return "Moderate"
    else:
        return "Weak"

if __name__ == "__main__":
    app = PasswordCrackingApp()
    app.mainloop()
