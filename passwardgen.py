import tkinter as tk
from tkinter import ttk, messagebox
import random
import string
import secrets
import pyperclip
import re
from datetime import datetime

class PasswordGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Advanced Password Generator")
        self.root.geometry("600x750")
        self.root.resizable(False, False)
        self.root.configure(bg="#1a1a2e")
        
        # Password history
        self.password_history = []
        
        # Color scheme
        self.colors = {
            'bg': '#1a1a2e',
            'secondary_bg': '#16213e',
            'accent': '#0f3460',
            'primary': '#533483',
            'success': '#27ae60',
            'warning': '#f39c12',
            'danger': '#e74c3c',
            'text': '#ffffff',
            'text_secondary': '#a0a0a0',
            'button_bg': '#533483',
            'button_hover': '#6c4a9b'
        }
        
        self.create_widgets()
        self.setup_styles()
    
    def setup_styles(self):
        # Configure ttk styles
        style = ttk.Style()
        style.theme_use('clam')
        
        # Custom button style
        style.configure('Custom.TButton',
                       background=self.colors['button_bg'],
                       foreground=self.colors['text'],
                       font=('Arial', 11, 'bold'),
                       borderwidth=0,
                       focuscolor='none')
        
        style.map('Custom.TButton',
                 background=[('active', self.colors['button_hover'])])
        
        # Custom scale style
        style.configure('Custom.Horizontal.TScale',
                       background=self.colors['bg'],
                       troughcolor=self.colors['accent'],
                       borderwidth=0,
                       lightcolor=self.colors['primary'],
                       darkcolor=self.colors['primary'])
    
    def create_widgets(self):
        # Main container
        main_frame = tk.Frame(self.root, bg=self.colors['bg'])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        title_label = tk.Label(main_frame, text="🔐 Advanced Password Generator",
                              font=('Arial', 22, 'bold'),
                              bg=self.colors['bg'], fg=self.colors['text'])
        title_label.pack(pady=(0, 30))
        
        # Settings Frame
        settings_frame = tk.LabelFrame(main_frame, text="Password Settings",
                                      font=('Arial', 14, 'bold'),
                                      bg=self.colors['secondary_bg'],
                                      fg=self.colors['text'],
                                      relief=tk.RAISED, bd=2)
        settings_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Length Section
        length_frame = tk.Frame(settings_frame, bg=self.colors['secondary_bg'])
        length_frame.pack(fill=tk.X, padx=20, pady=15)
        
        tk.Label(length_frame, text="Password Length:",
                font=('Arial', 12, 'bold'),
                bg=self.colors['secondary_bg'], fg=self.colors['text']).pack(anchor=tk.W)
        
        # Length slider and display
        length_control_frame = tk.Frame(length_frame, bg=self.colors['secondary_bg'])
        length_control_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.length_var = tk.IntVar(value=12)
        self.length_scale = ttk.Scale(length_control_frame, from_=4, to=128,
                                     orient=tk.HORIZONTAL, variable=self.length_var,
                                     style='Custom.Horizontal.TScale',
                                     command=self.update_length_display)
        self.length_scale.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.length_display = tk.Label(length_control_frame, text="12",
                                      font=('Arial', 14, 'bold'),
                                      bg=self.colors['secondary_bg'],
                                      fg=self.colors['primary'],
                                      width=4)
        self.length_display.pack(side=tk.RIGHT, padx=(10, 0))
        
        # Character Type Options
        options_frame = tk.Frame(settings_frame, bg=self.colors['secondary_bg'])
        options_frame.pack(fill=tk.X, padx=20, pady=(0, 15))
        
        tk.Label(options_frame, text="Character Types:",
                font=('Arial', 12, 'bold'),
                bg=self.colors['secondary_bg'], fg=self.colors['text']).pack(anchor=tk.W, pady=(0, 10))
        
        # Checkboxes for character types
        checkbox_frame = tk.Frame(options_frame, bg=self.colors['secondary_bg'])
        checkbox_frame.pack(fill=tk.X)
        
        self.include_uppercase = tk.BooleanVar(value=True)
        self.include_lowercase = tk.BooleanVar(value=True)
        self.include_numbers = tk.BooleanVar(value=True)
        self.include_symbols = tk.BooleanVar(value=True)
        
        uppercase_cb = tk.Checkbutton(checkbox_frame, text="Uppercase (A-Z)",
                                     variable=self.include_uppercase,
                                     font=('Arial', 10),
                                     bg=self.colors['secondary_bg'],
                                     fg=self.colors['text'],
                                     selectcolor=self.colors['accent'],
                                     activebackground=self.colors['secondary_bg'],
                                     activeforeground=self.colors['text'],
                                     command=self.update_strength)
        uppercase_cb.grid(row=0, column=0, sticky=tk.W, pady=2)
        
        lowercase_cb = tk.Checkbutton(checkbox_frame, text="Lowercase (a-z)",
                                     variable=self.include_lowercase,
                                     font=('Arial', 10),
                                     bg=self.colors['secondary_bg'],
                                     fg=self.colors['text'],
                                     selectcolor=self.colors['accent'],
                                     activebackground=self.colors['secondary_bg'],
                                     activeforeground=self.colors['text'],
                                     command=self.update_strength)
        lowercase_cb.grid(row=1, column=0, sticky=tk.W, pady=2)
        
        numbers_cb = tk.Checkbutton(checkbox_frame, text="Numbers (0-9)",
                                   variable=self.include_numbers,
                                   font=('Arial', 10),
                                   bg=self.colors['secondary_bg'],
                                   fg=self.colors['text'],
                                   selectcolor=self.colors['accent'],
                                   activebackground=self.colors['secondary_bg'],
                                   activeforeground=self.colors['text'],
                                   command=self.update_strength)
        numbers_cb.grid(row=0, column=1, sticky=tk.W, padx=(40, 0), pady=2)
        
        symbols_cb = tk.Checkbutton(checkbox_frame, text="Symbols (!@#$...)",
                                   variable=self.include_symbols,
                                   font=('Arial', 10),
                                   bg=self.colors['secondary_bg'],
                                   fg=self.colors['text'],
                                   selectcolor=self.colors['accent'],
                                   activebackground=self.colors['secondary_bg'],
                                   activeforeground=self.colors['text'],
                                   command=self.update_strength)
        symbols_cb.grid(row=1, column=1, sticky=tk.W, padx=(40, 0), pady=2)
        
        # Advanced Options
        advanced_frame = tk.Frame(settings_frame, bg=self.colors['secondary_bg'])
        advanced_frame.pack(fill=tk.X, padx=20, pady=(10, 15))
        
        self.exclude_ambiguous = tk.BooleanVar(value=False)
        ambiguous_cb = tk.Checkbutton(advanced_frame, text="Exclude ambiguous characters (0, O, l, I)",
                                     variable=self.exclude_ambiguous,
                                     font=('Arial', 10),
                                     bg=self.colors['secondary_bg'],
                                     fg=self.colors['text'],
                                     selectcolor=self.colors['accent'],
                                     activebackground=self.colors['secondary_bg'],
                                     activeforeground=self.colors['text'])
        ambiguous_cb.pack(anchor=tk.W)
        
        self.require_all_types = tk.BooleanVar(value=True)
        require_cb = tk.Checkbutton(advanced_frame, text="Ensure at least one character from each selected type",
                                   variable=self.require_all_types,
                                   font=('Arial', 10),
                                   bg=self.colors['secondary_bg'],
                                   fg=self.colors['text'],
                                   selectcolor=self.colors['accent'],
                                   activebackground=self.colors['secondary_bg'],
                                   activeforeground=self.colors['text'])
        require_cb.pack(anchor=tk.W, pady=(5, 0))
        
        # Preset Buttons
        preset_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        preset_frame.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(preset_frame, text="Quick Presets:",
                font=('Arial', 12, 'bold'),
                bg=self.colors['bg'], fg=self.colors['text']).pack(anchor=tk.W)
        
        preset_buttons_frame = tk.Frame(preset_frame, bg=self.colors['bg'])
        preset_buttons_frame.pack(fill=tk.X, pady=(10, 0))
        
        presets = [
            ("Simple", {"length": 8, "upper": True, "lower": True, "numbers": False, "symbols": False}),
            ("Standard", {"length": 12, "upper": True, "lower": True, "numbers": True, "symbols": False}),
            ("Strong", {"length": 16, "upper": True, "lower": True, "numbers": True, "symbols": True}),
            ("Ultra Strong", {"length": 24, "upper": True, "lower": True, "numbers": True, "symbols": True})
        ]
        
        for i, (name, config) in enumerate(presets):
            btn = ttk.Button(preset_buttons_frame, text=name,
                           style='Custom.TButton',
                           command=lambda c=config: self.apply_preset(c))
            btn.grid(row=0, column=i, padx=5, sticky='ew')
            preset_buttons_frame.grid_columnconfigure(i, weight=1)
        
        # Generate Button
        generate_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        generate_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.generate_btn = tk.Button(generate_frame, text="🎲 Generate Password",
                                     command=self.generate_password,
                                     font=('Arial', 14, 'bold'),
                                     bg=self.colors['button_bg'],
                                     fg=self.colors['text'],
                                     relief=tk.FLAT,
                                     pady=12,
                                     cursor='hand2')
        self.generate_btn.pack(fill=tk.X)
        
        # Password Display Frame
        display_frame = tk.LabelFrame(main_frame, text="Generated Password",
                                     font=('Arial', 14, 'bold'),
                                     bg=self.colors['secondary_bg'],
                                     fg=self.colors['text'],
                                     relief=tk.RAISED, bd=2)
        display_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Password display
        password_display_frame = tk.Frame(display_frame, bg=self.colors['secondary_bg'])
        password_display_frame.pack(fill=tk.X, padx=20, pady=15)
        
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(password_display_frame,
                                      textvariable=self.password_var,
                                      font=('Courier', 14, 'bold'),
                                      bg=self.colors['accent'],
                                      fg=self.colors['text'],
                                      relief=tk.FLAT,
                                      bd=0,
                                      state='readonly')
        self.password_entry.pack(fill=tk.X)
        
        # Action buttons
        action_frame = tk.Frame(display_frame, bg=self.colors['secondary_bg'])
        action_frame.pack(fill=tk.X, padx=20, pady=(0, 15))
        
        self.copy_btn = ttk.Button(action_frame, text="📋 Copy to Clipboard",
                                  style='Custom.TButton',
                                  command=self.copy_password)
        self.copy_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.save_btn = ttk.Button(action_frame, text="💾 Save to History",
                                  style='Custom.TButton',
                                  command=self.save_to_history)
        self.save_btn.pack(side=tk.LEFT)
        
        # Strength Indicator
        strength_frame = tk.Frame(display_frame, bg=self.colors['secondary_bg'])
        strength_frame.pack(fill=tk.X, padx=20, pady=(5, 15))
        
        tk.Label(strength_frame, text="Password Strength:",
                font=('Arial', 10, 'bold'),
                bg=self.colors['secondary_bg'], fg=self.colors['text']).pack(anchor=tk.W)
        
        self.strength_var = tk.StringVar()
        self.strength_label = tk.Label(strength_frame,
                                      textvariable=self.strength_var,
                                      font=('Arial', 12, 'bold'),
                                      bg=self.colors['secondary_bg'])
        self.strength_label.pack(anchor=tk.W, pady=(5, 0))
        
        # History Frame
        history_frame = tk.LabelFrame(main_frame, text="Password History",
                                     font=('Arial', 14, 'bold'),
                                     bg=self.colors['secondary_bg'],
                                     fg=self.colors['text'],
                                     relief=tk.RAISED, bd=2)
        history_frame.pack(fill=tk.BOTH, expand=True)
        
        # History listbox with scrollbar
        history_container = tk.Frame(history_frame, bg=self.colors['secondary_bg'])
        history_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=15)
        
        scrollbar = tk.Scrollbar(history_container)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.history_listbox = tk.Listbox(history_container,
                                         font=('Courier', 10),
                                         bg=self.colors['accent'],
                                         fg=self.colors['text'],
                                         selectbackground=self.colors['primary'],
                                         yscrollcommand=scrollbar.set,
                                         relief=tk.FLAT)
        self.history_listbox.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.history_listbox.yview)
        
        # History buttons
        history_btn_frame = tk.Frame(history_frame, bg=self.colors['secondary_bg'])
        history_btn_frame.pack(fill=tk.X, padx=20, pady=(0, 15))
        
        ttk.Button(history_btn_frame, text="🔄 Use Selected",
                  style='Custom.TButton',
                  command=self.use_from_history).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(history_btn_frame, text="🗑️ Clear History",
                  style='Custom.TButton',
                  command=self.clear_history).pack(side=tk.LEFT)
        
        # Initial strength update
        self.update_strength()
    
    def update_length_display(self, value=None):
        self.length_display.config(text=str(int(float(value or self.length_var.get()))))
        self.update_strength()
    
    def apply_preset(self, config):
        self.length_var.set(config["length"])
        self.include_uppercase.set(config["upper"])
        self.include_lowercase.set(config["lower"])
        self.include_numbers.set(config["numbers"])
        self.include_symbols.set(config["symbols"])
        self.update_length_display()
        self.update_strength()
    
    def get_character_sets(self):
        chars = ""
        char_types = []
        
        if self.include_uppercase.get():
            uppercase = string.ascii_uppercase
            if self.exclude_ambiguous.get():
                uppercase = uppercase.replace('O', '').replace('I', '')
            chars += uppercase
            char_types.append(uppercase)
        
        if self.include_lowercase.get():
            lowercase = string.ascii_lowercase
            if self.exclude_ambiguous.get():
                lowercase = lowercase.replace('l', '').replace('o', '')
            chars += lowercase
            char_types.append(lowercase)
        
        if self.include_numbers.get():
            numbers = string.digits
            if self.exclude_ambiguous.get():
                numbers = numbers.replace('0', '').replace('1', '')
            chars += numbers
            char_types.append(numbers)
        
        if self.include_symbols.get():
            symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            chars += symbols
            char_types.append(symbols)
        
        return chars, char_types
    
    def generate_password(self):
        if not any([self.include_uppercase.get(), self.include_lowercase.get(),
                   self.include_numbers.get(), self.include_symbols.get()]):
            messagebox.showwarning("Warning", "Please select at least one character type!")
            return
        
        length = self.length_var.get()
        chars, char_types = self.get_character_sets()
        
        if not chars:
            messagebox.showerror("Error", "No valid characters available!")
            return
        
        # Generate password
        if self.require_all_types.get() and len(char_types) > 1:
            # Ensure at least one character from each type
            password = []
            
            # Add one character from each type
            for char_set in char_types:
                if char_set:
                    password.append(secrets.choice(char_set))
            
            # Fill the rest randomly
            remaining_length = length - len(password)
            for _ in range(remaining_length):
                password.append(secrets.choice(chars))
            
            # Shuffle the password
            secrets.SystemRandom().shuffle(password)
            password = ''.join(password)
        else:
            # Generate completely random password
            password = ''.join(secrets.choice(chars) for _ in range(length))
        
        self.password_var.set(password)
        self.evaluate_password_strength(password)
    
    def evaluate_password_strength(self, password):
        score = 0
        feedback = []
        
        # Length scoring
        if len(password) >= 12:
            score += 25
        elif len(password) >= 8:
            score += 15
        else:
            score += 5
            feedback.append("Too short")
        
        # Character variety scoring
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_symbol = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password))
        
        variety_count = sum([has_upper, has_lower, has_digit, has_symbol])
        score += variety_count * 15
        
        # Repetition penalty
        unique_chars = len(set(password))
        repetition_ratio = unique_chars / len(password)
        if repetition_ratio < 0.7:
            score -= 10
            feedback.append("Repetitive characters")
        
        # Common patterns penalty
        if re.search(r'(012|123|234|345|456|567|678|789|890)', password):
            score -= 15
            feedback.append("Sequential numbers")
        
        if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):
            score -= 15
            feedback.append("Sequential letters")
        
        # Determine strength level and color
        if score >= 80:
            strength_text = "Very Strong 🔐"
            color = self.colors['success']
        elif score >= 60:
            strength_text = "Strong 💪"
            color = self.colors['success']
        elif score >= 40:
            strength_text = "Moderate ⚠️"
            color = self.colors['warning']
        else:
            strength_text = "Weak ❌"
            color = self.colors['danger']
        
        self.strength_var.set(f"{strength_text} (Score: {score}/100)")
        self.strength_label.config(fg=color)
    
    def update_strength(self):
        # Preview strength based on current settings
        chars, char_types = self.get_character_sets()
        length = self.length_var.get()
        
        if not chars:
            self.strength_var.set("No characters selected")
            self.strength_label.config(fg=self.colors['danger'])
            return
        
        # Calculate potential strength
        entropy = length * (len(chars).bit_length() - 1)
        
        if entropy >= 60:
            strength_text = "Potential: Very Strong"
            color = self.colors['success']
        elif entropy >= 50:
            strength_text = "Potential: Strong"
            color = self.colors['success']
        elif entropy >= 35:
            strength_text = "Potential: Moderate"
            color = self.colors['warning']
        else:
            strength_text = "Potential: Weak"
            color = self.colors['danger']
        
        self.strength_var.set(f"{strength_text} (Entropy: {entropy} bits)")
        self.strength_label.config(fg=color)
    
    def copy_password(self):
        password = self.password_var.get()
        if password:
            try:
                pyperclip.copy(password)
                messagebox.showinfo("Success", "Password copied to clipboard!")
            except:
                # Fallback method for systems without pyperclip
                self.root.clipboard_clear()
                self.root.clipboard_append(password)
                messagebox.showinfo("Success", "Password copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No password to copy!")
    
    def save_to_history(self):
        password = self.password_var.get()
        if password:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            entry = f"{timestamp} - {password}"
            self.password_history.append(entry)
            self.history_listbox.insert(tk.END, entry)
            
            # Limit history to 50 entries
            if len(self.password_history) > 50:
                self.password_history.pop(0)
                self.history_listbox.delete(0)
            
            messagebox.showinfo("Success", "Password saved to history!")
        else:
            messagebox.showwarning("Warning", "No password to save!")
    
    def use_from_history(self):
        selection = self.history_listbox.curselection()
        if selection:
            entry = self.history_listbox.get(selection[0])
            # Extract password from history entry
            password = entry.split(" - ", 1)[1]
            self.password_var.set(password)
            self.evaluate_password_strength(password)
        else:
            messagebox.showwarning("Warning", "Please select a password from history!")
    
    def clear_history(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to clear the password history?"):
            self.password_history.clear()
            self.history_listbox.delete(0, tk.END)
            messagebox.showinfo("Success", "Password history cleared!")

def main():
    try:
        import pyperclip
    except ImportError:
        print("Note: pyperclip not installed. Clipboard functionality will use tkinter fallback.")
    
    root = tk.Tk()
    app = PasswordGenerator(root)
    root.mainloop()

if __name__ == "__main__":
    main()
