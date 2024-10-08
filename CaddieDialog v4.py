import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import json


class GolfStringReaderApp:
    start_addresses = {
        0xB064,
        0xB0DA,
        0xB234,
        0xBC20
    }
    start_address_offsets = {
        0x00: 144,
        0x18: 1,
        0x24: 1,
        0x30: 1,
        0x5E: 8,
        0xD4: 1,
        0xE6: 1,
        0xF4: 1,
        0xFE: 1,
        0x108: 1,
        0x112: 1,
        0x11C: 1,
        0x142: 1,
        0x150: 1,
        0x15E: 1,
        0x168: 1,
        0x174: 1,
        0x180: 1,
        0x188: 1,
        0x194: 1,
        0x1A0: 1,
        0x1A8: 1,
        0x1B0: 1,
        0x1B8: 1,
        0x1C0: 1,
        0x1C8: 1,
        0x1D0: 1,
        0x1D8: 1,
        0x1E0: 1,
        0x1F8: 32,
        0x206: 1,
        0x214: 1
    }
    FIRST_BYTE_MAPPING = {"00": "None", "01": "Smile", "02": "Frown"}
    loaded_filepath = None

    def __init__(self, root):
        self.root = root
        self.root.title("T&E Golf Editor")
        self.string_data = []
        self.first_byte_var = tk.StringVar(value="")
        self.base_address = None
        self.current_string_index = 0
        self.create_menu()
        self.create_string_display()
        self.create_controls()

        try:
            with open("Translation.json", encoding="utf-8") as f:
                self.CHAR_MAP = json.load(f)
            self.REVERSED_CHAR_MAP = {v: k for k, v in self.CHAR_MAP.items()}  # Create reversed map here
        except (FileNotFoundError, json.JSONDecodeError) as e:
            messagebox.showerror("Error", f"Problem loading Translation.json: {e}")
            self.root.quit()

    def create_menu(self):
        menubar = tk.Menu(self.root)

        # File menu
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Load Bin", command=self.load_bin)
        filemenu.add_command(label="Save Bin", command=self.save_bin)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=filemenu)

        # Options menu
        optionsmenu = tk.Menu(menubar, tearoff=0)
        # Caddie Menus (Submenu)
        caddiemenu = tk.Menu(optionsmenu, tearoff=0)
        for i in range(1, 9):
            caddiemenu.add_command(label=f"Caddie {i}", command=lambda c=i: self.display_caddie_strings(c))
        optionsmenu.add_cascade(label="Display Caddie Advice", menu=caddiemenu)
        optionsmenu.add_command(label="Display All Advice", command=self.display_hole_strings)
        optionsmenu.add_command(label="Display Shared Dialog", command=self.display_shared_strings)
        optionsmenu.add_separator()
        optionsmenu.add_command(label="Display All Strings", command=self.display_all_strings)
        menubar.add_cascade(label="Options", menu=optionsmenu)

        self.root.config(menu=menubar)

    def create_string_display(self):
        self.string_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=24, height=10)
        self.string_text.grid(row=0, column=0, columnspan=4, padx=20, pady=10, sticky="nsew")

        ttk.Label(self.root, text="String: ").grid(row=2, column=0, padx=1, pady=(0, 10), sticky="e")
        self.string_num_var = tk.StringVar()
        self.string_num_dropdown = ttk.Combobox(self.root, textvariable=self.string_num_var, state="readonly", width=8,
                                                height=8)
        self.string_num_dropdown.grid(row=2, column=1, padx=(0, 5), pady=(0, 10), sticky="w")
        self.string_num_dropdown.bind("<<ComboboxSelected>>", self.on_string_select)

        self.total_string_label = ttk.Label(self.root, text="")
        self.total_string_label.grid(row=2, column=1, padx=(50, 5), pady=(0, 10), sticky="w")

        ttk.Label(self.root, text="Address:").grid(row=2, column=2, padx=1, pady=(0, 10), sticky="e")
        self.address_label = ttk.Label(self.root, text="")  # Initialize address_label
        self.address_label.grid(row=2, column=3, padx=0, pady=(0, 10), sticky="w")

        # Text box for loaded filename
        ttk.Label(self.root, text="File:").grid(row=3, column=0, pady=5, sticky="e")
        self.loaded_file_entry = ttk.Entry(self.root, width=24)  # Text box (Entry widget)
        self.loaded_file_entry.grid(row=3, column=1, columnspan=3, pady=5, sticky="w")
        self.loaded_file_entry.state(['readonly'])  # Make it read-only

        self.update_controls()
        self.update_string_display()

    def create_controls(self):
        button_frame = ttk.Frame(self.root)
        button_frame.grid(row=1, column=0, columnspan=4, padx=10, pady=10)

        ttk.Button(button_frame, text="Submit Changes", command=self.submit_changes).pack(side=tk.LEFT)

        # First Byte Dropdown (within button_frame)
        ttk.Label(button_frame, text="Face:").pack(side=tk.LEFT, padx=(10, 1))
        self.first_byte_var = tk.StringVar(value="None")
        self.first_byte_dropdown = ttk.Combobox(button_frame, textvariable=self.first_byte_var,
                                                values=list(self.FIRST_BYTE_MAPPING.values()), state="readonly",
                                                width=6)
        self.first_byte_dropdown.pack(side=tk.LEFT)

        self.update_controls()

    def update_controls(self):
        self.string_num_dropdown['values'] = [i + 1 for i in range(len(self.string_data))]
        if self.string_data:
            self.string_num_var.set(self.current_string_index + 1)
        else:
            self.string_num_var.set("")

    def load_bin(self):
        filepath = filedialog.askopenfilename(filetypes=[("BIN files", "*.bin")])
        if not filepath:
            return  # User canceled

        previous_data = self.string_data.copy()  # Backup in case of errors
        self.string_data = []

        try:
            self.read_strings(filepath)  # Read from the specified addresses
        except Exception as e:
            messagebox.showerror("Load Error", f"An error occurred while loading: {e}")
            self.string_data = previous_data  # Restore on any error
            return

        if not self.string_data:
            messagebox.showwarning("Load Failed", "No strings found at all specified addresses.")
        else:
            self.loaded_filepath = filepath
            self.current_string_index = 0

            # Update the filename in the text box
            last_slash_index = max(filepath.rfind("/"), filepath.rfind("\\"))
            filename = filepath[last_slash_index + 1:]
            self.loaded_file_entry.config(state='normal')
            self.loaded_file_entry.delete(0, tk.END)
            self.loaded_file_entry.insert(0, filename)
            self.loaded_file_entry.config(state='readonly')

            self.update_string_display()
            self.update_controls()

    def read_strings(self, filepath):
        string_data = []

        with open(filepath, "rb") as f:
            string_num = 1

            for base_address in self.start_addresses:
                all_checks_passed = True
                for offset in self.start_address_offsets.keys():  # Iterate over offsets
                    num_strings = self.start_address_offsets[offset]
                    absolute_address = base_address + offset
                    f.seek(absolute_address)

                    hex_check = f.read(2).hex().upper()
                    if hex_check != "41F9":
                        all_checks_passed = False
                        break

                    offset_size = 4
                    address_offset = 0
                    first_byte_size = 1

                    if num_strings > 1:
                        string_address_list_start = int.from_bytes(f.read(4), byteorder='big')
                        f.seek(string_address_list_start)
                        if num_strings == 144:
                            offset_size = 2
                            address_offset = string_address_list_start
                            first_byte_size = 0

                    string_address_bytes = f.read(offset_size * num_strings)
                    string_addresses = [
                        int.from_bytes(string_address_bytes[i: i + offset_size], byteorder='big') + address_offset
                        for i in range(0, len(string_address_bytes), offset_size)
                    ]

                    for string_address in string_addresses:
                        f.seek(string_address)
                        first_byte = f.read(first_byte_size).hex().upper()
                        hex_string = ""
                        while (byte := f.read(1).hex().upper()) and byte != "00":
                            hex_string += byte
                        string_data.append((string_address, first_byte, hex_string, string_num))
                        string_num += 1

                if all_checks_passed:
                    self.string_data = string_data
                    self.base_address = base_address
                    return

    def display_caddie_strings(self, caddie_num):
        if not self.string_data:
            messagebox.showinfo(f"Display Caddie {caddie_num} Hole Strings", "No strings loaded.")
            return

        caddie_strings_window = tk.Toplevel(self.root)
        caddie_strings_window.title(f"Caddie {caddie_num} Hole Strings")

        text_area = scrolledtext.ScrolledText(caddie_strings_window, wrap=tk.WORD, width=60, height=20)
        text_area.pack(expand=True, fill="both")

        for address, first_byte, hex_string, string_num in self.string_data:
            if 1 <= string_num <= 144 and (string_num - 1) % 8 + 1 == caddie_num:
                hole_number = (string_num - 1) // 8 + 1
                decoded_string = self.decode_hex_string(hex_string)
                output_str = f"String {string_num} - Hole {hole_number}: 0x{address:X}\n{decoded_string}\n\n"
                text_area.insert(tk.END, output_str)

    def display_hole_strings(self):
        if not self.string_data:
            messagebox.showinfo("Display Hole Strings", "No strings loaded.")
            return

        hole_strings_window = tk.Toplevel(self.root)
        hole_strings_window.title("Hole Strings (1-144)")

        text_area = scrolledtext.ScrolledText(hole_strings_window, wrap=tk.WORD, width=60, height=20)
        text_area.pack(expand=True, fill="both")

        for address, first_byte, hex_string, string_num in self.string_data:
            if 1 <= string_num <= 144:  # Check if within the hole strings range
                hole_number = (string_num - 1) // 8 + 1  # Calculate hole number (1-based index)
                caddie_number = (string_num - 1) % 8 + 1   # Calculate caddie number (1-based index)
                decoded_string = self.decode_hex_string(hex_string)
                output_str = (f"String {string_num} - 0x{address:X} - "
                              f"Hole {hole_number} Caddie {caddie_number}:\n{decoded_string}\n\n")
                text_area.insert(tk.END, output_str)

    def display_shared_strings(self):
        if not self.string_data:
            messagebox.showinfo("Display Shared Strings", "No strings loaded.")
            return

        shared_strings_window = tk.Toplevel(self.root)
        shared_strings_window.title("Shared Strings (After 144)")

        text_area = scrolledtext.ScrolledText(shared_strings_window, wrap=tk.WORD, width=60, height=20)
        text_area.pack(expand=True, fill="both")

        for address, first_byte, hex_string, string_num in self.string_data:
            if string_num > 144:  # Only display strings after 144
                decoded_string = self.decode_hex_string(hex_string)
                face_expression = self.FIRST_BYTE_MAPPING.get(first_byte, "Unknown")  # Get face expression
                output_str = f"String {string_num} - 0x{address:X} ({face_expression}):\n{decoded_string}\n\n"
                text_area.insert(tk.END, output_str)

    def display_all_strings(self):
        if not self.string_data:
            messagebox.showinfo("Display All", "No strings loaded.")
            return

        all_strings_window = tk.Toplevel(self.root)
        all_strings_window.title("All Strings")

        text_area = scrolledtext.ScrolledText(all_strings_window, wrap=tk.WORD, width=60, height=20)
        text_area.pack(expand=True, fill="both")

        for address, first_byte, hex_string, string_num in self.string_data:
            decoded_string = self.decode_hex_string(hex_string)

            if 1 <= string_num <= 144:  # Check if within the hole strings range
                hole_number = (string_num - 1) // 8 + 1  # Calculate hole number (1-based index)
                caddie_number = (string_num - 1) % 8 + 1  # Calculate caddie number (1-based index)
                output_str = (f"String {string_num} - 0x{address:X} - "
                              f"Hole {hole_number} Caddie {caddie_number}:\n{decoded_string}\n\n")
            else:
                face_expression = self.FIRST_BYTE_MAPPING.get(first_byte, "Unknown")  # Get face expression
                output_str = f"String {string_num} - 0x{address:X} ({face_expression}):\n{decoded_string}\n\n"

            text_area.insert(tk.END, output_str)

    def submit_changes(self):
        new_string = self.string_text.get(1.0, tk.END).strip("\n")
        hex_string = "".join(self.REVERSED_CHAR_MAP.get(char, "2E") for char in new_string)
        while hex_string and hex_string[-2:] in ("20", "A0", "0A"):
            hex_string = hex_string[:-2]

        old_address, old_first_byte, old_hex_string, string_num = self.string_data[self.current_string_index]

        if old_first_byte == "FF":  # Check if the original first byte is FF
            messagebox.showinfo("Cannot Modify", "This string cannot be modified.")
            return  # Exit the function without making any changes

        # Check if the original first byte was empty ("")
        if not old_first_byte:
            new_first_byte = ""  # Keep it empty if it was originally empty
        else:
            # Otherwise, get the new first byte based on the dropdown selection
            new_first_byte = next(
                (key for key, value in self.FIRST_BYTE_MAPPING.items() if value == self.first_byte_var.get()), "00")

        self.string_data[self.current_string_index] = (old_address, new_first_byte, hex_string, string_num)
        self.update_string_display()
        self.update_controls()

    def on_string_select(self, event=None):
        selected_value = self.string_num_var.get()
        self.current_string_index = int(selected_value) - 1
        self.update_string_display()

    def update_string_display(self):
        if self.string_data:
            address, first_byte, hex_string, string_num = self.string_data[self.current_string_index]

            decoded_string = self.decode_hex_string(hex_string)

            self.string_text.delete(1.0, tk.END)
            self.string_text.insert(tk.END, decoded_string)

            self.address_label.config(text=f"0x{address:X}")

            display_text = self.FIRST_BYTE_MAPPING.get(first_byte, "None")
            self.first_byte_var.set(display_text)

            # Disable dropdown if first byte is "FF" or blank
            if first_byte in ("FF", ""):
                self.first_byte_dropdown.config(state="disabled")
            else:
                self.first_byte_dropdown.config(state="readonly")

        else:
            self.string_text.delete(1.0, tk.END)
            self.address_label.config(text="")
            self.string_num_var.set("")
            self.total_string_label.config(text="")
            self.first_byte_var.set("None")

    def decode_hex_string(self, hex_string):
        decoded_string = ""
        skip_next_byte = False
        for i, byte in enumerate(bytes.fromhex(hex_string.replace('"', ''))):
            if skip_next_byte:
                skip_next_byte = False
                continue
            hex_value = f"{byte:02X}"
            if hex_value == "FE" and i < len(hex_string) - 1:
                next_byte = bytes.fromhex(hex_string.replace('"', ''))[i + 1]
                hex_value += f"{next_byte:02X}"
                skip_next_byte = True
            decoded_string += self.CHAR_MAP.get(hex_value, f"0x{hex_value}.")
        return decoded_string

    def save_bin(self):
        if not self.loaded_filepath or not self.string_data:
            messagebox.showerror("Error", "No file loaded or no strings to save.")
            return

        try:
            with (open(self.loaded_filepath, "rb") as
                  original_file, open(self.loaded_filepath + ".bak", "wb") as backup_file):
                backup_file.write(original_file.read())

            with open(self.loaded_filepath, "r+b") as f:
                offset_items = self.start_address_offsets.items()
                string_num = 0
                f.seek(self.base_address)
                hex_check = f.read(2).hex().upper()
                if hex_check != "41F9":
                    raise ValueError("Invalid marker at expected location.")
                else:
                    current_string_address = int.from_bytes(f.read(4), byteorder='big')

                for offset, num_strings in offset_items:
                    absolute_address = self.base_address + offset
                    f.seek(absolute_address)
                    hex_check = f.read(2).hex().upper()
                    if hex_check != "41F9":
                        raise ValueError("Invalid marker at expected location.")
                    else:
                        if num_strings > 1 and current_string_address % 2 != 0:
                            current_string_address += 1
                        f.write(current_string_address.to_bytes(4, byteorder='big'))
                        f.seek(current_string_address)

                    if num_strings > 1:
                        if num_strings == 144:
                            offset_size = 2
                            current_offset = num_strings * 2
                        else:
                            offset_size = 4
                            current_offset = (num_strings * 4) + current_string_address

                        for i in range(num_strings):
                            _, first_byte, hex_string, _ = self.string_data[i + string_num]
                            f.write(current_offset.to_bytes(offset_size, byteorder='big'))
                            string_bytes = bytes.fromhex(first_byte + hex_string + "00")
                            current_offset += len(string_bytes)

                    for i in range(num_strings):
                        _, first_byte, hex_string, _ = self.string_data[string_num]
                        f.write(bytes.fromhex(first_byte + hex_string + "00"))
                        string_num += 1

                    current_string_address = f.tell()

            # Reload strings after saving
            self.read_strings(self.loaded_filepath)
            self.update_string_display()  # Refresh the display
            self.update_controls()  # Update controls to match the new data

        except Exception as e:
            messagebox.showerror("Save Error", f"An error occurred while saving: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = GolfStringReaderApp(root)
    root.mainloop()