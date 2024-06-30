import tkinter as tk
from tkinter import ttk
import subprocess
import os

class ExploitGUI:
    def __init__(self, root):
        self.root = root
        root.title("Buffer Overflow Exploit Visualization")
        
        # Set a default font
        default_font = ("Arial", 12)
        root.option_add("*Font", default_font)
        
        self.mainframe = ttk.Frame(root, padding="10 10 10 10")
        self.mainframe.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        
        self.payload_label = ttk.Label(self.mainframe, text="Enter Payload:")
        self.payload_label.grid(column=1, row=1, sticky=tk.W)
        
        self.payload_entry = ttk.Entry(self.mainframe, width=50)
        self.payload_entry.grid(column=2, row=1, sticky=(tk.W, tk.E))
        
        self.run_button = ttk.Button(self.mainframe, text="Run Exploit", command=self.run_exploit)
        self.run_button.grid(column=2, row=2, sticky=tk.W)
        
        self.output_text = tk.Text(self.mainframe, width=80, height=15, wrap='word')
        self.output_text.grid(column=1, row=3, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)

        self.buffer_vis = tk.Canvas(self.mainframe, width=800, height=150, bg="white")
        self.buffer_vis.grid(column=1, row=4, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)

        self.info_label = ttk.Label(self.mainframe, text="Buffer size: 64 bytes")
        self.info_label.grid(column=1, row=5, sticky=tk.W, pady=5)

        self.hex_label = ttk.Label(self.mainframe, text="Hexdump:")
        self.hex_label.grid(column=1, row=6, sticky=tk.W, pady=5)
        self.hex_label.grid_remove()  # Initially hidden
        
        self.hex_text = tk.Text(self.mainframe, width=80, height=5, wrap='none')
        self.hex_text.grid(column=1, row=7, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        self.hex_text.grid_remove()  # Initially hidden

        self.exp_label = ttk.Label(self.mainframe, wraplength=400, justify="left")
        self.exp_label.grid(column=1, row=8, columnspan=2, sticky=(tk.W, tk.E), pady=10)

        for child in self.mainframe.winfo_children(): 
            child.grid_configure(padx=5, pady=5)

        # Make the GUI resizable
        for i in range(3):
            self.mainframe.columnconfigure(i, weight=1)
        for i in range(9):
            self.mainframe.rowconfigure(i, weight=1)

    def run_exploit(self):
        payload = self.payload_entry.get()
        try:
            # Compile the C code
            compile_process = subprocess.run(['gcc', '-fno-stack-protector', '-z', 'execstack', '-o', 'exploit', 'exploit.c'], 
                                             capture_output=True, text=True, check=True)
            
            # Run the compiled executable
            process = subprocess.run(['./exploit', payload], capture_output=True, text=True)
            
            # Display the output in the GUI
            output = f'Payload: {payload}\n\n**********DEMONSTRATION RUNNING**********\n'
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, output)
            
            # Visualize the buffer
            self.visualize_buffer(payload)
            
            # Check if there was a segmentation fault
            if process.returncode != 0:
                self.output_text.insert(tk.END, "\n\nBuffer overflow successful!")
            
            # Add dynamic information
            self.add_dynamic_info(payload, process.returncode)
            
            # Show hexdump
            self.visualize_hexdump(payload)
            
        except subprocess.CalledProcessError as e:
            error_message = f'Compilation Error: {e.stderr}'
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, error_message)
        except Exception as e:
            error_message = f'Error: {str(e)}'
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, error_message)

    def visualize_buffer(self, payload):
        self.buffer_vis.delete("all")
        buffer_size = 64
        char_width = 10
        char_height = 20
        
        # Draw the buffer
        self.buffer_vis.create_rectangle(10, 10, 10 + buffer_size * char_width, 50, outline="black", fill="lightgray")
        
        # Fill the buffer with the payload
        for i, char in enumerate(payload[:buffer_size]):
            x = 10 + i * char_width
            color = "black" if i < buffer_size else "red"
            self.buffer_vis.create_text(x + char_width/2, 30, text=char, fill=color)
            
        # Show overflow
        if len(payload) > buffer_size:
            overflow_start = 10 + buffer_size * char_width
            self.buffer_vis.create_rectangle(overflow_start, 10, overflow_start + char_width * (len(payload) - buffer_size), 50, outline="red", fill="pink")
            for i, char in enumerate(payload[buffer_size:]):
                x = overflow_start + i * char_width
                self.buffer_vis.create_text(x + char_width/2, 30, text=char, fill="red")
            
            self.buffer_vis.create_text(400, 80, text="Buffer Overflow!", fill="red", font=("Arial", 14, "bold"))

        # Show explanation only if buffer overflow occurs
        if len(payload) > buffer_size:
            self.show_explanation()
        else:
            self.exp_label.config(text="")

    def visualize_hexdump(self, payload):
        self.hex_label.grid()  # Make hexdump label visible
        self.hex_text.grid()   # Make hexdump text visible
        
        hexdump = ' '.join([f'{ord(c):02x}' for c in payload])
        formatted_hexdump = ''
        for i, hex_byte in enumerate(hexdump.split()):
            if i % 16 == 0 and i != 0:
                formatted_hexdump += '\n'
            formatted_hexdump += hex_byte + ' '
            if i == 63:
                formatted_hexdump += '| '

        self.hex_text.delete(1.0, tk.END)
        self.hex_text.insert(tk.END, formatted_hexdump)
        
        # Highlight overflow bytes
        if len(payload) > 64:
            self.hex_text.tag_configure("overflow", foreground="red")
            start = "1.{}".format(64 * 3)  # 3 characters per byte (2 hex + 1 space)
            self.hex_text.tag_add("overflow", start, tk.END)

    def show_explanation(self):
        explanation = (
            "Buffer Overflow Explanation:\n"
            "1. The buffer is 64 bytes long.\n"
            "2. Input exceeded 64 bytes due to which there was overflow into adjacent memory.\n"
            "3. This can lead to execution of arbitrary code, denial of service, or unauthorized access, depending on how the program handles the overflow\n"
            "4. This can overwrite important data like return addresses. An attacker can use this to execute arbitrary code.\n"
        )
        self.exp_label.config(text=explanation)

    def add_dynamic_info(self, payload, return_code):
        info = f"\nPayload length: {len(payload)} bytes\n"
        info += f"Buffer size: 64 bytes\n"
        if len(payload) > 64:
            info += f"Overflow: {len(payload) - 64} bytes\n"
        info += f"Program return code: {return_code}\n"
        if return_code != 0:
            info += "Segmentation fault occurred, indicating successful buffer overflow.\n"
        else:
            info += "Program executed without crashing.\n"
        self.output_text.insert(tk.END, info)

if __name__ == "__main__":
    root = tk.Tk()
    app = ExploitGUI(root)
    root.mainloop()