import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import os
import hashlib
import json
import time
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging
from pathlib import Path
import queue
import threading

class FileIntegrityMonitor:
    def __init__(self, directory_to_monitor):
        self.directory = directory_to_monitor
        self.baseline_file = "baseline.json"
        self.setup_logging()
        
    def setup_logging(self):
        """Configure logging for the application"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('file_monitor.log'),
                logging.StreamHandler()
            ]
        )
    
    def calculate_file_hash(self, filepath):
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logging.error(f"Error calculating hash for {filepath}: {e}")
            return None

    def create_baseline(self):
        """Create a baseline of all files and their hashes"""
        baseline = {}
        for root, _, files in os.walk(self.directory):
            for file in files:
                filepath = os.path.join(root, file)
                file_hash = self.calculate_file_hash(filepath)
                if file_hash:
                    baseline[filepath] = {
                        'hash': file_hash,
                        'timestamp': datetime.now().isoformat()
                    }
        
        with open(self.baseline_file, 'w') as f:
            json.dump(baseline, f, indent=4)
        
        logging.info(f"Baseline created with {len(baseline)} files")
        return baseline

    def load_baseline(self):
        """Load the existing baseline if it exists"""
        try:
            with open(self.baseline_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logging.warning("No baseline found. Creating new baseline...")
            return self.create_baseline()

class FileChangeHandler(FileSystemEventHandler):
    def __init__(self, monitor):
        self.monitor = monitor
        self.baseline = monitor.load_baseline()

    def on_modified(self, event):
        if event.is_directory:
            return
        filepath = event.src_path
        new_hash = self.monitor.calculate_file_hash(filepath)
        if filepath in self.baseline:
            old_hash = self.baseline[filepath]['hash']
            if new_hash != old_hash:
                logging.warning(f"File modified: {filepath}")
                logging.warning(f"Old hash: {old_hash}")
                logging.warning(f"New hash: {new_hash}")
                self.baseline[filepath] = {
                    'hash': new_hash,
                    'timestamp': datetime.now().isoformat()}
                with open(self.monitor.baseline_file, 'w') as f:
                    json.dump(self.baseline, f, indent=4)

    def on_created(self, event):
        if event.is_directory:
            return
            
        filepath = event.src_path
        file_hash = self.monitor.calculate_file_hash(filepath)
        logging.warning(f"New file created: {filepath}")
        logging.warning(f"Hash: {file_hash}")
        
        # Update baseline
        self.baseline[filepath] = {
            'hash': file_hash,
            'timestamp': datetime.now().isoformat()
        }
        with open(self.monitor.baseline_file, 'w') as f:
            json.dump(self.baseline, f, indent=4)

    def on_deleted(self, event):
        if event.is_directory:
            return
            
        filepath = event.src_path
        if filepath in self.baseline:
            logging.warning(f"File deleted: {filepath}")
            del self.baseline[filepath]
            with open(self.monitor.baseline_file, 'w') as f:
                json.dump(self.baseline, f, indent=4)

class FileMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("File Integrity Monitor")
        self.root.geometry("800x600")
        
        # Create a queue for thread-safe logging
        self.log_queue = queue.Queue()
        
        # Initialize monitoring state
        self.is_monitoring = False
        self.observer = None
        self.monitor = None
        
        self.create_gui()
        self.setup_logging()
        
        # Start queue checking
        self.check_log_queue()

        main_frame =x

    def create_gui(self):
        ttk.Label(main_frame, text="Directory to Monitor:").grid(row=0, column=0, sticky=tk.W)
        self.dir_var = tk.StringVar()
        dir_entry = ttk.Entry(main_frame, textvariable=self.dir_var, width=50)
        dir_entry.grid(row=0, column=1, padx=5, sticky=(tk.W, tk.E))
        ttk.Button(main_frame, text="Browse", command=self.browse_directory).grid(row=0, column=2)
        
        # Control buttons
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=1, column=0, columnspan=3, pady=10)
        main_frame =x
        self.start_button = ttk.Button(control_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(control_frame, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(control_frame, text="View Baseline", command=self.view_baseline).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Create New Baseline", command=self.create_new_baseline).pack(side=tk.LEFT, padx=5)
        
        # Status indicator
        self.status_var = tk.StringVar(value="Status: Not Monitoring")
        status_label = ttk.Label(main_frame, textvariable=self.status_var)
        status_label.grid(row=2, column=0, columnspan=3, pady=5)
        
        # Log display
        log_frame = ttk.LabelFrame(main_frame, text="Activity Log", padding="5")
        log_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=20, width=80)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure grid weights
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(3, weight=1)

    def setup_logging(self):
        class QueueHandler(logging.Handler):
            def __init__(self, queue):
                super().__init__()
                self.queue = queue

            def emit(self, record):
                self.queue.put(record)

        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('file_monitor.log'),
                QueueHandler(self.log_queue)
            ]
        )

    def check_log_queue(self):
        """Check for new log records"""
        while True:
            try:
                record = self.log_queue.get_nowait()
                self.log_text.insert(tk.END, f"{record.asctime} - {record.levelname} - {record.getMessage()}\n")
                self.log_text.see(tk.END)
            except queue.Empty:
                break
        self.root.after(100, self.check_log_queue)

    def browse_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.dir_var.set(directory)

    def start_monitoring(self):
        if not self.dir_var.get():
            messagebox.showerror("Error", "Please select a directory to monitor")
            return
            
        self.monitor = FileIntegrityMonitor(self.dir_var.get())
        self.event_handler = FileChangeHandler(self.monitor)
        self.observer = Observer()
        self.observer.schedule(self.event_handler, self.dir_var.get(), recursive=True)
        
        self.observer.start()
        self.is_monitoring = True
        self.status_var.set("Status: Monitoring Active")
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        logging.info(f"Started monitoring directory: {self.dir_var.get()}")

    def stop_monitoring(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.is_monitoring = False
            self.status_var.set("Status: Not Monitoring")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            logging.info("Monitoring stopped")

    def view_baseline(self):
        if not self.dir_var.get():
            messagebox.showerror("Error", "Please select a directory first")
            return
            
        if not self.monitor:
            self.monitor = FileIntegrityMonitor(self.dir_var.get())
        
        baseline = self.monitor.load_baseline()
        
        # Create new window to display baseline
        baseline_window = tk.Toplevel(self.root)
        baseline_window.title("Baseline Data")
        baseline_window.geometry("600x400")
        
        text_widget = scrolledtext.ScrolledText(baseline_window, width=70, height=20)
        text_widget.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # Format and display baseline data
        text_widget.insert(tk.END, json.dumps(baseline, indent=4))
        text_widget.config(state=tk.DISABLED)

    def create_new_baseline(self):
        if not self.dir_var.get():
            messagebox.showerror("Error", "Please select a directory first")
            return
            
        if not self.monitor:
            self.monitor = FileIntegrityMonitor(self.dir_var.get())
            
        self.monitor.create_baseline()
        messagebox.showinfo("Success", "New baseline created successfully")

def main():
    root = tk.Tk()
    app = FileMonitorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()