import os
import hashlib
import shutil
import threading
import queue
import csv
from datetime import datetime

# Προσπάθεια για drag & drop (tkinterdnd2 είναι προαιρετικό)
try:
    from tkinterdnd2 import DND_TEXT, TkinterDnD
    DND_AVAILABLE = True
except ImportError:
    DND_AVAILABLE = False

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from PIL import Image, ImageTk
from send2trash import send2trash


# ============== ΡΥΘΜΙΣΕΙΣ ΘΕΜΑΤΟΣ (DARK THEME) ==============

BG_COLOR = "#121212"
FG_COLOR = "#f2f2f2"
ACCENT_COLOR = "#3f51b5"
PANEL_COLOR = "#1e1e1e"
LOG_BG = "#000000"
LOG_FG = "#00ff99"


def file_hash(path, block_size=65536):
    """Υπολογισμός MD5 hash για ακριβή σύγκριση περιεχομένου αρχείων."""
    hasher = hashlib.md5()
    with open(path, "rb") as file:
        chunk = file.read(block_size)
        while chunk:
            hasher.update(chunk)
            chunk = file.read(block_size)
    return hasher.hexdigest()


def create_thumbnail(path, size=(120, 120)):
    """Δημιουργεί thumbnail για προεπισκόπηση εικόνας."""
    try:
        img = Image.open(path)
        img.thumbnail(size)
        return ImageTk.PhotoImage(img)
    except Exception:
        return None


class DuplicateDetoxApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Duplicate Detox 🧹")
        self.root.geometry("900x650")
        self.root.configure(bg=BG_COLOR)

        self.folder_path = tk.StringVar()
        self.action_var = tk.StringVar(value="trash")  # 'trash' ή 'move'
        self.log_queue = queue.Queue()
        self.thumbnail_cache = {}
        self.last_results = []  # λίστα dicts για export

        self._setup_style()
        self._create_ui()
        self._poll_log_queue()

    # ========== UI / THEME ==========

    def _setup_style(self):
        style = ttk.Style()
        # Κάποια themes δεν παίζουν καλά με dark, οπότε πάμε σε 'clam'
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure("TFrame", background=BG_COLOR)
        style.configure("TLabelframe", background=BG_COLOR, foreground=FG_COLOR)
        style.configure("TLabelframe.Label", background=BG_COLOR, foreground=FG_COLOR)
        style.configure("TLabel", background=BG_COLOR, foreground=FG_COLOR)
        style.configure("TButton", background=ACCENT_COLOR, foreground=FG_COLOR)
        style.map("TButton", background=[("active", "#5c6bc0")])
        style.configure("TRadiobutton", background=BG_COLOR, foreground=FG_COLOR)

    def _create_ui(self):
        # Top bar
        top_frame = ttk.Frame(self.root)
        top_frame.pack(fill="x", padx=10, pady=10)

        title_lbl = ttk.Label(top_frame, text="Duplicate Detox", font=("Helvetica", 16, "bold"))
        title_lbl.pack(side="left")

        # Folder selector
        folder_frame = ttk.Frame(self.root)
        folder_frame.pack(fill="x", padx=10, pady=5)

        lbl = ttk.Label(folder_frame, text="Φάκελος:")
        lbl.pack(side="left")

        EntryClass = tk.Entry if not DND_AVAILABLE else tk.Entry  # θα δηλώσουμε DND πιο κάτω
        self.folder_entry = EntryClass(folder_frame, textvariable=self.folder_path, width=60,
                                       bg=PANEL_COLOR, fg=FG_COLOR, insertbackground=FG_COLOR,
                                       relief="flat")
        self.folder_entry.pack(side="left", padx=5)

        if DND_AVAILABLE:
            # Ενεργοποίηση drag & drop στο entry
            self.folder_entry.drop_target_register(DND_TEXT)
            self.folder_entry.dnd_bind("<<Drop>>", self._on_drop)

        browse_btn = ttk.Button(folder_frame, text="📁 Browse", command=self.browse_folder)
        browse_btn.pack(side="left")

        if DND_AVAILABLE:
            dnd_lbl = ttk.Label(folder_frame, text="(Drag & Drop υποστηρίζεται)", foreground="#bbbbbb")
            dnd_lbl.pack(side="left", padx=5)

        # Action options
        action_frame = ttk.LabelFrame(self.root, text="Ενέργεια σε διπλότυπα", padding=10)
        action_frame.pack(fill="x", padx=10, pady=10)

        rb1 = ttk.Radiobutton(action_frame, text="🗑 Safe delete (στο Trash / Κάδο)",
                              value="trash", variable=self.action_var)
        rb1.pack(anchor="w")

        rb2 = ttk.Radiobutton(action_frame, text="📂 Μετακίνηση σε φάκελο 'Duplicates' στον ίδιο φάκελο",
                              value="move", variable=self.action_var)
        rb2.pack(anchor="w")

        # Buttons
        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(fill="x", padx=10, pady=5)

        scan_btn = ttk.Button(btn_frame, text="🚀 Scan & Clean", command=self.start_scan_thread)
        scan_btn.pack(side="left")

        export_btn = ttk.Button(btn_frame, text="📄 Export report (CSV)", command=self.export_report)
        export_btn.pack(side="left", padx=5)

        # Preview area
        preview_frame = ttk.LabelFrame(self.root, text="Preview διπλότυπων (τυχαία έως 12)", padding=5)
        preview_frame.pack(fill="both", expand=False, padx=10, pady=10)

        self.preview_canvas = tk.Canvas(preview_frame, bg=PANEL_COLOR, height=260, highlightthickness=0)
        self.preview_canvas.pack(fill="both", expand=True)

        # Log area
        log_frame = ttk.LabelFrame(self.root, text="Log", padding=5)
        log_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.log_box = tk.Text(log_frame, height=10, bg=LOG_BG, fg=LOG_FG,
                               insertbackground=FG_COLOR, relief="flat")
        self.log_box.pack(fill="both", expand=True)

    # ========== DRAG & DROP ==========

    def _on_drop(self, event):
        # Μερικές φορές έρχεται με άγκιστρα {}
        path = event.data.strip()
        if path.startswith("{") and path.endswith("}"):
            path = path[1:-1]
        if os.path.isdir(path):
            self.folder_path.set(path)

    # ========== FILE SYSTEM & SCAN ==========

    def browse_folder(self):
        path = filedialog.askdirectory()
        if path:
            self.folder_path.set(path)

    def start_scan_thread(self):
        t = threading.Thread(target=self.scan_and_clean, daemon=True)
        t.start()

    def scan_and_clean(self):
        folder = self.folder_path.get()
        if not folder or not os.path.isdir(folder):
            messagebox.showerror("Σφάλμα", "Δώσε έγκυρο φάκελο.")
            return

        action = self.action_var.get()
        duplicates_folder = os.path.join(folder, "Duplicates")

        if action == "move":
            os.makedirs(duplicates_folder, exist_ok=True)

        self.log(f"🔍 Σάρωση φακέλου: {folder}")

        hash_to_paths = {}
        total_files = 0

        # Πρώτο πέρασμα: μετράμε αρχεία (για μελλοντικό progress αν χρειαστεί)
        for root_dir, _, files in os.walk(folder):
            for _ in files:
                total_files += 1

        # Δεύτερο πέρασμα: hash και εύρεση διπλότυπων
        processed = 0
        for root_dir, _, files in os.walk(folder):
            for filename in files:
                path = os.path.join(root_dir, filename)

                # αγνοούμε τον φάκελο Duplicates
                rel = os.path.relpath(path, folder)
                if "Duplicates" in rel.split(os.sep):
                    continue

                processed += 1

                try:
                    h = file_hash(path)
                    if h in hash_to_paths:
                        hash_to_paths[h].append(path)
                    else:
                        hash_to_paths[h] = [path]
                except Exception as e:
                    self.log(f"⚠️ Σφάλμα στο {path}: {e}")

        # Φτιάχνουμε λίστα διπλοτύπων (εκτός του πρώτου ως original)
        duplicates = []
        self.last_results = []

        for file_hash_value, paths in hash_to_paths.items():
            if len(paths) > 1:
                original = paths[0]
                for dup in paths[1:]:
                    duplicates.append(dup)
                    size_bytes = os.path.getsize(dup)
                    size_kb = round(size_bytes / 1024, 2)
                    mtime = datetime.fromtimestamp(os.path.getmtime(dup)).isoformat(sep=" ", timespec="seconds")
                    self.last_results.append({
                        "original": original,
                        "duplicate": dup,
                        "size_kb": size_kb,
                        "mtime": mtime,
                    })

        if not duplicates:
            self.preview_canvas.delete("all")
            self.log("✅ Δεν βρέθηκαν διπλότυπα αρχεία.")
            messagebox.showinfo("Duplicate Detox", "Δεν βρέθηκαν διπλότυπα αρχεία.")
            return

        self.log(f"🔁 Βρέθηκαν {len(duplicates)} διπλότυπα αρχεία.")
        self.preview_duplicates(duplicates)

        # Εφαρμογή δράσης
        deleted = 0
        moved = 0

        for dup_path in duplicates:
            try:
                if action == "trash":
                    send2trash(dup_path)
                    deleted += 1
                    self.log(f"🗑 Στάλθηκε στον Κάδο: {dup_path}")
                else:
                    dest_path = os.path.join(duplicates_folder, os.path.basename(dup_path))
                    base, ext = os.path.splitext(dest_path)
                    counter = 1
                    while os.path.exists(dest_path):
                        dest_path = f"{base}_{counter}{ext}"
                        counter += 1
                    shutil.move(dup_path, dest_path)
                    moved += 1
                    self.log(f"📂 Μετακινήθηκε: {dup_path} → {dest_path}")
            except Exception as e:
                self.log(f"⚠️ Σφάλμα κατά την επεξεργασία {dup_path}: {e}")

        summary = f"✔ Ολοκληρώθηκε — {deleted} στον Κάδο, {moved} μετακινήσεις."
        self.log(summary)
        messagebox.showinfo("Duplicate Detox", summary)

    def preview_duplicates(self, duplicates):
        self.preview_canvas.delete("all")
        self.thumbnail_cache.clear()

        # Παίρνουμε μέχρι 12 για δείγμα
        show_list = duplicates[:12]

        x, y = 10, 10
        padding = 10

        for path in show_list:
            thumb = create_thumbnail(path)
            if not thumb:
                continue
            self.thumbnail_cache[path] = thumb
            self.preview_canvas.create_image(x, y, anchor="nw", image=thumb)
            self.preview_canvas.create_text(x, y + thumb.height() + 5, anchor="nw",
                                            text=os.path.basename(path),
                                            fill=FG_COLOR, font=("Arial", 8))
            x += thumb.width() + padding
            if x > 800:
                x = 10
                y += 140

    # ========== EXPORT REPORT ==========

    def export_report(self):
        if not self.last_results:
            messagebox.showinfo("Duplicate Detox", "Δεν υπάρχουν αποτελέσματα για export. Κάνε πρώτα ένα scan.")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if not save_path:
            return

        try:
            with open(save_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["original", "duplicate", "size_kb", "mtime"])
                for row in self.last_results:
                    writer.writerow([
                        row["original"],
                        row["duplicate"],
                        row["size_kb"],
                        row["mtime"],
                    ])
            self.log(f"📄 Report exported: {save_path}")
            messagebox.showinfo("Duplicate Detox", f"Report αποθηκεύτηκε:\n{save_path}")
        except Exception as e:
            self.log(f"⚠️ Σφάλμα στο export: {e}")
            messagebox.showerror("Duplicate Detox", f"Σφάλμα κατά το export:\n{e}")

    # ========== LOGGING ==========

    def log(self, text):
        self.log_queue.put(text)

    def _poll_log_queue(self):
        try:
            while True:
                msg = self.log_queue.get_nowait()
                self.log_box.insert("end", msg + "\n")
                self.log_box.see("end")
        except queue.Empty:
            pass
        self.root.after(100, self._poll_log_queue)


# ================== MAIN ==================

if __name__ == "__main__":
    if DND_AVAILABLE:
        from tkinterdnd2 import TkinterDnD
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()
    app = DuplicateDetoxApp(root)
    root.mainloop()
