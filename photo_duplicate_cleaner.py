import os
import hashlib
import shutil
import threading
import queue
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk


def file_hash(path, block_size=65536):
    """Υπολογισμός hash αρχείου για ακριβή σύγκριση περιεχομένου."""
    hasher = hashlib.md5()
    with open(path, "rb") as file:
        chunk = file.read(block_size)
        while chunk:
            hasher.update(chunk)
            chunk = file.read(block_size)
    return hasher.hexdigest()


def create_thumbnail(path, size=(120, 120)):
    """Δημιουργεί thumbnail για προεπισκόπηση."""
    try:
        img = Image.open(path)
        img.thumbnail(size)
        return ImageTk.PhotoImage(img)
    except:
        return None


class DuplicateCleanerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🧹 Duplicate Photo Cleaner")
        self.root.geometry("800x600")

        self.folder_path = tk.StringVar()
        self.log_queue = queue.Queue()
        self.thumbnail_cache = {}

        self.create_ui()
        self.poll_log_queue()

    # ----------- UI ---------------

    def create_ui(self):
        top_frame = tk.Frame(self.root)
        top_frame.pack(fill="x", pady=10)

        tk.Label(top_frame, text="Φάκελος:").pack(side="left")
        tk.Entry(top_frame, textvariable=self.folder_path, width=60).pack(side="left", padx=5)
        tk.Button(top_frame, text="📁 Browse", command=self.browse_folder).pack(side="left")

        action_frame = tk.LabelFrame(self.root, text="Τι να κάνω με τα διπλότυπα:")
        action_frame.pack(fill="x", padx=10, pady=10)

        self.action_var = tk.StringVar(value="delete")
        ttk.Radiobutton(action_frame, text="🗑 Διαγραφή", value="delete", variable=self.action_var).pack(anchor="w")
        ttk.Radiobutton(action_frame, text="📂 Μετακίνηση σε 'Duplicates'", value="move", variable=self.action_var).pack(anchor="w")

        tk.Button(self.root, text="🚀 Ξεκίνα σκανάρισμα", command=self.start_scan_thread).pack(pady=10)

        self.preview_canvas = tk.Canvas(self.root, bg="#f0f0f0", height=250)
        self.preview_canvas.pack(fill="both", expand=False, padx=10, pady=10)

        log_frame = tk.LabelFrame(self.root, text="Log")
        log_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.log_box = tk.Text(log_frame, height=10)
        self.log_box.pack(fill="both", expand=True)

    # ---------- File System ----------

    def browse_folder(self):
        path = filedialog.askdirectory()
        if path:
            self.folder_path.set(path)

    def start_scan_thread(self):
        t = threading.Thread(target=self.scan_duplicates, daemon=True)
        t.start()

    def scan_duplicates(self):
        folder = self.folder_path.get()
        if not folder or not os.path.isdir(folder):
            messagebox.showerror("Σφάλμα", "Δώσε έγκυρο φάκελο.")
            return

        action = self.action_var.get()
        duplicates_folder = os.path.join(folder, "Duplicates")
        if action == "move" and not os.path.exists(duplicates_folder):
            os.mkdir(duplicates_folder)

        hashes = {}
        duplicates = []
        deleted = 0
        moved = 0

        self.log(f"🔍 Σάρωση: {folder}")

        # Β' πέρασμα: hashing
        for root, _, files in os.walk(folder):
            for file in files:
                path = os.path.join(root, file)

                if "Duplicates" in path:
                    continue

                try:
                    h = file_hash(path)

                    if h in hashes:
                        duplicates.append(path)
                    else:
                        hashes[h] = path

                except Exception as e:
                    self.log(f"⚠️ Σφάλμα στο {path}: {e}")

        self.preview_duplicates(duplicates)

        # Γ' πέρασμα: cleanup
        for path in duplicates:
            try:
                if action == "delete":
                    os.remove(path)
                    deleted += 1
                    self.log(f"🗑 Deleted: {path}")
                else:
                    dest = os.path.join(duplicates_folder, os.path.basename(path))
                    shutil.move(path, dest)
                    moved += 1
                    self.log(f"📂 Moved: {path}")
            except Exception as e:
                self.log(f"⚠️ Σφάλμα στο {path}: {e}")

        summary = f"✔ Ολοκληρώθηκε — {deleted} διαγραφές, {moved} μετακινήσεις"
        self.log(summary)
        messagebox.showinfo("Ολοκληρώθηκε", summary)

    # ---------- Preview UI ----------

    def preview_duplicates(self, duplicates):
        self.preview_canvas.delete("all")
        self.thumbnail_cache.clear()

        x, y, padding = 10, 10, 10

        for path in duplicates[:12]:  # δείχνουμε max 12
            thumb = create_thumbnail(path)
            if thumb:
                self.thumbnail_cache[path] = thumb
                self.preview_canvas.create_image(x, y, image=thumb, anchor="nw")
                x += 130
                if x > 750:
                    x = 10
                    y += 140

    # ---------- Logging ----------

    def log(self, msg):
        self.log_queue.put(msg)

    def poll_log_queue(self):
        try:
            while True:
                msg = self.log_queue.get_nowait()
                self.log_box.insert("end", msg + "\n")
                self.log_box.see("end")
        except queue.Empty:
            pass
        self.root.after(100, self.poll_log_queue)


# ----------- MAIN ------------

if __name__ == "__main__":
    root = tk.Tk()
    app = DuplicateCleanerApp(root)
    root.mainloop()
