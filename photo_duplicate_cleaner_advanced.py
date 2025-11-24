import os
import hashlib
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image
import imagehash


def file_hash(path, block_size=65536):
    """Standard MD5 binary hash for exact duplicates."""
    hasher = hashlib.md5()
    with open(path, "rb") as file:
        buffer = file.read(block_size)
        while buffer:
            hasher.update(buffer)
            buffer = file.read(block_size)
    return hasher.hexdigest()


def perceptual_hash(path):
    """Perceptual hash for near-duplicate images."""
    try:
        img = Image.open(path)
        img_hash = imagehash.phash(img)
        return img_hash
    except:
        return None


class DuplicateFinderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("📁 Smart Photo Duplicate Cleaner")
        self.root.geometry("650x500")
        self.folder_path = tk.StringVar()

        self.create_widgets()

    def create_widgets(self):
        frame = tk.Frame(self.root)
        frame.pack(pady=10)

        tk.Label(frame, text="Επίλεξε φάκελο για σκανάρισμα:").pack()

        entry = tk.Entry(frame, textvariable=self.folder_path, width=50)
        entry.pack(pady=5)

        button = tk.Button(frame, text="Browse", command=self.browse_folder)
        button.pack()

        tk.Label(self.root, text="Τύπος Αναζήτησης:").pack(pady=5)

        self.mode = tk.StringVar(value="exact")
        ttk.Radiobutton(self.root, text="🔍 Exact Match (Ίδιο αρχείο)", variable=self.mode, value="exact").pack()
        ttk.Radiobutton(self.root, text="🧠 Smart Similarity (Σχεδόν ίδιες φωτο)", variable=self.mode, value="similar").pack()

        tk.Label(self.root, text="Ευαισθησία (0 = αυστηρό, 10 = πολύ χαλαρό):").pack(pady=5)

        self.threshold = tk.IntVar(value=5)
        tk.Scale(self.root, from_=0, to=10, orient=tk.HORIZONTAL, variable=self.threshold).pack()

        self.action_choice = tk.StringVar(value="delete")
        ttk.Radiobutton(self.root, text="🗑 Διαγραφή", variable=self.action_choice, value="delete").pack(pady=3)
        ttk.Radiobutton(self.root, text="📂 Μετακίνηση σε φάκελο 'Duplicates'", variable=self.action_choice, value="move").pack(pady=3)

        scan_button = tk.Button(self.root, text="🚀 Έναρξη", command=self.scan_duplicates)
        scan_button.pack(pady=10)

        self.log_box = tk.Text(self.root, height=12, width=75)
        self.log_box.pack(pady=10)

    def browse_folder(self):
        path = filedialog.askdirectory()
        if path:
            self.folder_path.set(path)

    def log(self, text):
        self.log_box.insert(tk.END, text + "\n")
        self.log_box.see(tk.END)

    def scan_duplicates(self):
        folder = self.folder_path.get()

        if not folder or not os.path.isdir(folder):
            messagebox.showerror("Σφάλμα", "Παρακαλώ επέλεξε έγκυρο φάκελο.")
            return

        self.log("🔎 Σκανάρισμα...")

        hashes = {}
        deleted_count = 0
        moved_count = 0

        log_file = os.path.join(folder, "duplicates_log.txt")
        duplicates_folder = os.path.join(folder, "Duplicates")

        if self.action_choice.get() == "move" and not os.path.exists(duplicates_folder):
            os.mkdir(duplicates_folder)

        with open(log_file, "w", encoding="utf-8") as log:

            for root_path, dirs, files in os.walk(folder):
                for filename in files:

                    file_path = os.path.join(root_path, filename)
                    img_hash = None

                    if self.mode.get() == "exact":
                        img_hash = file_hash(file_path)
                    else:
                        img_hash = perceptual_hash(file_path)

                    if img_hash is None:
                        continue

                    duplicate_found = False

                    for existing_hash, stored_path in hashes.items():
                        if self.mode.get() == "exact":
                            if img_hash == existing_hash:
                                duplicate_found = True
                                break
                        else:
                            diff = abs(img_hash - existing_hash)
                            if diff <= self.threshold.get():
                                duplicate_found = True
                                break

                    if duplicate_found:
                        action = self.action_choice.get()

                        if action == "delete":
                            os.remove(file_path)
                            deleted_count += 1
                            msg = f"🗑 Deleted duplicate: {file_path}"

                        else:
                            new_path = os.path.join(duplicates_folder, filename)
                            shutil.move(file_path, new_path)
                            moved_count += 1
                            msg = f"📂 Moved duplicate: {file_path}"

                        log.write(msg + "\n")
                        self.log(msg)

                    else:
                        hashes[img_hash] = file_path

        summary = f"\n✔ Ολοκληρώθηκε!\n🗑 Διαγράφηκαν: {deleted_count}\n📂 Μετακινήθηκαν: {moved_count}"
        self.log(summary)
        messagebox.showinfo("Τέλος", summary)


if __name__ == "__main__":
    root = tk.Tk()
    app = DuplicateFinderApp(root)
    root.mainloop()
