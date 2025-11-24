# 🧹 Duplicate Detox

**Duplicate Detox** is a smart, lightweight desktop tool that scans folders and detects **exact duplicate files** (by hash), helping you clean up storage and organize your photos faster.

✔ No machine learning  
✔ No cloud uploads  
✔ No face recognition  
✔ **Privacy-friendly & secure**

---

## 🚀 Features

| Feature | Status |
|--------|:------:|
| Exact duplicate detection (MD5 hashing) | ✅ |
| Safe delete (moves to system Trash instead of permanent removal) | ✅ |
| Move duplicates to a separate `Duplicates/` folder | ✅ |
| Thumbnail preview of found duplicates | ✅ |
| Drag-and-drop folder support (optional) | ✅ |
| Export results to CSV report | ✅ |
| Dark Theme UI | 🖤 |

---

## 🖼 Screenshots

(Add here after running the app 👍)

---

## 🔧 Installation

### 1️⃣ Install Python 3.9 or newer  
Download from: https://www.python.org/downloads/

### 2️⃣ Install dependencies

```sh
pip install -r requirements.txt

If you're on macOS and get errors due to security or missing GUI frameworks, try:
brew install python-tk
Run the App
python duplicate_detox.py
How It Works

Duplicate Detox scans the selected folder and:

Calculates a binary hash (MD5) for each file

Finds files with identical content (even if filenames differ!)

Lets you review thumbnails (limited preview sample)

Lets you choose action:

Mode	What Happens
🗑 Safe Delete	File is moved to OS Trash (recoverable)
📂 Move Mode	File is moved to a local Duplicates/ folder

