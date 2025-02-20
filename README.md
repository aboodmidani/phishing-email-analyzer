# 🛡️ Cybersecurity Tool

This repository contains two cybersecurity tools:

1. **Metadata Image Remover** - A Python tool that removes metadata from images to enhance privacy.

---

## 🖼️ Metadata Image Remover

### 📌 About
Metadata Image Remover is a Python script that removes EXIF metadata from images to protect privacy. This metadata may contain sensitive information like GPS location, camera details, and timestamps.

### 🚀 Features
✅ Removes all EXIF metadata from JPEG and PNG images  
✅ Supports batch processing of multiple images  
✅ Provides a clean version of the image without compromising quality  

### 🔧 Installation
Ensure you have **Python 3+** installed, then install dependencies:

```sh
pip install pillow
```

### ▶️ Usage
Run the script with:
```sh
python metadata_remover.py <input_image> <output_image>
```

Example:
```sh
python metadata_remover.py image.jpg clean_image.jpg
```

### 🛠️ How It Works
- Reads the image and extracts metadata.
- Saves the image without metadata while preserving its quality.



## 🔗 Contributing
Feel free to submit **issues** or **pull requests** if you'd like to improve these tools!

## 📜 License
This project is licensed under the **MIT License**.
