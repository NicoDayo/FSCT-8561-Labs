import exifread
from PIL import Image
from pathlib import Path
import csv
import base64
from datetime import datetime

pic_dir = Path("L6_metadata/Images")
images = [file for file in pic_dir.iterdir() if file.suffix.lower() in {".png", ".jpg", ".jpeg"}]

exif_tags = {
    "Create Date": "Image DateTime",
    "Modify Date": "EXIF DateTimeDigitized",
    "GPS Latitude": "GPS GPSLatitude",
    "GPS Longitude": "GPS GPSLongitude",
    "Date Original": "EXIF DateTimeOriginal",
    "Editing Software": "Image Software",
    "Camera Make": "Image Make",
    "Camera Model": "Image Model",
    "User Comment": "EXIF UserComment",
    "Description": "Image ImageDescription",
    "Maker Note": "EXIF MakerNote",
    "Copyright": "Image Copyright",
}

pillow_fields = {
    "xmp", "Create Date", "ModifyDate",
    "Software", "Make", "Model",
    "UserComment", "ImageDescription",
    "Copyright",
}

rows = []

def timestamp_check(row, path):
    stat = path.stat()
    row["File Modified (MAC)"] = datetime.fromtimestamp(stat.st_mtime).strftime("%Y:%m:%d %H:%M:%S")
    row["File Created (MAC)"] = datetime.fromtimestamp(stat.st_ctime).strftime("%Y:%m:%d %H:%M:%S")

    exif_create = row.get("Create Date (EXIF)", "")
    exif_modify = row.get("Modify Date (EXIF)", "")
    exif_original = row.get("Date Original (EXIF)", "")
    file_modified = row["File Modified (MAC)"]

    times = [t for t in [exif_create, exif_modify, exif_original] if t]

# anomaly if original metadata time is later than modified time
    if exif_original and exif_modify and exif_original > exif_modify:
        row["TS_Anomaly?"] = "O"
# anomaly if created metadata time is later than modified time
    elif exif_create and exif_modify and exif_create > exif_modify:
        row["TS_Anomaly?"] = "O"
# anomaly if any exif timestamp is later than the filesystem modified time
    elif any(t > file_modified for t in times):
        row["TS_Anomaly?"] = "O"
    else:
        row["TS_Anomaly?"] = "X"

def riskscoring(row):
    score = 0
    covert_fields = [
        row.get("Editing Software (EXIF)", ""),
        row.get("User Comment (EXIF)", ""),
        row.get("Description (EXIF)", ""),
        row.get("Maker Note (EXIF)", ""),
        row.get("Copyright (EXIF)", ""),
        row.get("Software (PIL)", ""),
        row.get("UserComment (PIL)", ""),
        row.get("ImageDescription (PIL)", ""),
        row.get("Copyright (PIL)", ""),
    ]

    print("Scored For:")

    if any(value for value in covert_fields):
        score += 10
        print("- Hidden Message: +10")

    if row.get("GPS Latitude (EXIF)", "") or row.get("GPS Longitude (EXIF)", ""):
        score += 5
        print("- GPS Privacy Leak: +5")

    if row.get("TS_Anomaly?", "") == "O":
        score += 5
        print("- Timestamp Anomaly: +5")
        # scoring only focused on these as I have not implemented double jpg check since I was stumped.

    row["Risk"] = score

for path in images:
    print(f"\n======= METADATA SCAN UNDER {path} =======\n")

    row = {"Filename": path.name}

    try:# EXIF
        with open(path, "rb") as f:
            tags = exifread.process_file(f)
        for name, key in exif_tags.items():
            value = str(tags.get(key, ""))
            row[f"{name} (EXIF)"] = value
            print(f"{name} (EXIF): {value}")
        # Pillow
        info = Image.open(path).info
        for key in pillow_fields:
            value = str(info.get(key, ""))
            row[f"{key} (PIL)"] = value
            if key in info:
                print(f"{key} (PIL): {value}")

        timestamp_check(row, path)
        riskscoring(row)

        print(f"File Modified (MAC): {row['File Modified (MAC)']}")
        print(f"File Created (MAC): {row['File Created (MAC)']}")
        print(f"TS_Anomaly?: {row['TS_Anomaly?']}")
        print(f"Risk Score: {row['Risk']}")

        
    except Exception as e:
        print("Error:", e)
        row["Error"] = str(e)
    rows.append(row)

csv_fields = ["Filename"]
csv_fields.extend([f"{name} (EXIF)" for name in exif_tags.keys()])
csv_fields.extend([f"{key} (PIL)" for key in pillow_fields])
csv_fields.extend(["File Modified (MAC)", "File Created (MAC)", "TS_Anomaly?", "Risk"])
output_csv = Path(__file__).resolve().parent / "metadata.csv"

with open(output_csv, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=csv_fields)
    w.writeheader()
    w.writerows(rows)

encoded_text = input("\nAny abnormal strings? Enter to decode here: \n")

try:
    decoded_text = base64.b64decode(encoded_text).decode("utf-8")
    print("Decoded text:", decoded_text)
except Exception as e:
    print("Could not decode string:", e)