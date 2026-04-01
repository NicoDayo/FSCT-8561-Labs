from PIL import Image
import stepic

carrier = Image.open('Profile.png')
footprint_data = "CONF_TOOL_SCAN: 80, 443, 3478, 5060".encode('utf-8')
stego_img = stepic.encode(carrier, footprint_data)
stego_img.save("profile_secret.png")
print("===DATA HIDDEN===")