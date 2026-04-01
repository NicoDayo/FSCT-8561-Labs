from PIL import Image
import stepic

image = Image.open("profile_secret.png")
data = stepic.decode(image)
print("Recovery:", data)