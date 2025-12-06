import fitz
import re

doc = fitz.open("14.pdf")
txt = ""

for p in doc:
	txt += p.get_text("text")

m = re.search(r"\[HWM\](.+?)\[/HWM\]", txt)
print(m.group(1) if m else "No HWM watermark found")