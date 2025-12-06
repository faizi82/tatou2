import pikepdf

INPUT = "19.pdf"

OUTPUT = "19_clean_full.pdf"

pdf = pikepdf.open(INPUT)

for obj in pdf.objects:

    # Only streams can contain text drawing instructions

    if not isinstance(obj, pikepdf.Stream):

        continue

    try:

        data = obj.read_bytes()

    except Exception:

        continue

    if b"Axel-Watermark" in data:

        # Blank the entire stream

        obj.set_stream(b"")

pdf.save(OUTPUT)

print("Saved:", OUTPUT)


import pikepdf

INPUT = "19.pdf"

OUTPUT = "19_clean_full.pdf"

pdf = pikepdf.open(INPUT)

for obj in pdf.objects:

    # Only streams can contain text drawing instructions

    if not isinstance(obj, pikepdf.Stream):

        continue

    try:

        data = obj.read_bytes()

    except Exception:

        continue

    if b"Axel-Watermark" in data:

        # Blank the entire stream

        obj.set_stream(b"")

pdf.save(OUTPUT)

print("Saved:", OUTPUT)


