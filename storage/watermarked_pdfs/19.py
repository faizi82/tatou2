import re
import pikepdf

INPUT = "19.pdf"
OUTPUT = "19_clean_structural.pdf"

pdf = pikepdf.open(INPUT)

# Regex to remove BT..ET blocks containing Axel-Watermark
pattern = re.compile(
    r"BT[\s\S]*?Axel-Watermark[\s\S]*?ET", 
    re.DOTALL

)

for page in pdf.pages:
    page_contents = page.get("/Contents")  # consistent across pikepdf versions
    if page_contents is None:
        continue

    # Normalize: one stream or multiple streams
    if isinstance(page_contents, pikepdf.Stream):
        streams = [page_contents]
    elif isinstance(page_contents, pikepdf.Array):
        streams = list(page_contents)
    else:
        continue

    new_streams = []
    changed = False

    for stream in streams:
        try:
            raw = stream.read_bytes()
        except Exception:
            new_streams.append(stream)
            continue

        # Only modify streams that actually contain your watermark text
        if b"Axel-Watermark" not in raw:
            new_streams.append(stream)
            continue

        # Decode safely
        text = raw.decode("latin-1", errors="ignore")

        # Remove watermark BT..ET blocks
        cleaned_text, removed = pattern.subn("", text)

        if removed > 0:
            changed = True
            if cleaned_text.strip():
                new_stream = pikepdf.Stream(pdf, cleaned_text.encode("latin-1"))
                new_streams.append(new_stream)

        else:
            new_streams.append(stream)

    # If we modified anything, update PDF structure
    if changed:
        if len(new_streams) == 0:
            page["/Contents"] = None
        elif len(new_streams) == 1:
            page["/Contents"] = new_streams[0]
        else:
            page["/Contents"] = pdf.make_indirect(pikepdf.Array(new_streams))

pdf.save(OUTPUT)
print(f"Saved cleaned PDF as {OUTPUT}")