"""Cut the embedded font down to the characters the interface uses.

Run after changing interface text: uv run --no-project --with "fonttools[woff]" scripts/subset_font.py
Text outside the subset (speaker names, for one) falls back to Microsoft YaHei UI.
"""

from pathlib import Path

from fontTools import subset

root = Path(__file__).resolve().parent.parent
sources = sorted([*root.glob("web/*.html"), *root.glob("web/*.js"), *root.glob("src/*.rs")])
text = "".join(path.read_text(encoding="utf-8") for path in sources)
chars = "".join(sorted({c for c in text if c > "~"} | {chr(c) for c in range(0x20, 0x7F)}))
(root / "web/fonts/NotoSansSC-UI.txt").write_text(chars, encoding="utf-8")

options = subset.Options()
options.flavor = "woff2"
font = subset.load_font(str(root / "assets/NotoSansSC-GB2312.woff2"), options)
subsetter = subset.Subsetter(options)
subsetter.populate(text=chars)
subsetter.subset(font)
subset.save_font(font, str(root / "web/fonts/NotoSansSC-UI.woff2"), options)
