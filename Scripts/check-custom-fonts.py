#!/usr/bin/env python3
"""Guard app typography; called by Xcode, also runnable from the project root."""
import os
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parents[1] / "uniPass"
# Centralized implementation alone may bridge UIFont/CoreText and style native Sections.
patterns = [
    (r"\.font\s*\((?!\s*CustomFont\.symbol\s*\()", "Use .customFont(...); CustomFont.symbol is only for SF Symbol images"),
    (r"\.(?:fontWeight|fontDesign|bold|italic|monospaced|monospacedDigit)\s*\(", "Do not override the supplied regular custom font faces"),
    (r"\bSection\s*[({]", "Use CustomSection to style section contents, headers and footers"),
    (r"\b(?:UIFont|UIFontDescriptor)\s*[.(]|\bFont\.(?:custom|system)\s*\(", "Create fonts only in CustomFont.swift"),
]
errors = []
paths = []
def traversal_error(error):
    errors.append(f"{error.filename}:1: error: Declare this source directory in the typography build phase input paths: {error}")


for directory, subdirectories, filenames in os.walk(root, onerror=traversal_error):
    subdirectories[:] = [name for name in subdirectories if name != "Fonts" and not name.endswith(".xcassets") and not name.startswith(".")]
    paths.extend(pathlib.Path(directory) / name for name in filenames if name.endswith(".swift"))
for path in sorted(paths):
    if path.name == "CustomFont.swift":
        continue
    try:
        lines = path.read_text().splitlines()
    except PermissionError:
        errors.append(f"{path}:1: error: Add this Swift source to Scripts/CustomFontInputs.xcfilelist for the sandboxed typography check")
        continue
    source = "\n".join(lines)
    for match in re.finditer(r"\.font\s*\(\s*CustomFont\.symbol\s*\(", source):
        if not re.search(r"Image\s*\(\s*systemName\s*:[^\n]*\)\s*$", source[:match.start()]):
            number = source[:match.start()].count("\n") + 1
            errors.append(f"{path}:{number}: error: Apply CustomFont.symbol directly to Image(systemName:), never to text or containers")
    for number, line in enumerate(lines, 1):
        if line.lstrip().startswith("//"):
            continue
        for pattern, message in patterns:
            if re.search(pattern, line):
                errors.append(f"{path}:{number}: error: {message}")
if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
print("CustomFont check passed.")
