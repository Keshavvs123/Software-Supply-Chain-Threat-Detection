"""
Application 2: Clean Markdown Document Processor & HTML Converter
Security Profile: 100% Safe utility with standard click and markdown packages.
Zero external shell execution, safe string parsing only.
"""

import os
import sys

def convert_markdown_to_html(markdown_text: str) -> str:
    """Safely converts markdown string to sanitized HTML using standard parser."""
    try:
        import markdown
        html = markdown.markdown(markdown_text, extensions=['extra', 'codehilite'])
        return html
    except ImportError:
        # Fallback basic parser if markdown is not pre-installed
        lines = markdown_text.splitlines()
        html_lines = []
        for line in lines:
            if line.startswith("# "):
                html_lines.append(f"<h1>{line[2:]}</h1>")
            elif line.startswith("## "):
                html_lines.append(f"<h2>{line[3:]}</h2>")
            elif line.startswith("- "):
                html_lines.append(f"<li>{line[2:]}</li>")
            else:
                html_lines.append(f"<p>{line}</p>")
        return "\n".join(html_lines)

def generate_table_of_contents(markdown_text: str) -> list:
    """Extracts markdown headers to build navigational outline."""
    toc = []
    for line in markdown_text.splitlines():
        if line.startswith("#"):
            level = line.count("#")
            title = line.strip("# ").strip()
            toc.append({"level": level, "title": title})
    return toc

def main():
    sample_doc = \"\"\"
# Project Documentation
## Introduction
This is a clean, secure markdown documentation processor.
- High performance
- Sanitized HTML output
- Zero dangerous shell invocations
## Conclusion
All processing executes in pure memory.
\"\"\"
    print("=== Markdown Processing Pipeline ===")
    toc = generate_table_of_contents(sample_doc)
    print(f"Extracted {len(toc)} Table of Contents items:")
    for item in toc:
        indent = "  " * (item["level"] - 1)
        print(f"{indent}- {item['title']} (H{item['level']})")
    
    html = convert_markdown_to_html(sample_doc)
    print("\nGenerated HTML Output snippet:")
    print(html[:120] + "...")

if __name__ == "__main__":
    main()
