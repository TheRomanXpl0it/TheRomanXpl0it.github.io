import os
import re
import sys
import subprocess
import frontmatter
import yaml
from slugify import slugify

INPUT_DIRS = {
    "posts": "_posts/articles/",
    "writeups": "_posts/writeups"
}
OUTPUT_ROOT = "out"

def get_git_lastmod(filepath):
    """Return ISO8601 timestamp of last git commit for filepath, or None."""
    try:
        ts = subprocess.check_output(
            ["git", "log", "-1", "--format=%cI", filepath],
            stderr=subprocess.DEVNULL
        ).strip().decode("utf-8")
        return ts
    except Exception:
        return None

DATE_REGEX = re.compile(r'^(?P<date>\d{4}-\d{2}-\d{2})[-_]')
def extract_date_from_filename(filepath):
    """Extract YYYY-MM-DD from filename if present, else return None."""
    name = os.path.basename(filepath)
    match = DATE_REGEX.match(name)
    if match:
        return match.group('date')
    return None

def convert_file(input_path, section, category=None):
    """
    Convert a Jekyll markdown file at input_path to a Hugo page bundle.
    - section: "posts" or "writeups"
    - category: for writeups, the subdirectory name (None for posts)
    """

    date = extract_date_from_filename(input_path)
    post = frontmatter.load(input_path)
    metadata = {
        "title": post.get("title", ""),
        "date": post.get("date", date)
    }

    # Add git lastmod if available
    lastmod = get_git_lastmod(input_path)
    if lastmod:
        metadata["lastmod"] = lastmod

    # Map frontmatter fields
    if "categories" in post:
        cats = post["categories"]
        metadata["categories"] = cats if isinstance(cats, list) else [cats]

        if section == "writeups":
            metadata["categories"] += ['writeup']

    if section == "writeups" and category:
        # Ensure writeup category is included in front matter
        metadata.setdefault("categories", []).append(category)
    if "keywords" in post:
        metadata["tags"] = post["keywords"] if isinstance(post["keywords"], list) else post["keywords"].split()
    if "authors" in post:
        metadata["authors"] = post["authors"]

    # Determine slug and output directory
    basename = os.path.splitext(os.path.basename(input_path))[0]

    # Remove date prefix from slug if present
    slug_source = DATE_REGEX.sub('', basename)

    slug = slugify(post.get("title", slug_source))
    out_dir = os.path.join(OUTPUT_ROOT, "posts", slug)
    os.makedirs(out_dir, exist_ok=True)

    # Write Hugo bundle: index.md
    out_path = os.path.join(out_dir, "index.md")
    with open(out_path, "w", encoding="utf-8") as out:
        out.write("---\n")
        yaml.dump(metadata, out, default_flow_style=False, sort_keys=False)
        out.write("---\n\n")
        out.write(post.content.strip() + "\n")
    print(f"Converted {input_path} → {out_path}")

def main():
    for section, input_dir in INPUT_DIRS.items():
        if not os.path.isdir(input_dir):
            print(f"Warning: input directory '{input_dir}' not found, skipping.")
            continue

        if section == "posts":
            # Flat markdown files
            for fname in os.listdir(input_dir):
                if fname.endswith(".md"):
                    convert_file(os.path.join(input_dir, fname), section)
        else:
            # writeups: expect subdirectories as categories
            for category in os.listdir(input_dir):
                cat_dir = os.path.join(input_dir, category)
                if os.path.isdir(cat_dir):
                    for fname in os.listdir(cat_dir):
                        if fname.endswith(".md"):
                            convert_file(os.path.join(cat_dir, fname), section, category)

if __name__ == "__main__":
    main()
