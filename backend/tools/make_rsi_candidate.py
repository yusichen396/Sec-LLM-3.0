"""Prepare a known developer-authored tokenizer candidate for execution-chain checks."""
import argparse
import hashlib
from pathlib import Path

from tools.optimize_rag import atomic_json


def make(root, output):
    path = root / "core/rag/hybrid.py"
    original = path.read_bytes()
    content = original.decode("utf-8").replace("\r\n", "\n")
    start, end = content.index("def tokenize("), content.index("\n\nclass BM25Index")
    replacement = '''def tokenize(text: str) -> list[str]:
    """Tokenize Chinese spans without crossing separators."""
    low = text.lower()
    grams = []
    for match in re.finditer(r"[\\u4e00-\\u9fff]+", low):
        span = match.group()
        grams.extend(span[i:i + 2] for i in range(len(span) - 1))
        if len(span) == 1:
            grams.append(span)
    return grams + _LATIN_RE.findall(low)
'''
    candidate = content[:start] + replacement + content[end:]
    compile(candidate, str(path), "exec")
    atomic_json(output, {"hypothesis": "Avoid artificial Chinese bigrams across separators; this is an authored harness candidate, not proven improvement.",
                "changes": [{"path": "core/rag/hybrid.py", "before_sha256": hashlib.sha256(original).hexdigest(),
                             "content": candidate}]})
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[2] / "artifacts/code_rsi_proposals/chinese_spans.json")
    args = parser.parse_args()
    print(make(args.root, args.output))
