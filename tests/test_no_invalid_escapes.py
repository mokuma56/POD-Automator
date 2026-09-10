"""No invalid escape sequences in Python string literals.

`"\\d"` in a non-raw string is not a Python escape. Today Python keeps it as a
literal backslash-d and emits a SyntaxWarning; a future version will make it an
error, and the ~5,000-line DASHBOARD_HTML template alone had 70 of them, all
inside embedded JavaScript regexes.

They are invisible until they are fatal, and the compiler reports only one per
string literal, so chasing the warnings finds them one at a time. This test
scans every literal instead, which is how all 70 were found at once.

The fix is always to double the backslash (`\\\\d`), which produces the
identical string value — or to use a raw string.
"""
import io
import pathlib
import tokenize

REPO = pathlib.Path(__file__).resolve().parent.parent

# What Python accepts after a backslash inside a (non-raw) str literal.
VALID = set("\\'\"abfnrtv01234567xNuU\n")
# \N \u \U are not special in bytes literals, so they are invalid escapes there.
VALID_BYTES = set("\\'\"abfnrtv01234567x\n")


def _prefix_of(tok):
    i = 0
    while i < len(tok) and tok[i] not in "\"'":
        i += 1
    return tok[:i].lower()


def _invalid_escapes(tok):
    pre = _prefix_of(tok)
    if "r" in pre:                      # raw strings do no escape processing
        return []
    valid = VALID_BYTES if "b" in pre else VALID
    body = tok[len(pre):]
    q = '"""' if body.startswith('"""') else "'''" if body.startswith("'''") \
        else body[0]
    inner = body[len(q):-len(q)]
    out, i = [], 0
    while i < len(inner):
        if inner[i] != "\\":
            i += 1
            continue
        if i + 1 >= len(inner):
            break
        nxt = inner[i + 1]
        if nxt in valid:
            i += 2
            continue
        out.append(nxt)
        i += 2
    return out


def _python_files():
    return sorted(p for p in REPO.rglob("*.py")
                  if ".venv" not in p.parts and "node_modules" not in p.parts)


def test_no_invalid_escape_sequences_anywhere():
    offenders = {}
    for f in _python_files():
        try:
            src = f.read_text()
            bad = []
            for tok in tokenize.generate_tokens(io.StringIO(src).readline):
                if tok.type == tokenize.STRING:
                    for ch in _invalid_escapes(tok.string):
                        bad.append((tok.start[0], ch))
        except (tokenize.TokenError, SyntaxError, UnicodeDecodeError):
            continue                    # not our problem to police here
        if bad:
            offenders[str(f.relative_to(REPO))] = bad[:8]
    assert not offenders, (
        "invalid escape sequences found — double the backslash (\\\\d) or use a "
        f"raw string: {offenders}")


def test_the_scanner_actually_detects_one():
    """Guard the guard: a test that can never fail is worse than no test."""
    assert _invalid_escapes(r'"a\d+b"') == ["d"]
    assert _invalid_escapes(r'"line\nbreak"') == []      # \n is valid
    assert _invalid_escapes(r'r"a\d+b"') == []           # raw: no processing
    assert _invalid_escapes(r'"\x41\u0041"') == []       # \x and \u are valid
