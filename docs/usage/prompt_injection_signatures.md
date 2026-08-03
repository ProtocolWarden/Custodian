# Prompt-injection signatures (INJ1)

INJ1 scans tracked text for invisible and bidirectional control characters —
the classic carrier for instructions hidden from a human reviewer but visible
to a model that ingests the text, and for homoglyph/direction tricks that make
a line render differently from how it parses.

It is **opt-in and off by default**, and it is deliberately the *outer* layer of
the injection defense, never the load-bearing one. See
[What this is not](#what-this-is-not) before relying on it.

## What it flags

A tracked, non-binary, UTF-8-decodable file containing any of these codepoints:

| Codepoint | Name | Why it matters |
|---|---|---|
| `U+200B` | Zero-width space | Splits a token invisibly — `de<ZWSP>lete` reads as `delete` |
| `U+200C` | Zero-width non-joiner | Same, with different shaping behavior |
| `U+200D` | Zero-width joiner | Same; also used to build composite emoji |
| `U+200E` | Left-to-right mark | Direction control |
| `U+200F` | Right-to-left mark | Direction control |
| `U+202A` | Left-to-right embedding | Direction control |
| `U+202B` | Right-to-left embedding | Direction control |
| `U+202C` | Pop directional formatting | Direction control |
| `U+202D` | Left-to-right override | Renders text in an order that differs from parse order |
| `U+202E` | Right-to-left override | The classic "Trojan Source" reordering attack |
| `U+2066` | Left-to-right isolate | Direction control |
| `U+2067` | Right-to-left isolate | Direction control |
| `U+2068` | First-strong isolate | Direction control |
| `U+2069` | Pop directional isolate | Direction control |
| `U+FEFF` | BOM / zero-width no-break space | Legitimate only at offset 0; mid-file it is invisible padding |
| `U+00AD` | Soft hyphen | Invisible unless the renderer breaks the line there |

None of these legitimately appear in source or prose, which is what keeps the
false-positive rate near zero. That is the whole selection criterion: INJ1 does
not attempt to detect injection *phrasing*, only smuggling *mechanics*.

## Running it

INJ1 is registered `deprecated=True`. In Custodian that flag means "skipped by
the default gate" — here it is not a tool-deprecation but the off-by-default
lever, because a repo's own injection-handling code (a sanitizer whose regex
*matches* these characters, a unicode test fixture) would otherwise trip the
detector fleet-wide.

```bash
custodian audit --only INJ1 --include-deprecated
```

The intended use is deliberate: run it against ingested PR content or any text
that arrives from outside the trust boundary. A hit is a signal to route the
content down a stricter deterministic path, not to fail the build.

## Exempting a file

A file that legitimately contains these characters opts out by carrying the
marker anywhere in its text:

```
custodian:allow-invisible-chars
```

The exemption is **by content, not by path** — deliberately. A sanitizer or a
unicode fixture carries its own justification, and consumers do not have to
maintain a path exclude list that drifts as files move. Note the consequence:
INJ1 does **not** read `audit.exclude_paths.INJ1`; adding one has no effect.

## What the finding tells you

```
src/ingest/parser.py:42: invisible/bidi control char U+202E
```

Path, line, and codepoint — never the surrounding text. That omission is
deliberate: echoing attacker-controlled content into an audit report, a CI log,
or a summary that a model later reads would re-launder it through a trusted
channel, which is exactly the failure the detector exists to catch.

Findings are counted **once per line**, not once per occurrence. A line carrying
six zero-width spaces reports one finding. The count answers "how many lines are
affected", which is the number that matters when you go to inspect them.

To see the actual bytes, look at the file directly:

```bash
grep -nP "[\x{200b}-\x{200f}\x{202a}-\x{202e}\x{2066}-\x{2069}\x{feff}\x{00ad}]" path/to/file
```

## What this is not

- **Not** a complete injection defense, and not load-bearing. It detects one
  narrow mechanical signature. Text carrying a plain-ASCII injection payload
  passes INJ1 cleanly, because there is nothing invisible about it.
- **Not** a homoglyph detector. Cyrillic `а` in place of Latin `a` is a
  different attack that INJ1 does not cover — those are visible characters.
- **Not** a reason to skip review. The load-bearing control is a reviewer's
  code-computed typed verdict; INJ1 only decides which path that review takes.
- **Not** run by `custodian audit` on its own. If you expect it in CI, you must
  pass `--only INJ1 --include-deprecated` explicitly.

## Related

- `docs/usage/private_repo_names.md` — the B-class boundary detectors, which
  share INJ1's tracked-file scanning helpers.
- `docs/design/detector_disposition_matrix.md` — INJ1's disposition and the
  rationale for shipping it opt-in.
