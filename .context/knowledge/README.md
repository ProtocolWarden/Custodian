# Cold store (`.context/knowledge/`)

One `<slug>.md` per durable finding, in the §2.6 item format (YAML front-matter
+ `## Finding` / `## Detail`). Surfaced one-line by the router on matching edits;
promoted to warm by `cl consolidate` under the consequence-veto. The engine reads
these; do not hand-edit `tier`/`last_injected` casually.
