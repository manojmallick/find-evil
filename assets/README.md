# Devpost Gallery Assets

Visual assets for the Devpost submission gallery and the GitHub README.
All PNGs are rendered at 2× (2560px wide) from the source HTML via headless
Chrome — regenerate any time with `make` below.

| File | Use | Source |
|---|---|---|
| `cover.png` | Devpost **gallery cover / thumbnail** + README hero | `cover.html` |
| `architecture.png` | Architecture + trust boundaries (judging: Constraint Implementation) | `architecture.html` |
| `report.png` | The **real** generated report — confirmed findings with traceable call_ids | `../docs/sample_run/report.html` |
| `proof.png` | "Verify any finding in <10s" — the audit-trail proof shot | `proof.html` |

Suggested Devpost gallery order: **cover → report → proof → architecture**
(hook, then proof it's real, then how it works).

## Regenerate the PNGs

```bash
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
shot() { "$CHROME" --headless=new --disable-gpu --hide-scrollbars \
  --force-device-scale-factor=2 --window-size="$3" \
  --screenshot="$2" "file://$PWD/$1"; }

shot assets/cover.html        assets/cover.png        1280,800
shot assets/architecture.html assets/architecture.png 1280,800
shot docs/sample_run/report.html assets/report.png    1280,900
shot assets/proof.html        assets/proof.png        1280,800
```
