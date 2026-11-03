# Design

<!-- impeccable:design-schema 1 -->

## World

CLI Terminal + Patch Panel — the tool IS a patch panel wearing an IOS terminal's voice. Subnets are labeled ports, WAN links are cable runs, every surface speaks `Router(config)#`. Chosen from the direction round (seed key dfb88abb, kind: pick) over the assigned darkroom roll and 6 challengers.

## Tokens

### Ground
- `--bg: #0a0e14` — phosphor-dark, near-black with blue cast
- `--surface: #111820` / `--surface2: #1a2330` — panel / raised chrome
- `--border: #2a3544` / `--border-bright: #3d4f63` — hairline edges
- CRT scanline texture via repeating-linear-gradient (deliberate, not decoration)

### Ink
- `--text: #d4dae4` — cool white primary
- `--text2: #93a1b3` — secondary (AA on surface2)
- `--text-dim: #8a97a8` — comments, prompts (AA on bg)

### Signals
- `--green: #00e676` — success, active, link-up
- `--amber: #ffb300` — warning, partial
- `--red: #ff5252` — fault, link-down
- `--cyan: #00e5ff` — headings, data accents
- `--blue: #448aff` — tags, secondary signals

### Terminal pane
- `--term-bg: #0d1117`, `--term-green: #7ee787`, `--term-blue: #79c0ff`, `--term-comment: #6e7681`

## Type

- Data/addresses/configs/labels: `Consolas, SF Mono, Courier New` monospace — the CLI voice
- UI chrome: system sans (`Segoe UI, system-ui`)
- Panel titles (`h2`): monospace green with `! ` prefix (IOS comment)
- Section titles (`h3`): monospace cyan with `> ` prefix (CLI prompt)
- Result titles (`h3.rb-title`): monospace terminal-blue with `$ ` prefix

## Structure

- Header: terminal title bar — `Router#` prompt + title, `!` comment subtitle, `!`-rule separator
- Tabs: patch-panel port strip — numbered monospace labels with link-light LED dots (green glow when active), keyboard navigable (Enter/Space/arrows), `role=tablist`
- Tables: label strips — uppercase cyan headers, 2px rule, LED dots per row
- Topology entries: port cards with green left-edge on hover
- Result boxes: terminal panes — dark bg, `$`-prefixed titles, green mono output
- Buttons: terminal commands — dark tinted bg, signal-colored border, invert on hover (no glow)

## States

- Link lights: `.led-green/amber/red/off` with subtle glow only on active state
- Tags: 1px signal border + tinted bg, 2px radius
- Focus: 2px green outline, always visible
- Reduced motion: all animation/transition killed via media query

## Provenance

- Direction: concept-seed dfb88abb → pick (CLI Terminal + Patch Panel over assigned darkroom)
- Detector: 55 findings (2026-09-28 critique) → 0 anti-patterns post-redesign
- Files: `app/index.html` (entry) + `app/styles.css` (this world) + `app/app.js` (logic)
