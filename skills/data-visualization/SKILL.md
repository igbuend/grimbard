---
name: data-visualization
description: Data visualization and information design best practices. Use when creating charts, dashboards, graphs, or any visual representation of data.
aliases:
  - dataviz
  - chart-design
  - info-design
---

# Data Visualization

Principles and best practices for effective data visualization.

## Core Principles

### Tufte's Foundations

**Data-Ink Ratio**: Maximize ink used for actual data
- Remove unnecessary gridlines, borders, backgrounds
- Eliminate 3D effects, shadows, decorative elements
- Every visual element must justify its existence

**Lie Factor**: Graphical representation must match data
- Lie Factor = Size of Effect in Graphic / Size of Effect in Data
- Ideal = 1. Substantial distortion when >1.05 or <0.95
- Avoid: non-zero baselines, inconsistent scales, 3D distortion

**Chart Junk**: Remove non-data ink and redundant data-ink

### Graphical Integrity

| Practice | Rule |
|----------|------|
| Bar charts | Must start at zero |
| Proportions | Size encodements reflect actual ratios |
| 3D effects | Never use—distorts perception |
| Pie charts | Maximum 3-4 slices |

## Visual Perception

### Gestalt Principles

| Principle | Application |
|-----------|-------------|
| **Proximity** | Cluster related data; space different categories |
| **Similarity** | Consistent color/shape for categories |
| **Continuity** | Connected line charts for trends |
| **Closure** | Complete shapes, avoid unnecessary borders |
| **Figure/Ground** | Data stands out against background |
| **Connection** | Lines/links show relationships |

### Preattentive Attributes

Processed in <200ms before conscious attention:

**Hierarchy:** Position > Color > Size > Shape > Orientation

| Attribute | Use Case |
|-----------|----------|
| Position (spatial) | Ranking, trends |
| Color (hue) | Categorical distinction |
| Size | Quantitative comparison |
| Shape | Category distinction |
| Intensity | Highlighting differences |

## Color

### Palette Types

**Sequential**: Ordered data (low → high), single hue light to dark  
**Diverging**: Data with meaningful midpoint, two hues meeting at neutral  
**Categorical**: Nominal data, distinct equally-spaced hues (max 6-8)

### Color-Blind Safe Palettes

~8% of men and 0.5% of women have color vision deficiency. Design for them by default.

**Okabe-Ito Palette** (recommended default):
- Black `#000000`, Orange `#E69F00`, Sky Blue `#56B4E9`
- Bluish Green `#009E73`, Yellow `#F0E442`, Blue `#0072B2`
- Vermillion `#D55E00`, Reddish Purple `#CC79A7`

**Other tested palettes**: Viridis, Cividis, Paul Tol, ColorBrewer (colorblind filter)

### Color Blindness Types

| Type | Prevalence | Confusion |
|------|-----------|-----------|
| Deuteranomaly | 5% of men | Red-green (most common) |
| Protanopia | 1% of men | Red-green |
| Deuteranopia | 1.3% of men | Red-green |
| Tritanopia | 0.0001% | Blue-yellow (rare) |
| Achromatopsia | 0.003% | No color (greyscale) |

### Cultural Considerations

| Color | Western | China | Other |
|-------|---------|-------|-------|
| Red | Danger | Good luck | Death (some African) |
| White | Purity | Death | |
| Green | Environment | Infidelity | |

## Accessibility

### Fundamental Rule

**Never use color alone to encode data.** Always combine with at least one other channel:
- Color + pattern/texture (bar charts)
- Color + line style: solid, dashed, dotted (line charts)
- Color + shape (scatter plots)
- Color + direct labels (all charts)

### Contrast Requirements (WCAG)

| Element | AA (minimum) | AAA (enhanced) |
|---------|-------------|----------------|
| Body text | 4.5:1 | 7:1 |
| Large text (18pt+) | 3:1 | 4.5:1 |
| Non-text (lines, bars, icons) | 3:1 | — |
| Focus indicators | 3:1 | 3:1 + 2px space |

### Low Vision Design

~253 million people globally have visual impairment.

**Typography in charts:**
- Minimum 12px for labels (14px preferred)
- Sans-serif fonts for readability
- Line height ≥1.5×
- High contrast text (4.5:1 minimum)

**Layout:**
- Support browser zoom to 200% without content loss
- No horizontal scrolling at zoomed levels
- Direct data labeling reduces magnification needs
- Avoid cluttered, dense layouts

**Dark mode:**
- Avoid pure white (#fff) on pure black (#000) — causes halation
- Use slightly heavier font weights on dark backgrounds
- Maintain all contrast ratios

### Screen Reader Accessibility

**Alt text for charts** (follow the four-level model by Lundgard & Satyanarayan, 2021):
1. **What**: Chart type and data ("Bar chart showing 2024 sales by region")
2. **How**: Encoding method ("Bars represent revenue in USD")
3. **Readout**: Key values ("North America leads at $450K")
4. **Insight**: Patterns/trends ("45% year-over-year growth")

**SVG accessibility:**
```html
<svg role="img" aria-labelledby="title desc">
  <title id="title">2024 Sales by Region</title>
  <desc id="desc">Bar chart. North America leads with 45% of revenue.</desc>
</svg>
```

**Always provide**: data table alternative or detailed description for complex charts.

### Multi-Modal Access

Beyond visual, consider:
- **Sonification**: Map data values to pitch/rhythm (Highcharts Sonification Studio, TwoTone)
- **Tactile graphics**: Raised-surface charts for blind users (swell-touch paper, 3D print)
- **Haptic feedback**: Vibration intensity proportional to data values
- **MAIDR**: Multi-Access Interactive Data Representation (text + audio + tactile)

### Accessibility Legislation

| Jurisdiction | Law/Standard | Requirement |
|-------------|-------------|-------------|
| **US** | Section 508, ADA | WCAG 2.0/2.1 AA (federal); courts use WCAG for ADA |
| **EU** | European Accessibility Act (2025), EN 301 549 | WCAG 2.1 AA for public + private sectors |
| **UK** | Equality Act 2010, PSBAR 2018 | WCAG 2.1 AA for public sector |
| **Japan** | JIS X 8341-3:2016 | Aligned with WCAG, AA recommended |
| **Australia** | Disability Discrimination Act 1992 | WCAG 2.1 AA benchmark |
| **Canada** | Accessible Canada Act, AODA (Ontario) | WCAG 2.0 AA minimum, moving to 2.1 |
| **Singapore** | Digital Service Standards | WCAG 2.1 AA for government |
| **China** | GB/T 37668-2019 | Aligned with WCAG 2.0 |
| **South Korea** | KWCAG 2.1 | Aligned with WCAG 2.1 |

### Accessibility Testing Checklist

- [ ] Color not sole encoding method (WCAG 1.4.1)
- [ ] Text contrast ≥4.5:1 (WCAG 1.4.3)
- [ ] Non-text contrast ≥3:1 (WCAG 1.4.11)
- [ ] Supports 200% zoom (WCAG 1.4.4)
- [ ] Text spacing adjustable (WCAG 1.4.12)
- [ ] Alt text or data table provided (WCAG 1.1.1)
- [ ] Keyboard navigable (WCAG 2.1.1)
- [ ] Test with color blindness simulator (Coblis, ColorOracle)
- [ ] Test with screen reader (NVDA, VoiceOver)
- [ ] Grayscale test: still understandable?

## Chart Selection

```
Data type:
├─ Categorical comparison → Bar chart
├─ Part-to-whole → Treemap/stacked bar (avoid pie >4 slices)
├─ Time series → Line chart
├─ Distribution → Histogram, box plot, violin
├─ Correlation → Scatter plot
├─ Geographic → Choropleth, proportional symbol
└─ Network/flow → Network graph, Sankey
```

## Common Mistakes

### Avoid
- Truncated Y-axis in bar charts
- Dual Y-axes (false correlations)
- >4 pie chart slices
- 3D charts
- Rainbow palettes without meaning
- Over-plotting (too many points)
- Color-only encoding (accessibility failure)
- Insufficient contrast on chart elements

### Fixes
- **Clutter** → Small multiples, sparklines
- **No context** → Add baseline, benchmarks
- **Hard to compare** → Consistent scales, aligned axes
- **Data overload** → Filter, aggregate, progressive disclosure
- **Inaccessible** → Redundant encoding, alt text, data tables

## Domain Guidance

### Financial
- Candlestick charts for prices
- Treemaps for portfolio allocation
- Log vs linear scale for long timeframes
- Annotate key events (earnings, mergers)

### Security/SOC
- Heatmaps for activity over time
- Network graphs for connection analysis
- Sankey for traffic flow
- Red/amber/green severity (**with icons** for color-blind users)
- Dark theme preferred (reduce eye strain)

### Scientific
- Vector graphics (SVG, PDF)
- Field-specific conventions
- Follow Nature 2025 checklist: clarity, accessibility
- 300+ DPI, clear labeling
- Color-blind safe palettes mandatory for publications

## Tools

| Use Case | Tool |
|----------|------|
| Custom web viz | D3.js, Plotly, Olli (accessible) |
| BI dashboards | Tableau, Power BI, Apache ECharts |
| Static reports | Matplotlib, Seaborn, ggplot2 |
| Rapid prototyping | Flourish, Google Data Studio |
| AI/ML integration | Python (Matplotlib, Plotly, Altair) |

### Accessibility Tools

| Purpose | Tool |
|---------|------|
| Color blind simulation | Coblis, ColorOracle, Chrome "Let Me Color" |
| Contrast checking | WebAIM Contrast Checker, axe DevTools |
| Screen reader testing | NVDA (free), JAWS, VoiceOver |
| Accessibility audit | WAVE, Lighthouse, Accessibility Insights |
| Accessible charts | Olli (MIT), Highcharts Sonification |
| Color palette design | ColorBrewer, Paul Tol, Accessible Colors |

## Quick Reference

1. **Start with grayscale** — add color only to encode data
2. **Redundant encoding** — color + pattern/shape/label always
3. **Okabe-Ito palette** — default color-blind safe choice
4. **4.5:1 / 3:1** — text contrast / non-text contrast minimums
5. **Small multiples** — same chart across subsets solves clutter
6. **Tufte's test** — can you remove this element and still understand?
7. **Alt text + data table** — provide text alternatives for every chart
8. **Test accessibility** — simulator + screen reader + grayscale

## Resources

- Tufte's 4 books (foundational)
- Wilke, *Fundamentals of Data Visualization* (2019)
- Lundgard & Satyanarayan, "Accessible Visualization via Natural Language Descriptions" (2021)
- Hajas et al., "Rich Screen Reader Experiences" (2022, MIT)
- Nature 2025 scientific visualization checklist
- W3C WAI: w3.org/WAI
- ColorBrewer: colorbrewer2.org
- WebAIM: webaim.org
- DIAGRAM Center: diagramcenter.org
