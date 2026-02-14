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

### Palette Selection

**Sequential**: Ordered data (low → high), single hue light to dark  
**Diverging**: Data with meaningful midpoint, two hues meeting at neutral  
**Categorical**: Nominal data, distinct equally-spaced hues (max 6-8)

### Accessibility

- **Never use red-green alone** to distinguish data
- Use [ColorBrewer](colorbrewer2.org) for tested palettes
- WCAG: minimum 4.5:1 contrast ratio for text
- Add patterns, labels, or icons—don't rely on color alone

### Cultural Considerations

| Color | Western | China | Other |
|-------|---------|-------|-------|
| Red | Danger | Good luck | Death (some African) |
| White | Purity | Death | |
| Green | Environment | Infidelity | |

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
- Color-only encoding

### Fixes
- **Clutter** → Small multiples, sparklines
- **No context** → Add baseline, benchmarks
- **Hard to compare** → Consistent scales, aligned axes
- **Data overload** → Filter, aggregate, progressive disclosure

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
- Red/amber/green severity (with icons)
- Dark theme preferred

### Scientific
- Vector graphics (SVG, PDF)
- Field-specific conventions
- Follow Nature 2025 checklist: clarity, accessibility
- 300+ DPI, clear labeling

## Tools

| Use Case | Tool |
|----------|------|
| Custom web viz | D3.js, Plotly |
| BI dashboards | Tableau, Power BI, Apache ECharts |
| Static reports | Matplotlib, Seaborn, ggplot2 |
| Rapid prototyping | Flourish, Google Data Studio |
| AI/ML integration | Python (Matplotlib, Plotly, Altair) |

## Quick Reference

1. **Start with grayscale** — add color only to encode data
2. **Small multiples** — same chart across subsets solves clutter
3. **Tufte's test** — can you remove this element and still understand?
4. **Accessibility first** — ColorBrewer + contrast checker + color blind test

## Resources

- Tufte's 4 books (foundational)
- Wilke, *Fundamentals of Data Visualization* (2019)
- Healy, *Data Visualization* (2019)
- ColorBrewer: colorbrewer2.org
- Nature 2025 visualization checklist
