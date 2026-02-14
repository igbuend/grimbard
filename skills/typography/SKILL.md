---
name: typography
description: Typography principles for print and screen. Use when selecting fonts, setting type, designing text layouts, or creating web typography.
aliases:
  - type-design
  - font-selection
  - web-typography
---

# Typography

Principles for effective typography across print and screen.

## Type Anatomy

- **Baseline**: Invisible line letters sit on
- **X-height**: Height of lowercase 'x', crucial for readability
- **Cap height**: Capital letter height
- **Ascender/Descender**: Parts above/below x-height
- **Kerning**: Adjusting space between specific pairs (AV, To)
- **Tracking**: Uniform letter-spacing across words
- **Leading**: Space between baselines (line-height)

## Font Classification

### Serif
| Type | Examples | Best For |
|------|----------|----------|
| Old Style | Garamond, Caslon | Books, long reading |
| Transitional | Baskerville, Times | Academic, newspapers |
| Modern | Bodoni, Didot | Luxury, headlines |
| Slab | Rockwell, Roboto Slab | Web, signage |

### Sans-Serif
| Type | Examples | Best For |
|------|----------|----------|
| Grotesque | Helvetica, Arial | Corporate, UI |
| Neo-Grotesque | Inter, Roboto | Modern interfaces |
| Geometric | Futura, Montserrat | Headlines, logos |
| Humanist | Gill Sans, Open Sans | Reading, accessibility |

## Print Typography

**Measure (line length)**: 45-75 characters optimal  
**Leading**: 1.4-1.6× for body, 1.1-1.3× for headlines  
**Ligatures**: Use fi, fl, ff in body text  
**Small caps**: For acronyms (NASA, WHO)  
**Oldstyle figures**: Blend with lowercase

## Screen Typography

**Minimum sizes**:
- Body: 16px (1rem)
- Captions: 12-14px

**Line height**: 1.5-1.7 for body (more than print)  
**Contrast**: 4.5:1 minimum (WCAG)  
**Dark mode**: Avoid pure white on black

## Web Fonts

### Formats
- **WOFF2**: Best choice, excellent compression
- **WOFF**: Legacy support
- Avoid: TTF (no compression), EOT, SVG

### Loading
```css
@font-face {
  font-family: 'MyFont';
  src: url('font.woff2') format('woff2');
  font-display: swap; /* Prevents FOIT */
}
```

### Preload critical fonts
```html
<link rel="preload" href="font.woff2" as="font" type="font/woff2" crossorigin>
```

## Responsive Typography

### Units
- **rem**: Root-relative (use for font sizes)
- **em**: Parent-relative (use for component spacing)
- **px**: Absolute (borders, precise elements)
- **vw/vh**: Viewport-relative (fluid headlines)

### Modular Scale
| Scale | Ratio | Use Case |
|-------|-------|----------|
| Major Second | 1.125 | Simple websites |
| Minor Third | 1.200 | Blogs |
| Major Third | 1.250 | Marketing sites |
| Perfect Fourth | 1.333 | Editorial |

### Fluid Type with clamp()
```css
html {
  font-size: clamp(1rem, 0.5rem + 1vw, 1.5rem);
}
```

## Hierarchy

**Levels**: h1 → h2 → h3 → body → caption  
**Size contrast**: 1.5× minimum between levels  
**Techniques**: Size, weight, color, spacing

## Accessibility

**WCAG Requirements**:
- Normal text: 4.5:1 contrast
- Large text (18px+ bold): 3:1
- Support 200% zoom
- Allow text spacing overrides

**Best fonts for accessibility**:
- Sans-serif for screens
- Adequate x-height
- Avoid decorative for body

## Common Mistakes

❌ Too many fonts (limit to 2-3)  
❌ Insufficient contrast  
❌ Line lengths >75 or <45 chars  
❌ Ignoring dark mode  
❌ Using display fonts for body  
❌ Justified text on web (creates rivers)

## Quick Reference

**Web body**: 16px, 1.5-1.7 line-height, 60-75 chars  
**Print body**: 10-12pt, 1.4-1.6× leading  
**Headlines**: 1.5-3× body, use modular scale  
**Pairing**: Serif + sans-serif, match x-heights

## Tools

- **Google Fonts**: Free web fonts
- **Type Scale**: typescalemaker.com
- **Fluid Type Calculator**: fluidtype.com
- **Fontpair**: Font pairing ideas
- **Color Contrast Checker**: WebAIM

## Variable Fonts

Single file with multiple weights/widths:
```css
h1 {
  font-variation-settings: 'wght' 700, 'wdth' 80;
}
```

**Common axes**: wght (weight), wdth (width), slnt (slant), opsz (optical size)

## Resources

- Tufte's typography works
- NN/g typography guidelines
- MDN CSS Fonts Module
- Typewolf (typewolf.com)
