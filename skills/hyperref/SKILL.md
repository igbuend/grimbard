---
name: hyperref
description: "LaTeX hyperref package for hyperlinks, cross-references, bookmarks, and PDF metadata. Use when helping users add clickable links, configure PDF properties, or manage cross-references."
---

# hyperref — Hyperlinks, Cross-References & PDF Metadata

**CTAN:** https://ctan.org/pkg/hyperref  
**Manual:** `texdoc hyperref`

## Setup

```latex
% LOAD HYPERREF LAST (or near last) — it redefines many commands
\usepackage[
  colorlinks=true,
  linkcolor=blue,
  citecolor=green!50!black,
  urlcolor=blue!70!black,
  pdftitle={My Document Title},
  pdfauthor={Author Name},
]{hyperref}

% If using cleveref, load it AFTER hyperref:
\usepackage{cleveref}
```

## Common Setup Options

| Option | Default | Description |
|--------|---------|-------------|
| `colorlinks` | `false` | Color link text (vs boxes) |
| `linkcolor` | `red` | Internal links (refs, TOC) |
| `citecolor` | `green` | Citation links |
| `urlcolor` | `magenta` | URL links |
| `filecolor` | `cyan` | File links |
| `allcolors` | — | Set all link colors at once |
| `hidelinks` | — | No color, no boxes (for print) |
| `bookmarks` | `true` | Generate PDF bookmarks |
| `bookmarksnumbered` | `false` | Include section numbers in bookmarks |
| `bookmarksopen` | `false` | Expand bookmarks by default |
| `pdfborder` | `{0 0 1}` | Link border (set `{0 0 0}` to remove) |
| `breaklinks` | `true` | Allow links to break across lines |
| `unicode` | `true` (modern) | Unicode in bookmarks |

### PDF Metadata Options

| Option | Description |
|--------|-------------|
| `pdftitle` | Document title |
| `pdfauthor` | Author name(s) |
| `pdfsubject` | Subject |
| `pdfkeywords` | Keywords (comma-separated) |
| `pdfcreator` | Creating application |
| `pdfproducer` | PDF producer |

```latex
% Or set after loading:
\hypersetup{
  pdftitle={My Paper},
  pdfauthor={Jane Doe},
  pdfsubject={LaTeX Tutorial},
  pdfkeywords={LaTeX, hyperref, tutorial},
}
```

## Link Commands

```latex
% External URL
\href{https://example.com}{Click here}
\href{mailto:user@example.com}{Email me}
\href{file:./report.pdf}{Local file}

% URL (typewriter, breakable)
\url{https://example.com/path?query=value}

% Internal reference with custom text
\hyperref[sec:intro]{see the introduction}

% Standard cross-references (auto-linked by hyperref)
\ref{fig:plot}        % "3"
\pageref{tab:data}    % "12"
\eqref{eq:main}       % "(1)" — from amsmath

% Auto-named references
\autoref{fig:plot}     % "Figure 3"
\autoref{tab:data}     % "Table 2"
\autoref{sec:intro}    % "section 1"
\autoref{eq:main}      % "equation 1"

% Name reference (prints the title/caption)
\nameref{sec:intro}    % "Introduction"
```

### \autoref Names

| Counter | Default name |
|---------|-------------|
| `figure` | Figure |
| `table` | Table |
| `equation` | equation |
| `section` | section |
| `chapter` | chapter |
| `theorem` | Theorem |
| `page` | page |

Customize: `\renewcommand{\sectionautorefname}{Section}`

## cleveref Integration

```latex
\usepackage{hyperref}
\usepackage{cleveref}   % MUST be after hyperref

% Automatic type detection + ranges
\cref{fig:a}              % "fig. 1"
\Cref{fig:a}              % "Figure 1" (capitalized)
\cref{fig:a,fig:b,fig:c}  % "figs. 1 to 3"
\cref{eq:1,eq:2}          % "eqs. (1) and (2)"
\crefrange{fig:a}{fig:d}  % "figs. 1 to 4"

% Customize names
\crefname{equation}{eq.}{eqs.}
\Crefname{equation}{Equation}{Equations}
\crefname{figure}{fig.}{figs.}
```

## Bookmarks

```latex
% Manual bookmark entry
\pdfbookmark[level]{Text}{anchor}
\pdfbookmark[0]{Title Page}{title}

% Current bookmark (without section command)
\currentpdfbookmark{Appendix A}{appendixA}

% Bookmark with section:
\belowpdfbookmark{Subsection text}{anchor}  % below current level
```

## Link Appearance

```latex
% Colored text links (preferred for screen)
\hypersetup{colorlinks=true, allcolors=blue}

% Boxed links (default)
\hypersetup{colorlinks=false, pdfborder={0 0 1}}

% Hidden links (for print)
\hypersetup{hidelinks}

% Custom: colored + no underline
\hypersetup{
  colorlinks=true,
  linkcolor={blue!80!black},
  citecolor={green!60!black},
  urlcolor={red!70!black},
}
```

## Common Patterns

### Clickable TOC with Print-Friendly Style

```latex
\usepackage[
  colorlinks=true,
  linkcolor=black,      % TOC/internal links in black
  citecolor=blue!50!black,
  urlcolor=blue!70!black,
  bookmarks=true,
  bookmarksnumbered=true,
]{hyperref}
```

### Thesis/Dissertation Setup

```latex
\usepackage[
  hidelinks,            % clean for printing
  bookmarks=true,
  bookmarksnumbered=true,
  bookmarksopen=true,
  bookmarksopenlevel=2,
  pdftitle={PhD Thesis},
  pdfauthor={Name},
]{hyperref}
\usepackage{cleveref}
```

## Back-References in Bibliography

```latex
\usepackage[backref=page]{hyperref}
% Adds "Cited on page(s) X, Y" to bibliography entries
```

## Common Pitfalls

| Problem | Cause | Fix |
|---------|-------|-----|
| Broken cross-references | hyperref loaded too early | Load hyperref **last** (before cleveref) |
| `\autoref` says "section" lowercase | Default names | `\renewcommand{\sectionautorefname}{Section}` |
| Bookmark errors with math | Math in section titles | `\texorpdfstring{$E=mc^2$}{E=mc2}` |
| "Token not allowed" | Special chars in PDF strings | Use `\texorpdfstring{LaTeX}{LaTeX}` |
| Links in headers/footers | Fragile commands | Use `\protect` or `\texorpdfstring` |
| cleveref not working | Loaded before hyperref | Load order: hyperref → cleveref |
| Link boxes overlap text | Default border style | Use `colorlinks=true` or `hidelinks` |
| `\url` breaks wrong | Long URLs | hyperref handles this; check `breaklinks=true` |
| Conflicts with other packages | Package redefines same commands | Load hyperref after most packages |

## Load Order Guide

```latex
% Safe order (most common packages):
\usepackage{amsmath}
\usepackage{graphicx}
\usepackage{booktabs}
\usepackage{...}          % other packages
\usepackage[options]{hyperref}  % near last
\usepackage{cleveref}           % very last
```

## Tips

- Always use `colorlinks` for screen PDFs; `hidelinks` for print
- `\texorpdfstring{LaTeX version}{plain text}` for anything fancy in section titles
- `\phantomsection` before `\addcontentsline` for correct hyperlinks in unnumbered sections
- `\hypersetup{}` can be called multiple times to change settings mid-document
- Use `\nohyperpage` in index entries to prevent hyperref page linking
