---
name: graphicx
description: "LaTeX graphicx package for image inclusion and manipulation. Use when helping users insert images, resize graphics, create figure environments, or work with subfigures."
---

# graphicx — Image Inclusion & Manipulation

**CTAN:** https://ctan.org/pkg/graphicx  
**Manual:** `texdoc graphicx`

## Setup

```latex
\usepackage{graphicx}

% Set default search paths for images
\graphicspath{{images/}{figures/}{./}}
```

## \includegraphics Options

```latex
\includegraphics[options]{filename}
```

| Option | Example | Description |
|--------|---------|-------------|
| `width` | `width=0.8\textwidth` | Scale to width |
| `height` | `height=5cm` | Scale to height |
| `scale` | `scale=0.5` | Scale factor |
| `angle` | `angle=90` | Rotate (counterclockwise, degrees) |
| `trim` | `trim=1cm 2cm 1cm 0cm` | Crop: left bottom right top |
| `clip` | `clip` | Must accompany `trim` to actually crop |
| `page` | `page=3` | Page of multi-page PDF |
| `keepaspectratio` | `keepaspectratio` | Maintain ratio when both width+height set |
| `draft` | `draft` | Show filename box instead of image |
| `bb` | `bb=0 0 100 100` | Bounding box (EPS) |
| `viewport` | `viewport=50 50 200 200` | View sub-region (with `clip`) |
| `resolution` | `resolution=300` | DPI for bitmap without natural size |

```latex
% Common patterns
\includegraphics[width=\textwidth]{photo}
\includegraphics[width=0.48\textwidth]{fig1}
\includegraphics[height=4cm, keepaspectratio]{diagram}
\includegraphics[angle=90, width=0.5\textwidth]{landscape}
\includegraphics[trim=10mm 5mm 10mm 5mm, clip, width=\linewidth]{screenshot}
\includegraphics[page=2, width=\textwidth]{multipage.pdf}
```

## Supported Formats by Engine

| Engine | Vector | Raster |
|--------|--------|--------|
| pdfLaTeX | PDF, EPS (auto-converted) | PNG, JPG |
| XeLaTeX | PDF, EPS | PNG, JPG, BMP |
| LuaLaTeX | PDF, EPS | PNG, JPG |
| LaTeX→DVI | EPS | (none natively) |

**Best practice:** Use PDF for vector graphics, PNG for screenshots/diagrams with transparency, JPG for photos.

## Scaling & Rotating Commands

```latex
% Scale content (text or images)
\scalebox{2}{Doubled}
\scalebox{0.5}[1.5]{Stretched}  % [horizontal]{vertical}

% Resize to exact dimensions
\resizebox{3cm}{!}{Content}     % ! = keep aspect ratio
\resizebox{!}{2cm}{Content}
\resizebox{3cm}{2cm}{Content}   % exact (may distort)

% Rotate
\rotatebox{45}{Rotated text}
\rotatebox[origin=c]{90}{Centered rotation}
% origin: l, r, c, t, b, lt, rb, etc.
```

## Figure Environment

```latex
\begin{figure}[htbp]   % placement: here, top, bottom, page
  \centering
  \includegraphics[width=0.8\textwidth]{plot.pdf}
  \caption{Experimental results showing growth over time.}
  \label{fig:results}
\end{figure}

% Reference: See Figure~\ref{fig:results}.
```

### Placement Specifiers

| Spec | Meaning |
|------|---------|
| `h` | Here (approximately) |
| `t` | Top of page |
| `b` | Bottom of page |
| `p` | Separate float page |
| `!` | Override internal limits |
| `H` | Exactly here (requires `float` package) |

**Tip:** Use `[htbp]` as default. Avoid `[H]` unless necessary.

## Subfigures

```latex
\usepackage{subcaption}  % preferred over subfig/subfigure

\begin{figure}[htbp]
  \centering
  \begin{subfigure}[b]{0.48\textwidth}
    \centering
    \includegraphics[width=\textwidth]{fig_a.pdf}
    \caption{First result}
    \label{fig:sub_a}
  \end{subfigure}
  \hfill
  \begin{subfigure}[b]{0.48\textwidth}
    \centering
    \includegraphics[width=\textwidth]{fig_b.pdf}
    \caption{Second result}
    \label{fig:sub_b}
  \end{subfigure}
  \caption{Comparison of results. (a) shows X, (b) shows Y.}
  \label{fig:comparison}
\end{figure}
```

### Three Subfigures in a Row

```latex
\begin{figure}[htbp]
  \centering
  \begin{subfigure}[b]{0.32\textwidth}
    \centering
    \includegraphics[width=\textwidth]{a}
    \caption{A}
  \end{subfigure}
  \hfill
  \begin{subfigure}[b]{0.32\textwidth}
    \centering
    \includegraphics[width=\textwidth]{b}
    \caption{B}
  \end{subfigure}
  \hfill
  \begin{subfigure}[b]{0.32\textwidth}
    \centering
    \includegraphics[width=\textwidth]{c}
    \caption{C}
  \end{subfigure}
  \caption{Three results side by side.}
\end{figure}
```

## Overlays with overpic

```latex
\usepackage{overpic}

\begin{overpic}[width=0.8\textwidth, grid, tics=10]{photo.jpg}
  % Coordinates are percentages (0-100)
  \put(20,80){\color{red}\Large\textbf{Label A}}
  \put(70,30){\vector(-1,1){15}}
\end{overpic}
```

Remove `grid, tics=10` after positioning. Coordinates are percentage-based.

## Wrapfigure (Text Wrapping)

```latex
\usepackage{wrapfig}

\begin{wrapfigure}{r}{0.4\textwidth}  % r=right, l=left
  \centering
  \includegraphics[width=0.38\textwidth]{small_fig}
  \caption{Side figure.}
\end{wrapfigure}
Text flows around the figure here...
```

## Common Pitfalls

| Problem | Cause | Fix |
|---------|-------|-----|
| "File not found" | Wrong path or extension | Check `\graphicspath`, omit extension |
| "Unknown graphics extension .eps" | pdfLaTeX can't use raw EPS | Use `epstopdf` package (auto-converts) or switch to PDF |
| Blurry images | Low resolution raster | Use ≥300 DPI or vector format |
| Figure floats away | LaTeX float algorithm | Use `[htbp!]`, add `\FloatBarrier` (placeins pkg) |
| Overfull hbox with subfigures | Widths sum > \textwidth | Ensure widths + gaps < 1.0\textwidth |
| `trim` not cropping | Missing `clip` | Always pair `trim` with `clip` |
| Image upside down | Camera EXIF rotation | Pre-rotate or use `angle=180` |
| Subfigure numbering wrong | Using deprecated `subfigure` pkg | Switch to `subcaption` |

## Tips

- Omit file extensions — LaTeX picks the best format automatically
- Use `\linewidth` inside minipages/columns, `\textwidth` at top level
- For publication: vector (PDF/EPS) for plots, high-DPI PNG/JPG for photos
- `\DeclareGraphicsExtensions{.pdf,.png,.jpg}` to set search priority
- `draft` option on `\documentclass` replaces all images with boxes (faster compilation)
