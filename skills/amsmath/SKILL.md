---
name: amsmath
description: "LaTeX amsmath/amssymb/mathtools packages for mathematical typesetting. Use when helping users write equations, align math, use mathematical symbols, matrices, theorems, or any advanced math formatting."
---

# amsmath + amssymb + mathtools — Math Typesetting

**CTAN:** https://ctan.org/pkg/amsmath | https://ctan.org/pkg/mathtools  
**Manual:** `texdoc amsmath`, `texdoc mathtools`

## Setup

```latex
\usepackage{amsmath}    % core math environments
\usepackage{amssymb}    % extra symbols (loads amsfonts)
\usepackage{mathtools}  % fixes + extensions for amsmath (loads amsmath)
\usepackage{amsthm}     % theorem environments

% mathtools loads amsmath, so you can just use:
\usepackage{mathtools}
\usepackage{amssymb}
\usepackage{amsthm}
```

## Equation Environments

### Single Equations

```latex
% Numbered
\begin{equation}
  E = mc^2
  \label{eq:einstein}
\end{equation}

% Unnumbered
\begin{equation*}
  E = mc^2
\end{equation*}
% or: \[ E = mc^2 \]
```

### align — Multiple Aligned Equations

```latex
\begin{align}
  f(x) &= x^2 + 2x + 1 \label{eq:f} \\
       &= (x+1)^2       \label{eq:f2}
\end{align}

% Unnumbered: align*
% Suppress single number: \nonumber or \notag before \\
```

### gather — Centered, No Alignment

```latex
\begin{gather}
  x + y = 1 \\
  x - y = 3
\end{gather}
```

### multline — Long Single Equation

```latex
\begin{multline}
  f(x) = a_0 + a_1 x + a_2 x^2 + a_3 x^3 \\
    + a_4 x^4 + a_5 x^5 + a_6 x^6
\end{multline}
```
First line left-aligned, last line right-aligned, middle centered.

### split — Sub-alignment Inside equation

```latex
\begin{equation}
\begin{split}
  f(x) &= a + b + c \\
       &\quad + d + e
\end{split}
\end{equation}
```
Single equation number for the group.

### cases

```latex
\begin{equation}
  |x| = \begin{cases}
    x  & \text{if } x \geq 0 \\
    -x & \text{if } x < 0
  \end{cases}
\end{equation}

% mathtools: dcases (displaystyle), rcases (right brace)
\begin{dcases}
  \frac{x}{2} & x > 0 \\
  0            & x = 0
\end{dcases}
```

### aligned / gathered — Inline Sub-environments

```latex
% Use inside equation or \[ \] for sub-alignment
\begin{equation}
  \left\{
  \begin{aligned}
    2x + 3y &= 7 \\
    x - y   &= 1
  \end{aligned}
  \right.
\end{equation}
```

### subequations

```latex
\begin{subequations} \label{eq:system}
\begin{align}
  x + y &= 1 \label{eq:system_a} \\
  x - y &= 3 \label{eq:system_b}
\end{align}
\end{subequations}
% Produces (1a), (1b)
```

## Environment Summary

| Environment | Alignment | Numbering | Use for |
|-------------|-----------|-----------|---------|
| `equation` | centered | one number | single equation |
| `align` | `&` columns | per line | aligned equations |
| `gather` | centered | per line | unrelated equations |
| `multline` | first L, last R | one number | long equation |
| `split` | `&` columns | one number (parent) | sub-align in equation |
| `cases` | `&` columns | none (in equation) | piecewise functions |
| `aligned` | `&` columns | none (in equation) | inline sub-alignment |
| `flalign` | `&` columns | per line | full-width alignment |

Add `*` for unnumbered variants (except `split`, `aligned`, `gathered`).

## Text in Math

```latex
\text{if }           % normal text (respects surrounding font)
\mathrm{const}       % upright roman
\textit{word}        % italic text
\mathit{diff}        % math italic (different spacing than default)
\mathbf{v}           % bold (not for Greek — use \boldsymbol)
\boldsymbol{\alpha}  % bold Greek
\mathbb{R}           % blackboard bold: ℝ (amssymb)
\mathcal{L}          % calligraphic: ℒ
\mathfrak{g}         % Fraktur (amssymb)
\mathsf{X}           % sans-serif
\mathtt{code}        % monospace
\operatorname{span}  % upright operator (one-off)
```

## Spacing in Math

| Command | Width | Example |
|---------|-------|---------|
| `\,` | 3/18 em (thin) | `\int f(x)\, dx` |
| `\:` or `\>` | 4/18 em (medium) | |
| `\;` | 5/18 em (thick) | |
| `\!` | −3/18 em (negative thin) | `\!\!` to tighten |
| `\quad` | 1 em | `x \quad y` |
| `\qquad` | 2 em | |
| `\phantom{x}` | space of "x" | alignment trick |
| `\hphantom{x}` | horizontal only | |
| `\vphantom{x}` | vertical only | |

## Operators

```latex
% Built-in: \sin, \cos, \tan, \log, \ln, \exp, \min, \max,
%   \sup, \inf, \lim, \det, \dim, \ker, \gcd, \Pr, \hom, ...

% Custom operator (preamble)
\DeclareMathOperator{\tr}{tr}       % like \sin
\DeclareMathOperator*{\argmax}{arg\,max}  % limits below in display

% Usage
\tr(A) = \sum_i a_{ii} \qquad x^* = \argmax_x f(x)
```

## Matrices

```latex
\begin{pmatrix} a & b \\ c & d \end{pmatrix}   % ( )
\begin{bmatrix} a & b \\ c & d \end{bmatrix}   % [ ]
\begin{Bmatrix} a & b \\ c & d \end{Bmatrix}   % { }
\begin{vmatrix} a & b \\ c & d \end{vmatrix}   % | |  (determinant)
\begin{Vmatrix} a & b \\ c & d \end{Vmatrix}   % ‖ ‖
\begin{matrix}  a & b \\ c & d \end{matrix}    % no delimiters

% Small inline matrix
$\bigl(\begin{smallmatrix} a & b \\ c & d \end{smallmatrix}\bigr)$
```

**Max columns default = 10.** For more: `\setcounter{MaxMatrixCols}{20}`

## Delimiters

```latex
% Auto-sizing (use sparingly — can oversize)
\left( \frac{a}{b} \right)
\left[ \sum_i x_i \right]
\left\{ x \in \mathbb{R} \mid x > 0 \right\}
\left. \frac{df}{dx} \right|_{x=0}   % \left. = invisible delimiter

% Manual sizing (preferred for control)
\bigl(  \bigr)    % slightly bigger
\Bigl(  \Bigr)    % bigger
\biggl( \biggr)   % even bigger
\Biggl( \Biggr)   % biggest

% mathtools paired delimiters (best approach)
\DeclarePairedDelimiter\abs{\lvert}{\rvert}
\DeclarePairedDelimiter\norm{\lVert}{\rVert}
\DeclarePairedDelimiter\ceil{\lceil}{\rceil}
\DeclarePairedDelimiter\floor{\lfloor}{\rfloor}
\DeclarePairedDelimiter\set{\{}{\}}

% Usage:
\abs{x}       % |x|  (no sizing)
\abs*{x}      % \left|x\right|  (auto-sizing)
\abs[\big]{x} % \bigl|x\bigr|  (manual)
```

## mathtools Additions

```latex
% Colon equals
\coloneqq   % :=
\eqqcolon   % =:

% dcases (displaystyle fractions in cases)
\begin{dcases} ... \end{dcases}

% rcases (right brace)
\begin{rcases} ... \end{rcases}

% Short intertext (less vertical space than \intertext)
\begin{align}
  f(x) &= x^2 \\
  \shortintertext{where}
  x &> 0
\end{align}

% Prescript (left sub/superscript)
\prescript{14}{6}{\mathrm{C}}   % ¹⁴₆C

% Cramped styles
\cramped{x^{x^x}}  % reduces height

% Smashed operator limits
\smashoperator{\sum_{i=1}^{n}}
```

## Symbol Reference

### Greek Letters

| Lower | Upper | Lower | Upper |
|-------|-------|-------|-------|
| `\alpha` α | — | `\nu` ν | — |
| `\beta` β | — | `\xi` ξ | `\Xi` Ξ |
| `\gamma` γ | `\Gamma` Γ | `\pi` π | `\Pi` Π |
| `\delta` δ | `\Delta` Δ | `\rho` ρ | — |
| `\epsilon` ε | — | `\sigma` σ | `\Sigma` Σ |
| `\varepsilon` ε | — | `\tau` τ | — |
| `\zeta` ζ | — | `\upsilon` υ | `\Upsilon` Υ |
| `\eta` η | — | `\phi` ϕ | `\Phi` Φ |
| `\theta` θ | `\Theta` Θ | `\varphi` φ | — |
| `\iota` ι | — | `\chi` χ | — |
| `\kappa` κ | — | `\psi` ψ | `\Psi` Ψ |
| `\lambda` λ | `\Lambda` Λ | `\omega` ω | `\Omega` Ω |
| `\mu` μ | — | | |

Variants: `\varepsilon`, `\vartheta`, `\varphi`, `\varrho`, `\varsigma`

### Relations

| Symbol | Command | Symbol | Command |
|--------|---------|--------|---------|
| ≤ | `\leq` | ≥ | `\geq` |
| ≪ | `\ll` | ≫ | `\gg` |
| ≠ | `\neq` | ≈ | `\approx` |
| ∼ | `\sim` | ≃ | `\simeq` |
| ≡ | `\equiv` | ≅ | `\cong` |
| ∝ | `\propto` | ∈ | `\in` |
| ∉ | `\notin` | ⊂ | `\subset` |
| ⊆ | `\subseteq` | ⊃ | `\supset` |
| ⊇ | `\supseteq` | ⊄ | `\not\subset` |
| ≺ | `\prec` | ≻ | `\succ` |
| ⊥ | `\perp` | ∥ | `\parallel` |
| ⊢ | `\vdash` | ⊣ | `\dashv` |
| ⊨ | `\models` | | |

### Binary Operators

| Symbol | Command | Symbol | Command |
|--------|---------|--------|---------|
| ± | `\pm` | ∓ | `\mp` |
| × | `\times` | ÷ | `\div` |
| · | `\cdot` | ∗ | `\ast` |
| ⊕ | `\oplus` | ⊗ | `\otimes` |
| ∪ | `\cup` | ∩ | `\cap` |
| ∨ | `\vee` | ∧ | `\wedge` |
| ∘ | `\circ` | • | `\bullet` |
| † | `\dagger` | ‡ | `\ddagger` |

### Arrows

| Symbol | Command | Symbol | Command |
|--------|---------|--------|---------|
| → | `\to` / `\rightarrow` | ← | `\leftarrow` |
| ⇒ | `\Rightarrow` | ⇐ | `\Leftarrow` |
| ↔ | `\leftrightarrow` | ⇔ | `\Leftrightarrow` |
| ↦ | `\mapsto` | ⟶ | `\longrightarrow` |
| ↑ | `\uparrow` | ↓ | `\downarrow` |
| ⇑ | `\Uparrow` | ⇓ | `\Downarrow` |
| ↗ | `\nearrow` | ↘ | `\searrow` |
| ⟹ | `\implies` | ⟸ | `\impliedby` |
| ⟺ | `\iff` | | |
| ↪ | `\hookrightarrow` | ↠ | `\twoheadrightarrow` |

### Big Operators

| Symbol | Command | Symbol | Command |
|--------|---------|--------|---------|
| ∑ | `\sum` | ∏ | `\prod` |
| ∫ | `\int` | ∮ | `\oint` |
| ∬ | `\iint` | ∭ | `\iiint` |
| ⋃ | `\bigcup` | ⋂ | `\bigcap` |
| ⨁ | `\bigoplus` | ⨂ | `\bigotimes` |
| ⋁ | `\bigvee` | ⋀ | `\bigwedge` |
| ∐ | `\coprod` | | |

### Dots

| Command | Output | Use |
|---------|--------|-----|
| `\cdots` | ⋯ | between operators: $a + \cdots + z$ |
| `\ldots` | … | in lists: $a_1, \ldots, a_n$ |
| `\vdots` | ⋮ | vertical |
| `\ddots` | ⋱ | diagonal (matrices) |

### Misc Symbols (amssymb)

| Symbol | Command | Symbol | Command |
|--------|---------|--------|---------|
| ℝ | `\mathbb{R}` | ℂ | `\mathbb{C}` |
| ℤ | `\mathbb{Z}` | ℕ | `\mathbb{N}` |
| ℚ | `\mathbb{Q}` | ∅ | `\emptyset` / `\varnothing` |
| ∞ | `\infty` | ∂ | `\partial` |
| ∇ | `\nabla` | ℓ | `\ell` |
| ℏ | `\hbar` | ∀ | `\forall` |
| ∃ | `\exists` | ¬ | `\neg` |
| √ | `\sqrt{x}` | ⁿ√ | `\sqrt[n]{x}` |
| ∠ | `\angle` | △ | `\triangle` |
| ⊤ | `\top` | ⊥ | `\bot` |
| ♠ | `\spadesuit` | ♣ | `\clubsuit` |

### Accents

| Command | Result | Use |
|---------|--------|-----|
| `\hat{a}` | â | unit vectors |
| `\bar{a}` | ā | averages, conjugates |
| `\vec{a}` | a⃗ | vectors |
| `\dot{a}` | ȧ | time derivative |
| `\ddot{a}` | ä | second derivative |
| `\tilde{a}` | ã | approximations |
| `\widehat{abc}` | wide hat | spanning |
| `\widetilde{abc}` | wide tilde | spanning |
| `\overline{abc}` | overline | sets, conjugates |
| `\underline{abc}` | underline | |
| `\overbrace{a+b}^{n}` | over-brace | grouping |
| `\underbrace{a+b}_{n}` | under-brace | grouping |

## Theorem Environments (amsthm)

```latex
\usepackage{amsthm}

% Define theorem types (preamble)
\newtheorem{theorem}{Theorem}[section]     % numbered by section
\newtheorem{lemma}[theorem]{Lemma}         % shares theorem counter
\newtheorem{corollary}[theorem]{Corollary}
\newtheorem{proposition}[theorem]{Proposition}

\theoremstyle{definition}
\newtheorem{definition}[theorem]{Definition}
\newtheorem{example}[theorem]{Example}

\theoremstyle{remark}
\newtheorem{remark}[theorem]{Remark}

% Usage
\begin{theorem}[Pythagoras]
  For a right triangle: $a^2 + b^2 = c^2$.
\end{theorem}

\begin{proof}
  Obvious. % ends with □ automatically
  % Use \qedhere to place □ at end of equation:
  % \[ a^2 + b^2 = c^2 \qedhere \]
\end{proof}
```

### Theorem Styles

| Style | Body font | Header | Use for |
|-------|-----------|--------|---------|
| `plain` (default) | italic | bold | theorems, lemmas |
| `definition` | upright | bold | definitions, examples |
| `remark` | upright | italic | remarks, notes |

## Common Pitfalls

| Problem | Cause | Fix |
|---------|-------|-----|
| `$$...$$` | TeX primitive, bad spacing | Use `\[...\]` or `equation*` |
| `eqnarray` | Bad spacing around `=` | Use `align` instead (always) |
| Equation number on wrong line | `\\` after last line | Remove trailing `\\` |
| `\left...\right` across lines | Can't span `\\` | Use `\bigl...\bigr` manually |
| Bold Greek | `\mathbf` doesn't work | Use `\boldsymbol{\alpha}` |
| Missing `\displaystyle` | Fractions small inline | Use `\dfrac` (or `\displaystyle\frac`) |
| `:=` spacing wrong | Colon treated as relation | Use `\coloneqq` (mathtools) |
| `\mid` vs `\|` vs `|` | Different spacing | `\mid` for "divides"/"given", `\|` for norms |
| Overfull hbox in equation | Equation too wide | Use `multline`, `split`, or manual breaks |
| Proof box missing | \qed inside environment | Use `\qedhere` at the end |
