"""burner >] mark. one 48-unit grid, one stroke weight."""
CHAR, PAPER, EMBER, DEEP, ASH, TERM = "#191916", "#f4f1e9", "#fa794a", "#b84a1f", "#c9c7bc", "#121314"
S = 6  # stroke (W/8)

def chevron(color, s=S):
    # arms meet at a mitered tip; butt ends
    return f'<path d="M8 10 L23 24 L8 38" fill="none" stroke="{color}" stroke-width="{s}" stroke-linecap="butt" stroke-linejoin="miter" stroke-miterlimit="10"></path>'

def bracket(color, s=S):
    return f'<path d="M30 8 H39 V40 H30" fill="none" stroke="{color}" stroke-width="{s}" stroke-linecap="butt" stroke-linejoin="miter"></path>'

def mark(fg, accent, s=S):
    return chevron(fg, s) + bracket(accent, s)

def small(fg, accent):
    # 16-24 px drawing: heavier stroke, wider gap, same shape
    return (f'<path d="M7 10 L21 24 L7 38" fill="none" stroke="{fg}" stroke-width="8" stroke-linejoin="miter" stroke-miterlimit="10"></path>'
            f'<path d="M30 8 H40 V40 H30" fill="none" stroke="{accent}" stroke-width="8" stroke-linejoin="miter"></path>')

def tile(field, fg, accent, tiny=False):
    inner = small(fg, accent) if tiny else mark(fg, accent, S * 1.15)
    k = 0.74
    o = 24 * (1 - k)
    return (f'<rect width="48" height="48" rx="12" fill="{field}"></rect>'
            f'<g transform="translate({o} {o}) scale({k})">{inner}</g>')

def avatar(field, fg, accent):
    return (f'<circle cx="24" cy="24" r="24" fill="{field}"></circle>'
            f'<g transform="translate(10.56 10.56) scale(0.56)">{mark(fg, accent, S * 1.3)}</g>')

def svg(body, size, label=None):
    a = f'role="img" aria-label="{label}"' if label else 'aria-hidden="true"'
    return f'<svg {a} width="{size}" height="{size}" viewBox="0 0 48 48" style="display: block">{body}</svg>'

def fav16(field, fg, accent):
    # hand-placed 16x16 drawing for the favicon: whole-pixel bracket, 45 degree chevron
    return (f'<rect width="16" height="16" rx="3.5" fill="{field}"></rect>'
            f'<path d="M3 4 L7 8 L3 12" fill="none" stroke="{fg}" stroke-width="2.2" stroke-linejoin="miter" stroke-miterlimit="10"></path>'
            f'<path d="M10 3 H13 V13 H10 V11 H11 V5 H10 Z" fill="{accent}"></path>')

def svg16(body, size, label=None):
    a = f'role="img" aria-label="{label}"' if label else 'aria-hidden="true"'
    return f'<svg {a} width="{size}" height="{size}" viewBox="0 0 16 16" style="display: block">{body}</svg>'
