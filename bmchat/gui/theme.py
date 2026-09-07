"""Theme system for bmchat — supports light and dark modes."""

from dataclasses import dataclass
from typing import Dict, List


@dataclass
class Theme:
    """Complete color theme for the application."""
    name: str

    # Header / toolbar
    header_bg: str
    header_bg_hover: str
    header_fg: str
    header_dim: str

    # Panels / backgrounds
    panel_bg: str
    panel_bg_secondary: str
    sidebar_bg: str
    chat_bg: str
    welcome_bg: str

    # Text colors
    text_primary: str
    text_secondary: str
    text_muted: str
    text_on_accent: str

    # Interactive elements
    accent: str
    accent_hover: str
    accent_pressed: str
    accent_fg: str

    # Bubbles
    bubble_in: str
    bubble_out: str
    bubble_in_fg: str
    bubble_out_fg: str

    # Status / feedback
    success: str
    warning: str
    error: str
    info: str

    # Borders / dividers
    border: str
    border_focus: str
    divider: str

    # Row states
    row_hover: str
    row_selected: str
    row_selected_fg: str

    # Badges / indicators
    badge_bg: str
    badge_fg: str
    unread_badge: str
    unread_badge_fg: str

    # Doodle / decorative
    doodle: str

    # Input
    input_bg: str
    input_border: str
    input_fg: str
    input_placeholder: str

    # Scrollbar
    scrollbar_bg: str
    scrollbar_thumb: str
    scrollbar_thumb_hover: str

    # Tooltip
    tooltip_bg: str
    tooltip_fg: str

    # Fonts
    font_family: str = 'Segoe UI'
    font_size: int = 10
    font_size_small: int = 9
    font_size_large: int = 12
    font_size_title: int = 14

    # Spacing
    spacing_xs: int = 4
    spacing_sm: int = 8
    spacing_md: int = 12
    spacing_lg: int = 16
    spacing_xl: int = 24

    # Border radius
    radius_sm: int = 4
    radius_md: int = 8
    radius_lg: int = 12
    radius_full: int = 999

    # Sender colors for group chats
    sender_colors: List[str] | None = None

    def __post_init__(self):
        if self.sender_colors is None:
            self.sender_colors = [
                '#e17076', '#e8a04c', '#a695e7', '#7fb968',
                '#5fb4d9', '#5b9bd5', '#ef7fa8',
            ]


LIGHT_THEME = Theme(
    name='light',

    header_bg='#4a6fa5',
    header_bg_hover='#3d5d8a',
    header_fg='#ffffff',
    header_dim='#b8c9db',

    panel_bg='#ffffff',
    panel_bg_secondary='#f8f9fa',
    sidebar_bg='#f1f3f5',
    chat_bg='#e8f0d9',
    welcome_bg='#f8f9fa',

    text_primary='#1a1d21',
    text_secondary='#495057',
    text_muted='#868e96',
    text_on_accent='#ffffff',

    accent='#4dabf7',
    accent_hover='#339af0',
    accent_pressed='#228be6',
    accent_fg='#ffffff',

    bubble_in='#ffffff',
    bubble_out='#e9f5db',
    bubble_in_fg='#1a1d21',
    bubble_out_fg='#1a1d21',

    success='#40c057',
    warning='#fab005',
    error='#fa5252',
    info='#4dabf7',

    border='#dee2e6',
    border_focus='#4dabf7',
    divider='#e9ecef',

    row_hover='#f1f3f5',
    row_selected='#e7f5ff',
    row_selected_fg='#1a1d21',

    badge_bg='#4dabf7',
    badge_fg='#ffffff',
    unread_badge='#4dabf7',
    unread_badge_fg='#ffffff',

    doodle='#c0d8a0',

    input_bg='#ffffff',
    input_border='#ced4da',
    input_fg='#1a1d21',
    input_placeholder='#adb5bd',

    scrollbar_bg='#f1f3f5',
    scrollbar_thumb='#adb5bd',
    scrollbar_thumb_hover='#868e96',

    tooltip_bg='#212529',
    tooltip_fg='#ffffff',
)


DARK_THEME = Theme(
    name='dark',

    header_bg='#1e2a3a',
    header_bg_hover='#253547',
    header_fg='#ffffff',
    header_dim='#6c7a89',

    panel_bg='#1a1e24',
    panel_bg_secondary='#21262d',
    sidebar_bg='#161b22',
    chat_bg='#161b22',
    welcome_bg='#1a1e24',

    text_primary='#f0f6fc',
    text_secondary='#8b949e',
    text_muted='#6e7681',
    text_on_accent='#ffffff',

    accent='#58a6ff',
    accent_hover='#79b8ff',
    accent_pressed='#388bfd',
    accent_fg='#ffffff',

    bubble_in='#21262d',
    bubble_out='#2d3a4d',
    bubble_in_fg='#f0f6fc',
    bubble_out_fg='#f0f6fc',

    success='#3fb950',
    warning='#d29922',
    error='#f85149',
    info='#58a6ff',

    border='#30363d',
    border_focus='#58a6ff',
    divider='#21262d',

    row_hover='#21262d',
    row_selected='#1f3a5f',
    row_selected_fg='#f0f6fc',

    badge_bg='#58a6ff',
    badge_fg='#ffffff',
    unread_badge='#58a6ff',
    unread_badge_fg='#ffffff',

    doodle='#2d3a4d',

    input_bg='#0d1117',
    input_border='#30363d',
    input_fg='#f0f6fc',
    input_placeholder='#6e7681',

    scrollbar_bg='#161b22',
    scrollbar_thumb='#30363d',
    scrollbar_thumb_hover='#484f58',

    tooltip_bg='#f0f6fc',
    tooltip_fg='#1a1d21',
)


THEMES: Dict[str, Theme] = {
    'light': LIGHT_THEME,
    'dark': DARK_THEME,
}


def get_theme(name: str = 'light') -> Theme:
    """Get theme by name, defaulting to light."""
    return THEMES.get(name, LIGHT_THEME)


def register_theme(theme: Theme) -> None:
    """Register a custom theme."""
    THEMES[theme.name] = theme