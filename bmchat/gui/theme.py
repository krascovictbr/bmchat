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

    # Telegram-specific additions
    online_dot: str = "#4dc920"
    bubble_shadow: str = "#d0d7db"
    bubble_in_shadow: str = "#d1d9de"
    bubble_out_shadow: str = "#c8dcc0"
    date_bg: str = "#a0aab3"
    date_fg: str = "#ffffff"
    reply_bar_in: str = "#37a1de"
    reply_bar_out: str = "#5eb854"
    tick_sent: str = "#5dc452"
    tick_read: str = "#419fd9"
    file_thumb_blue: str = "#419fd9"
    file_thumb_green: str = "#5eb854"
    file_thumb_red: str = "#e17076"
    file_thumb_yellow: str = "#e8a04c"
    scrollbar_width: int = 6

    # Fonts
    font_family: str = "Segoe UI"
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
                "#e17076",
                "#e8a04c",
                "#a695e7",
                "#7fb968",
                "#5fb4d9",
                "#5b9bd5",
                "#ef7fa8",
            ]


LIGHT_THEME = Theme(
    name="light",
    header_bg="#419fd9",
    header_bg_hover="#3a8cc7",
    header_fg="#ffffff",
    header_dim="#d0e4f5",
    panel_bg="#ffffff",
    panel_bg_secondary="#f5f7f8",
    sidebar_bg="#ffffff",
    chat_bg="#e6ebee",
    welcome_bg="#f5f7f8",
    text_primary="#000000",
    text_secondary="#70777b",
    text_muted="#bbbbbb",
    text_on_accent="#ffffff",
    accent="#40a7e3",
    accent_hover="#3a97cc",
    accent_pressed="#2e7fb0",
    accent_fg="#ffffff",
    bubble_in="#ffffff",
    bubble_out="#effdde",
    bubble_in_fg="#000000",
    bubble_out_fg="#000000",
    success="#40c057",
    warning="#fab005",
    error="#fa5252",
    info="#419fd9",
    border="#e6ecf0",
    border_focus="#40a7e3",
    divider="#e6ecf0",
    row_hover="#f1f3f5",
    row_selected="#419fd9",
    row_selected_fg="#ffffff",
    badge_bg="#40a7e3",
    badge_fg="#ffffff",
    unread_badge="#40a7e3",
    unread_badge_fg="#ffffff",
    doodle="#d7e3ec",
    input_bg="#ffffff",
    input_border="#e6ecf0",
    input_fg="#000000",
    input_placeholder="#aab8c2",
    scrollbar_bg="#ffffff",
    scrollbar_thumb="#c4c9cc",
    scrollbar_thumb_hover="#a8adb3",
    tooltip_bg="#212529",
    tooltip_fg="#ffffff",
    online_dot="#4dc920",
    bubble_shadow="#c8d1d6",
    bubble_in_shadow="#d1d9de",
    bubble_out_shadow="#b8d0a8",
    date_bg="#a0aab3",
    date_fg="#ffffff",
    reply_bar_in="#37a1de",
    reply_bar_out="#5eb854",
    tick_sent="#5dc452",
    tick_read="#419fd9",
    file_thumb_blue="#419fd9",
    file_thumb_green="#5eb854",
    file_thumb_red="#e17076",
    file_thumb_yellow="#e8a04c",
    scrollbar_width=6,
)


DARK_THEME = Theme(
    name="dark",
    header_bg="#17212b",
    header_bg_hover="#1e2c3a",
    header_fg="#ffffff",
    header_dim="#aab8c2",
    panel_bg="#17212b",
    panel_bg_secondary="#0e1621",
    sidebar_bg="#17212b",
    chat_bg="#0e1621",
    welcome_bg="#17212b",
    text_primary="#f5f5f5",
    text_secondary="#aab8c2",
    text_muted="#6d7f8f",
    text_on_accent="#ffffff",
    accent="#5288c1",
    accent_hover="#5e96d0",
    accent_pressed="#3d6da3",
    accent_fg="#ffffff",
    bubble_in="#182533",
    bubble_out="#2b5278",
    bubble_in_fg="#f5f5f5",
    bubble_out_fg="#ffffff",
    success="#3fb950",
    warning="#d29922",
    error="#f85149",
    info="#5288c1",
    border="#242f3d",
    border_focus="#5288c1",
    divider="#242f3d",
    row_hover="#202e3a",
    row_selected="#2b5278",
    row_selected_fg="#ffffff",
    badge_bg="#5288c1",
    badge_fg="#ffffff",
    unread_badge="#5288c1",
    unread_badge_fg="#ffffff",
    doodle="#1a2a3a",
    input_bg="#242f3d",
    input_border="#242f3d",
    input_fg="#f5f5f5",
    input_placeholder="#6d7f8f",
    scrollbar_bg="#17212b",
    scrollbar_thumb="#3d4a5a",
    scrollbar_thumb_hover="#4a5a6a",
    tooltip_bg="#f5f5f5",
    tooltip_fg="#0e1621",
    online_dot="#4dc920",
    bubble_shadow="#0a121a",
    bubble_in_shadow="#0a121a",
    bubble_out_shadow="#1a2a3a",
    date_bg="#3a4754",
    date_fg="#ffffff",
    reply_bar_in="#5288c1",
    reply_bar_out="#6abf69",
    tick_sent="#78e378",
    tick_read="#5288c1",
    file_thumb_blue="#5288c1",
    file_thumb_green="#6abf69",
    file_thumb_red="#e17076",
    file_thumb_yellow="#e8a04c",
    scrollbar_width=6,
)


THEMES: Dict[str, Theme] = {
    "light": LIGHT_THEME,
    "dark": DARK_THEME,
}


def get_theme(name: str = "light") -> Theme:
    """Get theme by name, defaulting to light."""
    return THEMES.get(name, LIGHT_THEME)


def register_theme(theme: Theme) -> None:
    """Register a custom theme."""
    THEMES[theme.name] = theme
