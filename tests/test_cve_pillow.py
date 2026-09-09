"""Regressão das CVEs de Pillow (fix/security-20260908, FASE 3).

Cobre a defesa em profundidade em `bmchat/gui/app.py`:
`_open_image_for_layout` / `_open_image_for_render` recusam formatos
fora de `ALLOWED_PREVIEW_FORMATS` (CVE-2026-25990, CVE-2026-40192,
CVE-2026-42311, CVE-2026-59204 — decoders PSD/FITS/JPEG2000 alcançáveis
via `Image.open().load()` em bytes vindos de peer) e o piso de versões
do `requirements.txt` (Pillow>=12.3.0 corrige as 18 CVEs que afetam a
11.3.0; ecdsa>=0.19.2 contém a correção da CVE-2026-33936;
pycryptodome>=3.19.1 contém a da CVE-2023-52323).
"""

import base64
import os
from io import BytesIO

import pytest

from bmchat.gui.app import (
    ALLOWED_PREVIEW_FORMATS,
    App,
)


# Magic bytes mínimos suficientes para o sniffing de formato do Pillow
# (prefixos avaliados pelos `_accept` dos plugins, sem payload válido).
PSD_MAGIC = b'8BPS\x00\x01' + b'\x00' * 64
FITS_MAGIC = b'SIMPLE  =                    T' + b'\x00' * 64
JP2_MAGIC = b'\x00\x00\x00\x0cjP  \r\n\x87\n' + b'\x00' * 64


def _png_bytes(size=(10, 10)):
    PIL = pytest.importorskip('PIL')
    from PIL import Image
    assert PIL is not None
    img = Image.new('RGB', size, color='red')
    buf = BytesIO()
    img.save(buf, format='PNG')
    return buf.getvalue()


def test_preview_allowlist_covers_common_photo_formats():
    assert ALLOWED_PREVIEW_FORMATS == frozenset(
        {'PNG', 'JPEG', 'GIF', 'BMP', 'WEBP'})


def test_layout_helper_loads_valid_png():
    data = _png_bytes()
    img = App._open_image_for_layout(data)
    assert img is not None
    assert img.size == (10, 10)


def test_render_helper_loads_valid_png():
    data = _png_bytes()
    img = App._open_image_for_render(data)
    assert img is not None
    assert img.size == (10, 10)


@pytest.mark.parametrize('blob', [PSD_MAGIC, FITS_MAGIC, JP2_MAGIC])
def test_layout_helper_refuses_risky_decoders(blob):
    assert App._open_image_for_layout(blob) is None


@pytest.mark.parametrize('blob', [PSD_MAGIC, FITS_MAGIC, JP2_MAGIC])
def test_render_helper_refuses_risky_decoders(blob):
    assert App._open_image_for_render(blob) is None


def test_helpers_refuse_garbage():
    assert App._open_image_for_layout(b'\x00\x01\x02\x03' * 64) is None
    assert App._open_image_for_render(b'\x00\x01\x02\x03' * 64) is None


def test_attachment_height_falls_back_to_icon_for_psd():
    payload = base64.b64encode(PSD_MAGIC).decode('ascii')
    attachment = {'mime': 'image/psd', 'data': payload}
    assert App._calc_attachment_height(App, attachment, 300, False) == 48


def _parse_minimums():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, 'requirements.txt')
    minimums = {}
    with open(path, encoding='utf-8') as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith('#') or '>=' not in line:
                continue
            name, version = line.split('>=', 1)
            minimums[name.strip().lower()] = version.strip()
    return minimums


def _at_least(actual, wanted):
    def parts(text):
        return [int(piece) for piece in text.split('.')]
    return parts(actual) >= parts(wanted)


def test_requirements_pins_fixed_versions():
    minimums = _parse_minimums()
    assert _at_least(minimums.get('pillow', '0'), '12.3.0')
    assert _at_least(minimums.get('ecdsa', '0'), '0.19.2')
    assert _at_least(minimums.get('pycryptodome', '0'), '3.19.1')
    assert 'pysocks' in minimums
