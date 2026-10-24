from __future__ import annotations

import re

from .models import DevicePresentation, Neighbor


DEVICE_RULES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("📱", "Mobile", ("iphone", "ipad", "android", "galaxy", "pixel", "mobile", "phone")),
    ("🎮", "Game Console", ("playstation", "ps4", "ps5", "xbox", "nintendo", "switch")),
    ("📺", "Television", ("smarttv", "smart-tv", "appletv", "chromecast", "google cast", "roku", "firetv", "television", "skyworth", "8008/http", "8009/ajp13", "8060/http")),
    ("🖨️", "Printer", ("printer", "laserjet", "officejet", "deskjet", "epson", "brother", "631/ipp", "9100/jetdirect", "515/printer")),
    ("📷", "Camera", ("camera", "webcam", "doorbell", "ring", "wyze", "reolink", "554/rtsp")),
    ("🔊", "Speaker", ("speaker", "homepod", "sonos", "echo", "alexa")),
    ("🔌", "Smart Device", ("plug", "bulb", "light", "hue", "tuya", "tapo", "iot", "1883/mqtt", "8883/secure-mqtt")),
    ("🗄️", "Server / NAS", ("server", "nas", "synology", "qnap", "raspberry", "pi-hole", "32400/plex", "8123/http")),
    ("💻", "Computer", ("macbook", "imac", "desktop", "laptop", "notebook", "thinkpad", "workstation", "pc")),
)


def _search_text(neighbor: Neighbor) -> str:
    return " ".join(filter(None, (neighbor.hostname, neighbor.vendor, neighbor.model, *neighbor.services))).lower()


def present(neighbor: Neighbor) -> DevicePresentation:
    if neighbor.is_gateway:
        emoji, device_type = "🌐", "Router"
    else:
        text = _search_text(neighbor)
        emoji, device_type = "📡", "Unknown Device"
        for candidate_emoji, candidate_type, keywords in DEVICE_RULES:
            if any(re.search(rf"(?:^|[^a-z0-9]){re.escape(word)}(?:[^a-z0-9]|$)", text) for word in keywords):
                emoji, device_type = candidate_emoji, candidate_type
                break

    if neighbor.is_self:
        status = "This device"
    elif neighbor.responsive:
        status = "Online"
    else:
        status = "Discovered"

    name = neighbor.hostname or neighbor.model or (
        "Unknown" if neighbor.vendor == "Private / randomized MAC" else neighbor.vendor
    ) or "Unknown"
    return DevicePresentation(emoji=emoji, device_type=device_type, name=name, status=status)

