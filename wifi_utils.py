import pywifi  # pyright: ignore[reportMissingImports]
from pywifi import const  # pyright: ignore[reportMissingImports]
import time

def get_card():
    try:
        wifi = pywifi.PyWiFi()
        ifaces = wifi.interfaces()
        if not ifaces:
            return None
        card = ifaces[0]
        card.disconnect()
        time.sleep(1)
        status = card.status()
        if status not in [const.IFACE_DISCONNECTED, const.IFACE_INACTIVE]:
            return None
        return card
    except Exception as e:
        print(f"Error getting WiFi card: {e}")
        return None

def scan_wifi(card, wait_time=2):
    try:
        card.scan()
        time.sleep(wait_time)
        return card.scan_results()
    except Exception as e:
        print(f"Error scanning WiFi: {e}")
        return []

def detect_encryption(wifi_info):
    # Try to detect encryption type
    if hasattr(wifi_info, "akm"):
        if const.AKM_TYPE_WPA2PSK in wifi_info.akm:
            return "WPA2"
        elif const.AKM_TYPE_WPAPSK in wifi_info.akm:
            return "WPA"
        elif const.AKM_TYPE_NONE in wifi_info.akm:
            return "OPEN"
    if hasattr(wifi_info, "auth"):
        if wifi_info.auth == const.AUTH_ALG_SHARED:
            return "WEP"
    return "UNKNOWN"

def connect_to_wifi(pwd, ssid, card, encryption="WPA2"):
    try:
        profile = pywifi.Profile()
        profile.ssid = ssid
        profile.key = pwd
        profile.auth = const.AUTH_ALG_OPEN
        if encryption == "WPA2":
            profile.akm = [const.AKM_TYPE_WPA2PSK]
            profile.cipher = const.CIPHER_TYPE_CCMP
        elif encryption == "WPA":
            profile.akm = [const.AKM_TYPE_WPAPSK]
            profile.cipher = const.CIPHER_TYPE_TKIP
        elif encryption == "WEP":
            profile.akm = [const.AKM_TYPE_NONE]
            profile.cipher = const.CIPHER_TYPE_WEP
        else:
            profile.akm = [const.AKM_TYPE_NONE]
            profile.cipher = const.CIPHER_TYPE_NONE

        card.remove_all_network_profiles()
        tmp_profile = card.add_network_profile(profile)
        card.connect(tmp_profile)
        time.sleep(2)
        is_connected = card.status() == const.IFACE_CONNECTED
        card.disconnect()
        time.sleep(1)
        return is_connected
    except Exception as e:
        print(f"Error connecting to WiFi: {e}")
        return False