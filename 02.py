import pywifi  # pyright: ignore[reportMissingImports]
from pywifi import const  # pyright: ignore[reportMissingImports]
import time
#https://github.com/microsoft/pylance-release/blob/main/docs/diagnostics/reportMissingImports.md
# Use comments like # pyright: ignore[reportMissingImports] to suppress warnings for optional or platform-specific imports.

#get the wifi card

def get_card():
    wifi = pywifi.PyWiFi()
    card = wifi.interfaces()[0]  # Get the first wifi card
    card.disconnect
    time.sleep(1)
    status = card.status()
    if status not in [const.IFACE_DISCONNECTED, const.IFACE_INACTIVE]:
        print("Disconnecting from current network...")
        return False
    return card

# Scan for available networks
def scan_wifi(card):
    print("Scanning for networks...")
    card.scan()
    time.sleep(15)  # Wait for the scan to complete
    wifi_list = card.scan_results()
    print(wifi_list)
card = get_card()
scan_wifi(card)
# Note: The above code assumes that the pywifi library is installed and available in your Python environment.    
