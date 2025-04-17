# pwnagotchi-rulesdic
Plugins for pwnagotchi to run a wordlist based on the ESSID. The main goal is to target weak Wi-Fi, like IoT or devices with default passwords.  
For educational purposes only, run it on your OWN Wi-Fi.

# Install
- Install dependencies:
  ```bash
  sudo apt-get install hashcat hcxtools
  ```
- Copy `rulesdic.py` into your custom plugin directory:
  ```bash
  cp rulesdic.py /usr/local/share/pwnagotchi/custom-plugins/
  ```
- Restart your Pwnagotchi:
  ```bash
  sudo systemctl restart pwnagotchi
  ```
- Cracked passwords are stored in the `hashcat.potfile`.

Cracked passwords are also available by clicking on `rulesdic` in the plugin page.

# Config.toml
```toml
main.plugins.rulesdic.enabled = true
main.plugins.rulesdic.tmp_folder = '/my/tmp/folder' # optional, default: /tmp
main.plugins.rulesdic.max_essid_len = 12 # optional, if set to -1 -> no limit, else does not generate leet rule if len(essid) > max_essid_len
main.plugins.rulesdic.exclude = [  # REGEXP to match the Wi-Fi name
    "^Android",
    "^[Ii][Pp]hone"
]
main.plugins.rulesdic.include = [  # REGEXP to include specific Wi-Fi names or BSSIDs
    "^MyWiFi",
    "00:11:22:33:44:55"
]
main.plugins.rulesdic.vendors = [  # REGEXP to match vendor OUIs
    "^00:1A:2B",  # Cisco Systems
    "^F4:5C:89",  # Apple, Inc.
    "^00:16:6F"   # Samsung Electronics
]
main.plugins.rulesdic.handshakes_dir = '/home/pi/handshakes' # default
main.plugins.rulesdic.max_crack_time = 5  # defaults to 10 minutes if not defined, you can also use -1 for Infinite cracking time
```

# Features
- **Dynamic Wordlist Generation**: Generates a wordlist based on the ESSID with rules for leet transformations, punctuation, years, and more.
- **Real-Time Feedback**: Displays progress updates, elapsed time, and cracking status on the display.
- **Dynamic Faces**: Shows different faces (happy, sad, neutral, angry) based on the current state of the cracking process.
- **Vendor Filtering**: Allows filtering of handshakes based on vendor OUI patterns.
- **Include/Exclude Filters**: Processes handshakes based on user-defined ESSID/BSSID patterns.
- **Web Interface**: Displays a list of cracked passwords via a web interface.
- **Pot File Storage**: Cracked passwords are stored in the `hashcat.potfile`.

# Password Wordlist Generated
- **Basic**: Upper, lower, capitalized, reversed.
- **Punctuation and Years**: Adds punctuation and/or years (1900 until today) in several orders.
- **Leet**: Generates leet-style transformations (e.g., `a -> 4`, `e -> 3`), if `len(essid) <= max_essid_len`.

# Web Interface
- Access the list of cracked passwords via the web interface:
  ```
  http://<pwnagotchi-ip>:8080/plugins/rulesdic/
  ```
- The web interface includes a search bar to filter results by SSID.

# Display Feedback
The plugin uses dynamic faces to represent the current state:
- **Neutral**: `(≡·≡)`, `(•_•)`, `(¬_¬)`
- **Happy**: `(•‿•)`, `(✧≖‿ゝ≖)`, `(＾▽＾)`
- **Sad**: `(╥﹏╥)`, `(ಥ﹏ಥ)`, `(T_T)`
- **Angry**: `(╯°□°）╯︵ ┻━┻`, `(ಠ_ಠ)`, `(ノಠ益ಠ)ノ彡┻━┻`

### Example Display Messages
- **Processing Handshake**: `(≡·≡) Processing handshake...`
- **Handshake Found**: `(•‿•) Handshake found! Time: 5.23s`
- **Cracking in Progress**: `(•_•) Cracking... Elapsed: 2.5 min`
- **Password Cracked**: `(✧≖‿ゝ≖) Password cracked: mypassword123`
- **Failure**: `(ಥ﹏ಥ) Password not found`

# TODO
- [X] Try with hashcat as it seems more efficient, instead of aircrack-ng.
- [X] Limit hashcat duration as we don't want to make them run for hours but perhaps 5-10 min max.
- [X] Improve exclude and add include options to select which Wi-Fi to target, perhaps with vendors :-).
- [X] Add some cool messages and faces on display. It's a bit boring right now.
- [ ] Hack the World!

# Based On
- https://github.com/SilenTree12th/pwnagotchi_plugins/blob/main/better_quickdic.py (main logic)
- https://github.com/xfox64x/pwnagotchi_plugins/blob/master/quick_rides_to_jail/quick_rides_to_jail.py (regexp :-) )
- wpa-sec-list (webhook)

Have fun!

Version: 1.0.6
