import logging
import os
import re
import subprocess
import resource
import pathlib
import time  # Add this import for time tracking
from itertools import product
from datetime import datetime
from string import punctuation
from flask import abort, send_from_directory, render_template_string

import pwnagotchi.plugins as plugins
from pwnagotchi.utils import StatusFile
from json.decoder import JSONDecodeError

crackable_handshake_re = re.compile(
    r'\s+\d+\s+(?P<bssid>([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})\s+(?P<ssid>.+?)\s+((\([1-9][0-9]* handshake(, with PMKID)?\))|(\(\d+ handshake, with PMKID\)))')

TEMPLATE = """
{% extends "base.html" %}
{% set active_page = "passwordsList" %}
{% block title %}
    {{ title }}
{% endblock %}
{% block meta %}
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, user-scalable=0" />
{% endblock %}
{% block styles %}
{{ super() }}
    <style>
        #searchText {
            width: 100%;
        }
        table {
            table-layout: auto;
            width: 100%;
        }
        table, th, td {
            border: 1px solid;
            border-collapse: collapse;
        }
        th, td {
            padding: 15px;
            text-align: left;
        }
        @media screen and (max-width:700px) {
            table, tr, td {
                padding:0;
                border:1px solid;
            }
            table {
                border:none;
            }
            tr:first-child, thead, th {
                display:none;
                border:none;
            }
            tr {
                float: left;
                width: 100%;
                margin-bottom: 2em;
            }
            td {
                float: left;
                width: 100%;
                padding:1em;
            }
            td::before {
                content:attr(data-label);
                word-wrap: break-word;
                color: white;
                border-right:2px solid;
                width: 20%;
                float:left;
                padding:1em;
                font-weight: bold;
                margin:-1em 1em -1em -1em;
            }
        }
    </style>
{% endblock %}
{% block script %}
    var searchInput = document.getElementById("searchText");
    searchInput.onkeyup = function() {
        var filter, table, tr, td, i, txtValue;
        filter = searchInput.value.toUpperCase();
        table = document.getElementById("tableOptions");
        if (table) {
            tr = table.getElementsByTagName("tr");

            for (i = 0; i < tr.length; i++) {
                td = tr[i].getElementsByTagName("td")[0];
                if (td) {
                    txtValue = td.textContent || td.innerText;
                    if (txtValue.toUpperCase().indexOf(filter) > -1) {
                        tr[i].style.display = "";
                    }else{
                        tr[i].style.display = "none";
                    }
                }
            }
        }
    }
{% endblock %}
{% block content %}
    <input type="text" id="searchText" placeholder="Search for ..." title="Type in a filter">
    <table id="tableOptions">
        <tr>
            <th>SSID</th>
            <th>BSSID</th>
            <th>Password</th>
        </tr>
        {% for p in passwords %}
            <tr>
                <td data-label="SSID">{{p["ssid"]}}</td>
                <td data-label="BSSID">{{p["bssid"]}}</td>
                <td data-label="Password">{{p["password"]}}</td>
            </tr>
        {% endfor %}
    </table>
{% endblock %}
"""

def log_message(level, message):
    """Helper function for logging."""
    getattr(logging, level)(f"[RulesDic] {message}")

def run_command(command, shell=True):
    """Helper function to run shell commands."""
    return subprocess.run(command, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def generate_variations(base, transformations):
    """Generate variations of a base string using transformations."""
    return [''.join(p) for p in product(*[transformations.get(c, [c]) for c in base.lower()])]

class RulesDic(plugins.Plugin):
    __author__ = 'fmatray, AWWShuck'
    __version__ = '1.0.3'
    __license__ = 'GPL3'
    __description__ = 'Tries to crack with hashcat with a generated wordlist base on the wifi name'
    __dependencies__ = {
        'apt': ['hashcat', 'hcxtools'],
    }

    def __init__(self):
        self.options = dict()
        self.options['handshake_dir'] = '/home/pi/handshakes'
        self.options['max_crack_time'] = 10  # Default max crack time in minutes
        self.years = list(map(str, range(1900, datetime.now().year + 1)))
        self.years.extend(map(str, range(0, 100)))
        self.running = False
        self.counter = 0

        self.load_report()

    def load_report(self):
        try:
            self.report = StatusFile(os.path.join(self.options['handshake_dir'], '.rulesdic'),
                                     data_format='json')
        except JSONDecodeError:
            try:
                os.remove(os.path.join(self.options['handshake_dir'], '.rulesdic'))
            except OSError as e:
                log_message('error', f"Failed to remove corrupted .rulesdic file: {e}")
            self.report = StatusFile(os.path.join(self.options['handshake_dir'], '.rulesdic'),
                                     data_format='json')
        
    def on_loaded(self):
        log_message('info', 'plugin loaded')
        self.check_and_install('hcxtools')
        self.check_and_install('hashcat')

    def check_and_install(self, package_name):
        """Check if a package is installed, and install it if missing."""
        check = run_command(f"dpkg-query -W -f='${{Status}}' {package_name}")
        if "install ok installed" in check.stdout.decode('utf-8'):
            log_message('info', f"Found {package_name}")
        else:
            log_message('warning', f"{package_name} not installed. Installing...")
            install = run_command(f'sudo apt update && sudo apt install -y {package_name}')
            if install.returncode == 0:
                log_message('info', f"{package_name} installed successfully")
            else:
                log_message('error', f"Failed to install {package_name}")

    def on_config_changed(self, config):
        self.options['handshakes'] = config['bettercap']['handshakes']
        self.options['handshake_dir'] = config.get('handshake_dir', '/home/pi/handshakes')
        self.options['max_crack_time'] = config.get('max_crack_time', 10)  # Allow user to configure max time
        if 'exclude' not in self.options:
            self.options['exclude'] = []
        if 'tmp_folder' not in self.options:
            self.options['tmp_folder'] = '/tmp'
        if 'max_essid_len' not in self.options:
            self.options['max_essid_len'] = 12
        if 'face' not in self.options:
            self.options['face'] = '(≡·≡)'
        self.load_report()

    def on_handshake(self, agent, filename, access_point, client_station):
        if not self.running:
            return

        reported = self.report.data_field_or('reported', default=[])
        excluded = self.report.data_field_or('excluded', default=[])
        essid = os.path.splitext(os.path.basename(filename))[0].split("_")[0]
        if filename in reported:
            log_message('info', f"{filename} already processed")
            return
        if self.options['exclude']:
            if filename in excluded:
                log_message('info', f"{filename} already excluded")
                return
            for pattern in self.options['exclude']:
                if re.match(pattern, essid):
                    excluded.append(filename)
                    self.report.update(data={'reported': reported, 'excluded': excluded})
                    log_message('info', f"{filename} excluded")
                    return
        display = agent.view()
        display.set('face', self.options['face'])
        display.set('status', 'Captured new handshake')
        log_message('info', f"New Handshake {filename}")
        current_time = datetime.now()

        try:
            result = self.check_handcheck(filename)
            if not result:
                log_message('info', 'No handshake')
                return
        except Exception as e:
            log_message('error', f"Error checking handshake: {e}")
            return

        bssid = result.group('bssid')
        display.set('face', self.options['face'])
        display.set('status', 'Handshake found')
        log_message('info', 'Handshake confirmed')
        pwd = self.try_to_crack(filename, essid, bssid)
        duration = (datetime.now() - current_time).total_seconds()
        if not pwd:
            display.set('face', self.options['face'])
            display.set('status', r'Password not found for {essid} :\'()')
            log_message('warning', f"Key not found for {essid} in {duration // 60:.0f}min and {duration % 60:.0f}s")
        else:
            display.set('face', self.options['face'])
            display.set('status', r'Password cracked for {essid} :\'()')
            log_message('warning', f"Cracked password for {essid}: {pwd}. Found in {duration // 60:.0f}min and {duration % 60:.0f}s")
        reported.append(filename)
        self.report.update(data={'reported': reported, 'excluded': excluded})

    def check_handcheck(self, filename):
        base_filename = os.path.splitext(filename)[0]
        converted_filename = f"{base_filename}.22000"

        convert_command = ["hcxpcapngtool", "-o", converted_filename, filename]
        try:
            subprocess.run(convert_command, check=True)
        except subprocess.CalledProcessError as e:
            log_message('error', f"Error converting pcap file: {e}")
            return None

        hashcat_execution = subprocess.run(
            (f'nice /usr/bin/hashcat --show -m 22000 {converted_filename}'),
            shell=True, stdout=subprocess.PIPE
        )
        result = hashcat_execution.stdout.decode('utf-8', errors='ignore').strip()
        return crackable_handshake_re.search(result)

    def try_to_crack(self, filename, essid, bssid):
        base_filename = os.path.splitext(filename)[0]
        converted_filename = f"{base_filename}.22000"

        wordlist_filename = self._generate_dictionnary(filename, essid)

        hashcat_command = (
            f'hashcat -m 22000 {converted_filename} -a 0 {wordlist_filename} --quiet --show'
        )

        start_time = time.time()
        process = subprocess.Popen(
            hashcat_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        while process.poll() is None:
            elapsed_time = (time.time() - start_time) / 60  # Convert to minutes
            if elapsed_time > self.options['max_crack_time']:
                process.terminate()
                log_message('warning', f"Cracking process terminated after {self.options['max_crack_time']} minutes")
                return None
            time.sleep(1)  # Check every second

        result = process.stdout.read().decode("utf-8").strip()

        if ":" in result:
            password = result.split(':')[-1].strip()
        else:
            log_message('warning', "Unexpected hashcat output format")
            return None

        if password:
            with open(f"{filename}.cracked", "w") as f:
                f.write(f"{filename} : {essid} : {password}")

            return password
        return None

    def _generate_dictionnary(self, filename, essid):
        """Generate a wordlist based on ESSID."""
        os.makedirs(self.options['tmp_folder'], exist_ok=True)
        wordlist_filename = os.path.join(self.options['tmp_folder'], f"{os.path.splitext(filename)[0]}.txt")
        log_message('info', f"Generating {wordlist_filename}")

        essid_bases = self._essid_base(essid)
        wordlist = set(essid_bases + self._reverse_rule(essid_bases) + self._punctuation_rule(essid_bases) +
                       self._years_rule(essid_bases) + (self._leet_rule(essid) if len(essid) <= self.options['max_essid_len'] else []))

        with open(wordlist_filename, "w") as f:
            f.write('\n'.join(wordlist))
        log_message('info', f"{len(wordlist)} passwords generated")
        return wordlist_filename

    def _essid_base(self, essid):
        return [essid,
                essid.upper(), essid.lower(), essid.capitalize(),
                re.sub('[0-9]*$', "", essid)]

    def _reverse_rule(self, base_essids):
        return [essid[::-1] for essid in base_essids]

    def _punctuation_rule(self, base_essids):
        wd = ["".join(p) for p in product(base_essids, punctuation)]
        wd.extend(["".join(p) for p in
                   product(base_essids, punctuation, punctuation)])
        wd.extend(["".join(p) for p in product(punctuation, base_essids)])
        wd.extend(["".join(p) for p in
                   product(punctuation, base_essids, punctuation)])
        return wd

    def _years_rule(self, base_essids):
        wd = ["".join(p) for p in product(base_essids, self.years)]
        wd.extend(
            ["".join(p) for p in product(base_essids, self.years, punctuation)])
        wd.extend(
            ["".join(p) for p in product(base_essids, punctuation, self.years)])
        return wd

    def _leet_rule(self, essid):
        """Generate leet variations of an ESSID."""
        leet_dict = {
            'a': ['4', '@', 'a', 'A'], 'b': ['8', '6', 'b', 'B'], 'c': ['(', '<', '{', '[', 'c', 'C'],
            'd': ['d', 'D'], 'e': ['3', 'e', 'E'], 'f': ['f', 'F'], 'g': ['6', '9', 'g', 'G'],
            'h': ['#', 'h', 'H'], 'i': ['!', '|', '1', 'i', 'I'], 'j': ['j', 'J'], 'k': ['k', 'K'],
            'l': ['1', 'l', 'L'], 'm': ['m', 'M'], 'n': ['n', 'N'], 'o': ['0', 'o', 'O'], 'p': ['p', 'P'],
            'q': ['q', 'Q'], 'r': ['r', 'R'], 's': ['5', '$', 's', 'S'], 't': ['7', '+', 't', 'T'],
            'u': ['u', 'U'], 'v': ['v', 'V'], 'w': ['w', 'W'], 'x': ['x', 'X'], 'y': ['y', 'Y'],
            'z': ['2', 'z', 'Z'], '0': ['o', 'O', '0'], '1': ['i', 'I', '1'], '2': ['r', 'R', '2'],
            '3': ['e', 'E', '3'], '4': ['a', 'A', '4'], '5': ['s', 'S', '5'], '6': ['b', 'B', '6'],
            '7': ['y', 'Y', '7'], '8': ['b', 'B', '8'], '9': ['g', 'G', '9'],
        }
        return generate_variations(essid, leet_dict)

    def on_webhook(self, path, request):
        if not self.running:
            return
        if path == "/" or not path:
            try:
                passwords = []
                cracked_files = pathlib.Path(self.options['handshake_dir']).glob('*.cracked')
                for cracked_file in cracked_files:
                    match = re.findall("(.*)_([0-9a-f]{12})\.", cracked_file.name)
                    if match:
                        ssid, bssid = match[0]
                    else:
                        log_message('warning', f"Unexpected cracked file format: {cracked_file.name}")
                        continue
                    with open(cracked_file, 'r') as f:
                        pwd = f.read()
                    passwords.append({
                        "ssid": ssid,
                        "bssid": bssid,
                        "password": pwd})
                return render_template_string(TEMPLATE,
                                              title="Passwords list",
                                              passwords=passwords)
            except Exception as e:
                log_message('error', f"error while loading passwords: {e}")
                logging.debug(e, exc_info=True)
