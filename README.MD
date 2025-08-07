# Wi-Fi Password Brute-Force Tool 🛡️

**Publisher:** Noshadi-sec

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

This is a Python-based script for testing the security of your WPA2-PSK Wi-Fi network. It features two primary attack vectors: a **wordlist attack** and a **generated brute-force attack**. Its main strength lies in its ability to function as a **distributed system**, where multiple computers can work together to test passwords, significantly reducing the time required.

## ⚠️ Disclaimer

**This tool is intended for educational purposes and for testing networks to which you have explicit, authorized permission ONLY.** Unauthorized access to computer networks is illegal. The publisher of this tool, Noshadi-sec, assumes no liability and is not responsible for any misuse or damage caused by this program. **Use it ethically and legally.**

---

## ## Prerequisites

Before you begin, ensure you have the following:

* **Python 3.x** installed on your system.
* **pip** (Python's package installer).
* A **compatible wireless network interface card** and drivers.
    * *Note: The `pywifi` library's compatibility can vary depending on your operating system and hardware drivers. It may require some troubleshooting.*

---

## ## How It Works

The script operates in a few simple stages:

1.  **Scanning:** It first scans for all visible Wi-Fi networks and presents them in a list.
2.  **Target Selection:** You choose a target network from the list.
3.  **Attack Mode:** You select either a wordlist attack or a generated (brute-force) attack.
4.  **Distributed Attack Configuration:** This is the core feature.
    * You define the **total number of workers** (computers) that will participate.
    * You assign a unique **Worker ID** to the current machine (starting from 0).
    * The script uses a **modulo (`%`) operation** to divide the work. For example, if there are 3 workers, Worker 0 tests passwords on lines 0, 3, 6, etc., of the wordlist, while Worker 1 tests lines 1, 4, 7, and so on. This ensures no work is repeated and the load is shared.
    
    `password_is_mine = (password_index % total_workers) == my_worker_id`

---

## ## Installation and Usage

Follow these steps to get the tool running.

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/Noshadi-sec/Wi-Fi-Password-Brute-Force.git](https://github.com/Noshadi-sec/Wi-Fi-Password-Brute-Force.git)
    cd Wi-Fi-Password-Brute-Force
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the script:**
    * *(Make sure to replace `wifi_cracker.py` with the actual name of your Python file)*
    ```bash
    python wifi_cracker.py
    ```
---

## ## Example Walkthrough

Here is what a typical session in the terminal looks like:

```
Scanning for networks...

Available Networks:
1. MyHomeWiFi
2. Neighbors-Net
3. CoffeeShop_Guest
Choose a network number: 1

Choose attack type: (w)ordlist or (g)enerated brute-force? w

Enter the full path to your wordlist file: C:\Users\Test\Desktop\passwords.txt

Enter TOTAL number of workers participating: 2

Enter this worker's ID (from 0 to 1): 0

Worker 0/1 starting WORDLIST attack on 'MyHomeWiFi' using 'C:\Users\Test\Desktop\passwords.txt'...
Total passwords in wordlist for Worker 0: 1,492,122
Worker 0 (Wordlist) | Try 1/746061 (Line: 1): password123
Worker 0 (Wordlist) | Try 2/746061 (Line: 3): 12345678
...
```
*On a second computer, you would run the same script but enter `1` for the worker ID.*

---

## ## License

This project is licensed under the MIT License. See the **`LICENSE`** file for the full text.