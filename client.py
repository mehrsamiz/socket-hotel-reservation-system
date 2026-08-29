import socket 
import json 
import os 
import copy 
from datetime import datetime 
 
CONFIG_FILE = "config.json" 
CLIENT_LOG_DIR = "client_logs" 
 
# Field names that should never be written to disk in plaintext, even in a debug log. 
SENSITIVE_FIELDS = ("password", "new_password") 
 
def _redact(payload): 
    """Return a deep copy of a request payload with any password fields masked, 
    for safe logging. The real value is still sent on the wire - only what gets 
    written to client_logs/*.log is masked.""" 
    redacted = copy.deepcopy(payload) 
    def scrub(node): 
        if isinstance(node, dict): 
            for key in node: 
                if key in SENSITIVE_FIELDS: 
                    node[key] = "***REDACTED***" 
                else: 
                    scrub(node[key]) 
    scrub(redacted) 
    return redacted 
 
# --- Client Logging --- 
client_logger = None 
 
def setup_client_logger(username): 
    global client_logger 
    if not os.path.exists(CLIENT_LOG_DIR): 
        os.makedirs(CLIENT_LOG_DIR) 
    log_file_path = os.path.join(CLIENT_LOG_DIR, f"{username}.log") 
     
    # Simple file logger for client 
    def log_event(message_type, content): # content can be request or response dict 
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S") 
        log_entry = f"[{timestamp}] [{message_type}]\n{json.dumps(content, indent=2, ensure_ascii=False)}\n---\n" 
        try: 
            with open(log_file_path, 'a', encoding='utf-8') as f: 
                f.write(log_entry) 
        except IOError: 
            print(f"Error writing to client log: {log_file_path}") 
 
    client_logger = log_event 
    client_logger("INFO", {"event": "Logger initialized."}) 
 
 
def load_config(): 
    try: 
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f: 
            return json.load(f) 
    except Exception as e: 
        print(f"Error loading config.json: {e}") 
        return None 
 
class HotelClient: 
    def __init__(self, host, port): 
        self.host = host 
        self.port = port 
        self.socket = None 
        self.current_user_type = None # 'admin' or 'normal' 
        self.username_for_log = "guest" 
 
    def connect(self): 
        try: 
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
            self.socket.connect((self.host, self.port)) 
            print(f"Connected to server at {self.host}:{self.port}") 
            return True 
        except socket.error as e: 
            print(f"Connection error: {e}") 
            return False 
 

    def send_request(self, command, args=None): 
        if not self.socket: 
            print("Not connected to server.") 
            return None 
         
        request_data = {"command": command} 
        if args: 
            request_data["args"] = args 
         
        try: 
            json_request = json.dumps(request_data) 
            if client_logger: client_logger("REQUEST", _redact(request_data)) 
            self.socket.sendall(json_request.encode('utf-8')) 
             
            response_raw = self.socket.recv(4096) # Increased buffer 
            if not response_raw: 
                print("Server closed the connection.") 
                return None 
             
            response_data = json.loads(response_raw.decode('utf-8')) 
            if client_logger: client_logger("RESPONSE", response_data) 
             
            print(f"\n<-- SERVER RESPONSE ({response_data.get('status_code')}): {response_data.get('message')}") 
            if "data" in response_data and response_data["data"]: 
                print("Data:") 
                print(json.dumps(response_data["data"], indent=2, ensure_ascii=False)) 
            print("-" * 20) 
            return response_data 
        except socket.error as e: 
            print(f"Socket error during send/recv: {e}") 
            if client_logger: client_logger("ERROR", {"error": str(e)}) 
            self.disconnect() # Disconnect on socket error 
            return None 
        except json.JSONDecodeError as e: 
            print(f"Error decoding JSON response: {e}") 
            if client_logger: client_logger("ERROR", {"error": f"JSON Decode Error: {e}", "raw_data": response_raw.decode('utf-8', errors='ignore')}) 
            return None 
        except Exception as e: 
            print(f"An unexpected error occurred: {e}") 
            if client_logger: client_logger("ERROR", {"error": str(e)}) 
            return None 
 
 
    def disconnect(self): 
        if self.socket: 
            self.socket.close() 
            self.socket = None 
            print("Disconnected from server.") 
            if client_logger: client_logger("INFO", {"event": "Disconnected."}) 
     
    def initial_screen(self): 
        while True:
            print("\nWelcome to Hotel Reservation System") 
            print("1. Set System Time (Admin First Task)") 
            print("2. Sign Up") 
            print("3. Sign In") 
            print("0. Exit") 
            choice = input("Enter choice: ") 
 
            if choice == '1': 
                if not self.socket or not self.socket.fileno() != -1: # Check if socket is valid 
                    if not self.connect(): continue 
                datetime_str = input("Enter system date (dd-mm-yyyy): ") 
                self.send_request("setTime", {"datetime": datetime_str}) 
            elif choice == '2': 
                if not self.socket or not self.socket.fileno() != -1: 
                    if not self.connect(): continue 
                username = input("Enter username for signup: ") 
                # Don't switch the logger to this username yet - the account isn't 
                # confirmed until we get a final 231. Switching early left orphaned 
                # log files for signups that failed or were dropped partway through. 
 
                response = self.send_request("signup", {"username": username}) 
                if response and response.get("status_code") == 311: # Server asks for more details 
                    password = input("Enter password: ") 
                    purse = input("Enter initial purse amount: ") 
                    phone = input("Enter phone number: ") 
                    address = input("Enter address: ") 
                    # All four fields are sent together as ONE message. Sending them as four
                    # separate messages relied on each one arriving in its own recv() on the
                    # server, which TCP does not guarantee - two fields sent close together can
                    # arrive concatenated in a single recv() and fail to parse as JSON. 
                    final_response = self.send_request(None, { 
                        "password": password, "purse": purse, "phone": phone, "address": address 
                    }) 
                    if final_response and final_response.get("status_code") == 231: 
                        self.username_for_log = username 
                        setup_client_logger(self.username_for_log) 
 
            elif choice == '3': 
                if not self.socket or not self.socket.fileno() != -1: 
                    if not self.connect(): continue 
                username = input("Enter username: ") 
                password = input("Enter password: ") # In real app, use getpass 
                response = self.send_request("signin", {"username": username, "password": password}) 
                if response and response.get("status_code") == 230: 
                    self.username_for_log = username # Final username for logging 
                    setup_client_logger(self.username_for_log) # Re-setup if changed from guest 
                    self.current_user_type = response.get("data", {}).get("user_type") 
                    self.main_menu() 
                    # After main_menu (logout), current_user_type should be reset 
                    self.current_user_type = None  
                    # Reset log target back to the shared guest logger. Previously this only 
                    # reset the *name* but never re-pointed client_logger, so every action taken 
                    # before the next successful signin/signup kept writing into the PREVIOUS 
                    # user's log file (e.g. a second person's signin attempt landing in the 
                    # first user's log). 
                    self.username_for_log = "guest_session" 
                    setup_client_logger(self.username_for_log) 
            elif choice == '0': 
                break 
            else: 
                print("Invalid choice.") 
        self.disconnect() 
 
    def main_menu(self): 
        while True: 
            print("\n--- Main Menu ---") 
            print("1. View user information") 
            if self.current_user_type == "true": # Admin 
                print("2. View all users (Admin)") 
            print("3. View rooms information") 
            if self.current_user_type == "false": # Normal user 
                print("4. Booking") 
                print("5. Canceling a reservation") 
            print("6. Edit information (Password/Phone/Address)") 
            if self.current_user_type == "false": # Normal user 
                 print("7. Leaving room (Checkout)") 
            if self.current_user_type == "true": # Admin 
                print("8. Rooms Management (Admin)") 
            print("0. Logout") 
             
            choice = input(f"Command -> ({self.username_for_log}) <choice number>: ") 
 
            if choice == '1': 
                self.send_request("view_user_info") 
            elif choice == '2' and self.current_user_type == "true": 
                self.send_request("view_all_users") 
            elif choice == '3':
                self.send_request("view_rooms_info") 
            elif choice == '4' and self.current_user_type == "false": 
                room_num = input("Enter room number: ") 
                num_beds = input("Enter number of beds: ") 
                checkin = input("Enter check-in date (dd-mm-yyyy): ") 
                checkout = input("Enter checkout date (dd-mm-yyyy): ") 
                self.send_request("book", {"room_num": room_num, "num_beds": num_beds,  
                                           "checkin_date": checkin, "checkout_date": checkout}) 
            elif choice == '5' and self.current_user_type == "false": 
                print("Your current reservations (if any) would be listed here by the server.") # As per spec page 6 
                print("Then you'd enter the command.") 
                room_num = input("Enter room number to cancel: ") 
                num_val = input("Enter number of beds/reservations (n) to cancel: ") 
                self.send_request("cancel_booking", {"room_num": room_num, "num_beds": num_val}) 
 
            elif choice == '6': 
                print("What do you want to edit?") 
                edit_choice = input(" (1) Password (2) Phone (3) Address (4) All (or comma-separated): ").lower() 
                args = {} 
                if '1' in edit_choice or 'all' in edit_choice or 'password' in edit_choice: 
                    args["new_password"] = input("Enter new password: ") 
                if '2' in edit_choice or 'all' in edit_choice or 'phone' in edit_choice: 
                    args["phone"] = input("Enter new phone: ") 
                if '3' in edit_choice or 'all' in edit_choice or 'address' in edit_choice: 
                    args["address"] = input("Enter new address: ") 
                 
                if args: 
                    self.send_request("edit_information", args) 
                else: 
                    print("No changes specified.") 
 
            elif choice == '7' and self.current_user_type == "false": 
                room_num_leave = input("Enter room number you are leaving: ") 
                self.send_request("leaving_room", {"value": room_num_leave}) 
 
            elif choice == '8' and self.current_user_type == "true": 
                self.admin_rooms_menu() 
             
            elif choice == '0': 
                self.send_request("logout") 
                break # Exit main menu, back to initial screen or exit 
            else: 
                print("Invalid choice or permission denied.") 
                # Send a dummy request or a special "menu_error" to server to log 503 
                # For simplicity, just print client-side error. Server will give 503 if command is unknown. 
 
    def admin_rooms_menu(self): 
        while True: 
            print("\n--- Admin Rooms Management ---") 
            print("1. Add Room") 
            print("2. Modify Room") 
            print("3. Remove Room") 
            print("0. Back to Main Menu") 
            choice = input("Command -> <choice number>: ") 
 
            if choice == '1': 
                room_num = input("Enter new room number: ") 
                max_cap = input("Enter max capacity: ") 
                price = input("Enter price per bed: ") 
                self.send_request("admin_add_room", {"room_num": room_num, "max_capacity": max_cap, "price": price}) 
            elif choice == '2': 
                room_num = input("Enter room number to modify: ") 
                new_max_cap = input("Enter new max capacity: ") 
                new_price = input("Enter new price: ") 
                self.send_request("admin_modify_room", {"room_num": room_num,  
                                                       "new_max_capacity": new_max_cap,  
                                                       "new_price": new_price}) 
            elif choice == '3': 
                room_num = input("Enter room number to remove: ") 
                self.send_request("admin_remove_room", {"room_num": room_num}) 
            elif choice == '0':
                break 
            else: 
                print("Invalid choice.") 
 
 
if __name__ == "__main__": 
    config_data = load_config() 
    if not config_data: 
        print("Exiting due to config load error.") 
    else: 
        # Initialize logger with a default name, will be updated upon successful login/signup 
        if not os.path.exists(CLIENT_LOG_DIR): 
            os.makedirs(CLIENT_LOG_DIR) 
        setup_client_logger("guest_session") # Default logger for pre-login 
 
        client = HotelClient(config_data["hostName"], config_data["commandChannelPort"]) 
        client.initial_screen() 