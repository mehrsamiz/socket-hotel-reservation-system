import socket
import threading
import json
import os
import hashlib
from datetime import datetime, date

# --- Configuration and Data Loading ---
CONFIG_FILE = "config.json"
USERS_FILE = "UsersInfo.json"
ROOMS_FILE = "RoomsInfo.json"
SERVER_LOG_FILE = "server.log"
SYSTEM_STATE_FILE = "system_state.json" # persists the admin-set system date across server restarts

# --- Logging ---
log_lock = threading.Lock()
def log_server_event(message):
    with log_lock:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [SERVER] {message}\n"
        print(log_entry.strip()) # Also print to console for real-time monitoring
        try:
            with open(SERVER_LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(log_entry)
        except IOError:
            print(f"CRITICAL: Could not write to server log file {SERVER_LOG_FILE}")


def load_json(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        log_server_event(f"Error: {filename} not found.")
        return [] if "Info" in filename else {} # return empty list for users/rooms, empty dict for config
    except json.JSONDecodeError:
        log_server_event(f"Error: Could not decode JSON from {filename}.")
        return [] if "Info" in filename else {}

def save_json(filename, data):
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        log_server_event(f"Data saved to {filename}")
    except IOError:
        log_server_event(f"Error: Could not write to {filename}.")

# --- Password Hashing ---
# Passwords are never stored or compared in plaintext. Each user gets a random
# salt (stored alongside the hash) and PBKDF2-HMAC-SHA256 is run over
# password+salt. Even two users with the same password get different hashes,
# and a leaked UsersInfo.json does not directly reveal anyone's password.
PBKDF2_ITERATIONS = 100_000

def hash_password(password, salt_hex=None):
    if salt_hex is None:
        salt_hex = os.urandom(16).hex()
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt_hex), PBKDF2_ITERATIONS)
    return salt_hex, digest.hex()

def verify_password(password, salt_hex, expected_hash_hex):
    _, computed_hash_hex = hash_password(password, salt_hex)
    return computed_hash_hex == expected_hash_hex

def migrate_plaintext_passwords(users):
    """One-time upgrade path: any user record still carrying a plaintext
    "password" field (e.g. the original sample UsersInfo.json) gets it replaced
    with a salted hash on the very first load after this change, then saved.
    Existing plaintext passwords still work for signin - only the on-disk
    representation changes."""
    changed = False
    for user in users:
        if "password" in user and "password_hash" not in user:
            salt_hex, hash_hex = hash_password(user["password"])
            user["password_hash"] = hash_hex
            user["password_salt"] = salt_hex
            del user["password"]
            changed = True
    if changed:
        save_json(USERS_FILE, users)
        log_server_event("Migrated plaintext passwords in UsersInfo.json to salted hashes.")
    return users

config = load_json(CONFIG_FILE)
users_data = migrate_plaintext_passwords(load_json(USERS_FILE))
rooms_data = load_json(ROOMS_FILE)

# --- Thread Safety ---
data_lock = threading.Lock() # For users_data and rooms_data

# --- Server State --- (system_date is initialized further below, after parse_date_string is defined)

# --- Helper Functions ---
def find_user(username):
    for user in users_data:
        if user["user"] == username:
            return user
    return None

def find_room(room_number):
    for room in rooms_data:
        if room["number"] == str(room_number):
            return room
    return None

def parse_date_string(date_str):
    try:
        return datetime.strptime(date_str, "%d-%m-%Y").date()
    except ValueError:
        return None

def load_system_date():
    """Restore the admin-set date from disk, so the server doesn't forget it (and
    force setTime again) every time it restarts."""
    try:
        with open(SYSTEM_STATE_FILE, 'r', encoding='utf-8') as f:
            saved = json.load(f)
        return parse_date_string(saved.get("system_date"))
    except (FileNotFoundError, json.JSONDecodeError):
        return None

def save_system_date(d):
    try:
        with open(SYSTEM_STATE_FILE, 'w', encoding='utf-8') as f:
            json.dump({"system_date": d.strftime("%d-%m-%Y")}, f)
    except IOError:
        log_server_event(f"Error: Could not write to {SYSTEM_STATE_FILE}.")

# --- Server State ---
system_date = load_system_date() # None on first-ever run, otherwise restored from disk
if system_date:
    log_server_event(f"Restored system date from {SYSTEM_STATE_FILE}: {system_date.strftime('%d-%m-%Y')}")

def check_room_availability(room, check_in_date_obj, check_out_date_obj, num_of_beds):
    if not room:
        return False, "Room not found"
    if room["capacity"] < num_of_beds:
        return False, "Not enough capacity for requested beds"

    # Check for overlapping reservations
    for res_user in room.get("users", []):
        res_start_date = parse_date_string(res_user["reserveDate"])
        res_end_date = parse_date_string(res_user["checkoutDate"])
        if res_start_date and res_end_date:
            # Overlap if (StartA <= EndB) and (EndA >= StartB)
            if (check_in_date_obj < res_end_date) and \
               (check_out_date_obj > res_start_date):
                # Check if considering remaining capacity is needed (more complex)
                # For simplicity in this example, if there's any overlap, assume full for that period
                # A more advanced check would sum beds for overlapping periods.
                # For now, let's assume if any user is in the room during the period,
                # and we are checking for the *entire* room.
                # If checking for partial capacity, this logic needs refinement.
                # The problem description implies we check if the room has enough *remaining* capacity.

                # Let's refine this: Calculate occupied beds during the overlap
                occupied_beds_during_overlap = 0
                for existing_res in room["users"]:
                    existing_start = parse_date_string(existing_res["reserveDate"])
                    existing_end = parse_date_string(existing_res["checkoutDate"])
                    # Check if existing_res overlaps with the requested period
                    if (existing_start < check_out_date_obj) and (existing_end > check_in_date_obj):
                         occupied_beds_during_overlap += existing_res["numOfBeds"]
                
                if room["maxCapacity"] - occupied_beds_during_overlap < num_of_beds:
                    return False, "Not enough beds available for the requested dates (overlap)."

    return True, "Available"

def get_next_user_id():
    if not users_data:
        return 0
    return max(user["id"] for user in users_data) + 1

# --- Request Handler ---
class ClientHandler(threading.Thread):
    def __init__(self, client_socket, client_address):
        super().__init__()
        self.client_socket = client_socket
        self.client_address = client_address
        self.current_user = None
        self.is_running = True
        log_server_event(f"Accepted connection from {client_address}")

    def send_response(self, status_code, message, data=None):
        response = {"status_code": status_code, "message": message}
        if data:
            response["data"] = data
        try:
            self.client_socket.sendall(json.dumps(response).encode('utf-8'))
            log_server_event(f"Sent to {self.client_address}: {status_code} - {message}")
        except socket.error as e:
            log_server_event(f"Error sending response to {self.client_address}: {e}")
            self.is_running = False


    def handle_command(self, command_data):
        global users_data, rooms_data, system_date
        command = command_data.get("command")
        args = command_data.get("args", {})
        log_server_event(f"Received from {self.client_address} ({self.current_user['user'] if self.current_user else 'Guest'}): {command} with args {args}")

        # --- Initial command: setTime (must be done first) ---
        if command == "setTime":
            if system_date is not None and (not self.current_user or not self.current_user.get("admin") == "true"):
                self.send_response(403, "System date already set or permission denied.")
                return
            
            date_str = args.get("datetime")
            parsed_dt = parse_date_string(date_str)
            if not parsed_dt:
                self.send_response(401, "Date time format: dd-mm-yyyy")
                return
            with data_lock:
                system_date = parsed_dt
                save_system_date(system_date) # persist so a server restart doesn't lose it
            # Auto-checkout rooms based on new system_date
            self.auto_checkout_rooms()
            self.send_response(200, f"System date set to {system_date.strftime('%d-%m-%Y')}")
            return

        # All other commands require system_date to be set
        if system_date is None:
            self.send_response(503, "System date not set. Admin must run 'setTime' first.")
            return

        # --- Authentication and User Management ---
        if command == "signup":
            username = args.get("username")
            if find_user(username):
                self.send_response(451, "User already existed!")
                return
            # Phase 1: Username accepted, ask for more details
            self.send_response(311, "User Signed up. Enter your password, purse, phone and address.")
            
            try:
                # Expect ONE message with password, purse, phone and address together.
                # This used to be 4 separate recv() calls, one per field, sent back-to-back
                # with no response in between. TCP does not preserve message boundaries, so
                # if the client sent two fields close together they could arrive concatenated
                # in a single recv() (json.loads "Extra data" error), or one recv() could pick
                # up a partial message. Sending all four fields as one JSON object removes
                # that framing ambiguity entirely.
                detail_data = json.loads(self.client_socket.recv(2048).decode('utf-8'))
                detail_args = detail_data.get("args", {})
                password = detail_args.get("password")
                purse_str = detail_args.get("purse")
                phone = detail_args.get("phone")
                address = detail_args.get("address")

                if not all([password, purse_str, phone, address]):
                    self.send_response(503, "Missing information for signup.")
                    return
                
                try:
                    purse = int(purse_str)
                    if purse < 0: raise ValueError("Purse cannot be negative")
                except ValueError:
                    self.send_response(503, "Invalid purse amount.")
                    return

                with data_lock:
                    salt_hex, hash_hex = hash_password(password)
                    new_user = {
                        "id": get_next_user_id(),
                        "user": username,
                        "password_hash": hash_hex,
                        "password_salt": salt_hex,
                        "admin": "false",
                        "purse": str(purse),
                        "phoneNumber": phone,
                        "address": address
                    }
                    users_data.append(new_user)
                    save_json(USERS_FILE, users_data)
                self.send_response(231, "User successfully signed up.")
            except Exception as e:
                log_server_event(f"Signup detail receiving error: {e}")
                self.send_response(503, "Error during signup process. Signup cancelled.")


        elif command == "signin":
            username = args.get("username")
            password = args.get("password")
            user = find_user(username)
            if user and verify_password(password, user.get("password_salt", ""), user.get("password_hash", "")):
                self.current_user = user
                self.send_response(230, "User logged in.", {"user_type": user["admin"]})
            else:
                self.send_response(430, "Invalid username or password.")
        
        # --- Commands requiring login ---
        elif not self.current_user:
            self.send_response(401, "Not authenticated. Please signin.")
        
        elif command == "logout":
            user_name = self.current_user["user"]
            self.current_user = None
            self.send_response(201, "User logged out successfully.")
            log_server_event(f"User {user_name} logged out from {self.client_address}")
            # self.is_running = False # Optionally close connection on logout

        elif command == "view_user_info":
            user_info_to_send = {k: v for k, v in self.current_user.items() if k not in ("password", "password_hash", "password_salt")}
            self.send_response(200, "User information.", user_info_to_send)

        elif command == "view_all_users":
            if self.current_user["admin"] != "true":
                self.send_response(403, "Access denied!")
                return
            all_users_info = []
            for u in users_data:
                user_copy = {k: v for k, v in u.items() if k not in ("password", "password_hash", "password_salt")}
                all_users_info.append(user_copy)
            self.send_response(200, "All users information.", all_users_info)

        elif command == "view_rooms_info":
            # If admin, show users in room. Otherwise, just basic room info.
            rooms_to_send = []
            for r in rooms_data:
                room_copy = r.copy()
                if self.current_user["admin"] != "true":
                    if "users" in room_copy:
                        # For non-admins, don't show who is in the room, maybe just if it's occupied
                        # Or, as per spec "کاربران حاضر در اتاق را نیز نمایش دهد که این بخش صرفا برای ادمین قابل مشاهده باشد"
                        # So, for normal users, we might omit the "users" field or make it generic.
                        # Let's omit it for non-admins for simplicity here.
                        del room_copy["users"] 
                rooms_to_send.append(room_copy)
            self.send_response(200, "Rooms information.", rooms_to_send)
        
        elif command == "edit_information":
            new_password = args.get("new_password")
            new_phone = args.get("phone")
            new_address = args.get("address")
            
            user_to_edit = None
            # Admin can edit their own, normal users can edit their own.
            # The problem says "ادمین نیز مانند سایر کاربران تنها اطلاعات شخصی خود که فقط رمز عبور میباشد را میتواند تغییر دهد"
            # This is a bit contradictory to "ادمین میتواند تمام اطلاعات مجاز کاربر را مشاهده کند"
            # Let's assume admin can only change their own password, phone, address like normal users.
            # If admin needs to edit others, the command structure would need a target_username.
            
            with data_lock:
                user_idx = next((i for i, u in enumerate(users_data) if u["id"] == self.current_user["id"]), None)
                if user_idx is not None:
                    if new_password:
                        new_salt_hex, new_hash_hex = hash_password(new_password)
                        users_data[user_idx]["password_hash"] = new_hash_hex
                        users_data[user_idx]["password_salt"] = new_salt_hex
                    if new_phone:
                         users_data[user_idx]["phoneNumber"] = new_phone
                    if new_address:
                         users_data[user_idx]["address"] = new_address
                    save_json(USERS_FILE, users_data)
                    self.current_user = users_data[user_idx] # Update current_user in memory
                    self.send_response(312, "Information was changed successfully.")
                else: # Should not happen if user is logged in
                    self.send_response(503, "User not found for editing.")


        elif command == "book":
            if self.current_user["admin"] == "true":
                self.send_response(403, "Admins cannot book rooms directly.") # Or implement if needed
                return

            room_num = args.get("room_num")
            num_beds_str = args.get("num_beds")
            checkin_str = args.get("checkin_date")
            checkout_str = args.get("checkout_date")

            if not all([room_num, num_beds_str, checkin_str, checkout_str]):
                self.send_response(503, "Bad sequence of commands. Missing booking arguments.")
                return
            
            try:
                num_beds = int(num_beds_str)
                if num_beds <= 0: raise ValueError
            except ValueError:
                self.send_response(503, "Invalid number of beds.")
                return

            checkin_date_obj = parse_date_string(checkin_str)
            checkout_date_obj = parse_date_string(checkout_str)

            if not (checkin_date_obj and checkout_date_obj):
                self.send_response(503, "Invalid date format (dd-mm-yyyy).")
                return
            if checkin_date_obj < system_date or checkout_date_obj <= checkin_date_obj:
                self.send_response(503, "Invalid check-in/checkout dates relative to system date or each other.")
                return
            
            with data_lock:
                room = find_room(room_num)
                if not room:
                    self.send_response(101, "The desired room was not found")
                    return

                user_purse = int(self.current_user["purse"])
                room_price_per_bed_per_night = int(room["price"])
                num_nights = (checkout_date_obj - checkin_date_obj).days
                total_cost = room_price_per_bed_per_night * num_beds * num_nights

                if user_purse < total_cost:
                    self.send_response(108, "Your account balance is not enough")
                    return
                
                is_available, reason = check_room_availability(room, checkin_date_obj, checkout_date_obj, num_beds)
                if not is_available:
                    # If reason implies full capacity, send 109. Otherwise, it might be a configuration issue.
                    if "capacity" in reason or "overlap" in reason:
                         self.send_response(109, "The room capacity is full or not enough beds for the period.")
                    else:
                         self.send_response(503, f"Booking failed: {reason}")
                    return

                # Proceed with booking
                room_idx = rooms_data.index(room)
                user_idx = users_data.index(self.current_user)

                new_reservation = {
                    "id": self.current_user["id"], # User ID
                    "numOfBeds": num_beds,
                    "reserveDate": checkin_str,
                    "checkoutDate": checkout_str
                }
                rooms_data[room_idx]["users"].append(new_reservation)
                rooms_data[room_idx]["capacity"] -= num_beds
                rooms_data[room_idx]["status"] = 1 if rooms_data[room_idx]["capacity"] < rooms_data[room_idx]["maxCapacity"] else 0 # Simplified status: 1 if any bed taken
                
                users_data[user_idx]["purse"] = str(user_purse - total_cost)
                self.current_user["purse"] = users_data[user_idx]["purse"] # Update in-memory session

                save_json(ROOMS_FILE, rooms_data)
                save_json(USERS_FILE, users_data)
                self.send_response(110, f"Successfully booked room {room_num} for {num_beds} bed(s). Cost: {total_cost}")


        elif command == "cancel_booking":
            if self.current_user["admin"] == "true":
                # Admin can cancel *any* user's reservation. Normal user can only cancel their own.
                # The problem statement for Admin says "میتواند رزرو اتاقی را لغو نماید" - implies any room.
                # For normal user, the command `cancel` <RoomNum> <Num> is for cancelling *their own* reservation.
                # This handler needs to know which user's reservation to cancel if admin.
                # Let's assume for now the provided `cancel <RoomNum> <Num>` is for the *logged-in user*.
                # An admin-specific cancel might need `cancel_user_booking <UserID> <RoomNum> <Num>`
                self.send_response(403, "Admin cancellation of specific user booking not fully implemented with this command. Use user account.")
                return

            room_num_to_cancel = args.get("room_num")
            num_beds_to_cancel_str = args.get("num_beds") # This is 'n' from the spec.

            if not room_num_to_cancel or not num_beds_to_cancel_str:
                self.send_response(401, "Invalid command structure for cancel.") # 401 for bad format
                return
            
            try:
                num_beds_to_cancel = int(num_beds_to_cancel_str)
            except ValueError:
                self.send_response(401, "Invalid number of beds for cancellation.")
                return

            with data_lock:
                room = find_room(room_num_to_cancel)
                if not room:
                    self.send_response(101, "The desired room was not found")
                    return
                
                reservation_found = False
                reservation_to_remove = None
                user_id_to_cancel = self.current_user["id"]

                for res in room["users"]:
                    if res["id"] == user_id_to_cancel and res["numOfBeds"] == num_beds_to_cancel:
                        # Assuming a user can only have one type of reservation (same num_beds) in a room at a time.
                        # If multiple, need more criteria like date. For simplicity, first match.
                        reservation_to_remove = res
                        reservation_found = True
                        break
                
                if not reservation_found:
                    self.send_response(102, "Your reservation was not found (or bed count mismatch).")
                    return

                # Calculate refund (half of the original cost)
                # Need to re-calculate original cost as it's not stored directly with reservation
                checkin_date_obj = parse_date_string(reservation_to_remove["reserveDate"])
                checkout_date_obj = parse_date_string(reservation_to_remove["checkoutDate"])
                if not checkin_date_obj or not checkout_date_obj: # Should not happen if data is consistent
                    self.send_response(500, "Corrupted reservation data (dates).")
                    return

                num_nights = (checkout_date_obj - checkin_date_obj).days
                room_price_per_bed = int(room["price"])
                original_cost = room_price_per_bed * num_beds_to_cancel * num_nights
                refund_amount = original_cost // 2

                # Update room
                room_idx = rooms_data.index(room)
                rooms_data[room_idx]["users"].remove(reservation_to_remove)
                rooms_data[room_idx]["capacity"] += num_beds_to_cancel
                if rooms_data[room_idx]["capacity"] == rooms_data[room_idx]["maxCapacity"]:
                    rooms_data[room_idx]["status"] = 0
                
                # Update user purse
                user_idx = next((i for i, u in enumerate(users_data) if u["id"] == user_id_to_cancel), None)
                if user_idx is not None:
                    current_purse = int(users_data[user_idx]["purse"])
                    users_data[user_idx]["purse"] = str(current_purse + refund_amount)
                    self.current_user["purse"] = users_data[user_idx]["purse"] # Update session

                save_json(ROOMS_FILE, rooms_data)
                save_json(USERS_FILE, users_data)
                self.send_response(110, f"Successfully cancelled reservation. Refund: {refund_amount}")
        
        elif command == "leaving_room": # User checks out
            room_num_leaving = args.get("value") # 'value' is room number per spec
            if not room_num_leaving:
                self.send_response(503, "Room number not specified for leaving.")
                return

            with data_lock:
                room = find_room(room_num_leaving)
                if not room:
                    self.send_response(503, "Invalid room number (not found).") # 503 for invalid input data
                    return

                user_reservation_in_room = None
                for res in room.get("users", []):
                    if res["id"] == self.current_user["id"]:
                        user_reservation_in_room = res
                        break
                
                if not user_reservation_in_room:
                    self.send_response(102, "You do not have a reservation in this room to leave from.") # 102 as "your reservation not found"
                    return
                
                # Check if current system_date is on or after checkoutDate
                checkout_date_obj = parse_date_string(user_reservation_in_room["checkoutDate"])
                if system_date < checkout_date_obj:
                    self.send_response(503, f"Cannot leave room yet. Checkout date is {user_reservation_in_room['checkoutDate']}.")
                    return


                room_idx = rooms_data.index(room)
                beds_freed = user_reservation_in_room["numOfBeds"]
                rooms_data[room_idx]["users"].remove(user_reservation_in_room)
                rooms_data[room_idx]["capacity"] += beds_freed
                if rooms_data[room_idx]["capacity"] == rooms_data[room_idx]["maxCapacity"]:
                    rooms_data[room_idx]["status"] = 0
                
                save_json(ROOMS_FILE, rooms_data)
                self.send_response(413, "Successfully Leaving.") # 413 as per spec
        
        # --- Admin Room Management ---
        elif command == "admin_add_room":
            if self.current_user["admin"] != "true":
                self.send_response(403, "Access denied!")
                return
            
            room_num = args.get("room_num")
            max_cap_str = args.get("max_capacity")
            price_str = args.get("price")

            if not all([room_num, max_cap_str, price_str]):
                self.send_response(503, "Missing arguments for adding room.")
                return

            with data_lock:
                if find_room(room_num):
                    self.send_response(111, "This room already exists")
                    return
                try:
                    max_capacity = int(max_cap_str)
                    price = int(price_str)
                    if max_capacity <= 0 or price <= 0: raise ValueError
                except ValueError:
                    self.send_response(503, "Invalid capacity or price value.")
                    return
                
                new_room = {
                    "number": str(room_num),
                    "status": 0,
                    "price": price,
                    "maxCapacity": max_capacity,
                    "capacity": max_capacity,
                    "users": []
                }
                rooms_data.append(new_room)
                save_json(ROOMS_FILE, rooms_data)
                # 104 = added, 105 = modified, 106 = deleted (per spec).
                # NOTE: this used to send BOTH 105 and 104 for the same request, which
                # put two JSON responses back-to-back on the socket. The client only
                # reads one response per request, so the extra bytes were left sitting
                # in the socket buffer and got misread as the response to whatever the
                # client sent next -> request/response desync. Send exactly one response.
                self.send_response(104, "Successfully added.")


        elif command == "admin_modify_room":
            if self.current_user["admin"] != "true":
                self.send_response(403, "Access denied!")
                return

            room_num = args.get("room_num")
            new_max_cap_str = args.get("new_max_capacity")
            new_price_str = args.get("new_price")

            if not all([room_num, new_max_cap_str, new_price_str]):
                self.send_response(503, "Missing arguments for modifying room.")
                return

            with data_lock:
                room = find_room(room_num)
                if not room:
                    self.send_response(101, "The desired room was not found")
                    return
                
                try:
                    new_max_capacity = int(new_max_cap_str)
                    new_price = int(new_price_str)
                    if new_max_capacity <= 0 or new_price <= 0: raise ValueError
                except ValueError:
                    self.send_response(503, "Invalid new capacity or price value.")
                    return

                # Check if new max capacity is less than currently occupied beds
                occupied_beds = room["maxCapacity"] - room["capacity"]
                if new_max_capacity < occupied_beds:
                    self.send_response(109, "Cannot reduce capacity below currently occupied beds.") # 109 for capacity full
                    return
                
                room_idx = rooms_data.index(room)
                rooms_data[room_idx]["price"] = new_price
                # Adjust current capacity based on new max capacity
                rooms_data[room_idx]["capacity"] = new_max_capacity - occupied_beds
                rooms_data[room_idx]["maxCapacity"] = new_max_capacity
                
                save_json(ROOMS_FILE, rooms_data)
                self.send_response(105, "Successfully modified.")

        elif command == "admin_remove_room":
            if self.current_user["admin"] != "true":
                self.send_response(403, "Access denied!")
                return
            
            room_num = args.get("room_num")
            if not room_num:
                self.send_response(503, "Room number not specified for removal.")
                return

            with data_lock:
                room = find_room(room_num)
                if not room:
                    self.send_response(101, "The desired room was not found")
                    return
                
                if room.get("users"): # Check if room["users"] is not empty
                    self.send_response(109, "Cannot remove room. Room is currently occupied or has reservations.")
                    return

                rooms_data.remove(room)
                save_json(ROOMS_FILE, rooms_data)
                self.send_response(106, "Successfully deleted.")
        
        else:
            self.send_response(503, "Bad sequence of commands. Unknown command.")
    
    def auto_checkout_rooms(self):
        """Automatically checks out users whose checkoutDate is on or before system_date."""
        global rooms_data
        if not system_date:
            return

        log_server_event("Running auto-checkout process...")
        with data_lock:
            modified = False
            for room_idx, room in enumerate(rooms_data):
                reservations_to_keep = []
                beds_freed_in_room = 0
                for res in room.get("users", []):
                    checkout_date_obj = parse_date_string(res["checkoutDate"])
                    if checkout_date_obj and checkout_date_obj <= system_date:
                        log_server_event(f"Auto-checking out user {res['id']} from room {room['number']} (checkout: {res['checkoutDate']})")
                        beds_freed_in_room += res["numOfBeds"]
                        modified = True
                    else:
                        reservations_to_keep.append(res)
                
                if beds_freed_in_room > 0:
                    rooms_data[room_idx]["users"] = reservations_to_keep
                    rooms_data[room_idx]["capacity"] += beds_freed_in_room
                    if rooms_data[room_idx]["capacity"] >= rooms_data[room_idx]["maxCapacity"]:
                        # Ensure capacity doesn't exceed max and set status if fully empty
                        rooms_data[room_idx]["capacity"] = rooms_data[room_idx]["maxCapacity"]
                        rooms_data[room_idx]["status"] = 0 
            
            if modified:
                save_json(ROOMS_FILE, rooms_data)
                log_server_event("Auto-checkout process completed. Rooms data updated.")


    def run(self):
        try:
            while self.is_running:
                # On new connection or after some operations, auto-checkout
                if system_date: self.auto_checkout_rooms()

                raw_data = self.client_socket.recv(2048) # Increased buffer size
                if not raw_data:
                    log_server_event(f"Client {self.client_address} disconnected.")
                    break
                
                try:
                    # Handle multiple JSON objects if sent together (less likely with this design but good practice)
                    data_str = raw_data.decode('utf-8')
                    # Simple split, assumes no nested JSONs containing '}{'
                    # For robust multi-JSON handling, a proper framing protocol is needed.
                    # Here, we assume one JSON command per recv.
                    
                    # Check for concatenated JSONs (simple case)
                    # This is a basic attempt and might not be robust for all cases.
                    # A better way is for client to send a length prefix or a delimiter.
                    if data_str.count('{') > 1 and data_str.count('}') > 1 and data_str.rfind('}') != len(data_str) -1 :
                         # This is a heuristic. If client sends messages too fast, they might concatenate.
                         # For this assignment, assume one command per send/recv.
                         pass

                    command_data = json.loads(data_str)
                    self.handle_command(command_data)
                except json.JSONDecodeError:
                    log_server_event(f"Invalid JSON received from {self.client_address}: {data_str}")
                    self.send_response(503, "Bad request: Invalid JSON format.")
                except socket.timeout:
                    log_server_event(f"Socket timeout for client {self.client_address}")
                    self.is_running = False
                except Exception as e:
                    log_server_event(f"Error processing command from {self.client_address}: {e}")
                    try:
                        self.send_response(500, "Internal server error.")
                    except: pass # If sending fails, can't do much

        except ConnectionResetError:
            log_server_event(f"Client {self.client_address} reset the connection.")
        except Exception as e:
            log_server_event(f"Unhandled exception in client handler {self.client_address}: {e}")
        finally:
            log_server_event(f"Closing connection for {self.client_address}")
            if self.current_user: # Log out user if connection drops unexpectedly
                 log_server_event(f"User {self.current_user['user']} implicitly logged out due to connection drop.")
            self.client_socket.close()
            # Update JSON files one last time, though saving after each change is better
            with data_lock:
                save_json(USERS_FILE, users_data)
                save_json(ROOMS_FILE, rooms_data)


def main_server():
    global system_date
    if not config or "hostName" not in config or "commandChannelPort" not in config:
        log_server_event("CRITICAL: config.json is missing or malformed. Cannot start server.")
        return

    host = config["hostName"]
    port = config["commandChannelPort"]

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allow reuse of address

    try:
        server_socket.bind((host, port)) #connect
        server_socket.listen(5) # Max 5 queued connections
        log_server_event(f"Server listening on {host}:{port}")
        print("Server started. Waiting for admin to set time via a client connection...")
        print("Example: Command -> setTime <Date Time> (e.g., setTime 01-01-2024)")


        while True:
            try:
                client_socket, client_address = server_socket.accept()
                handler = ClientHandler(client_socket, client_address)
                handler.start()
            except socket.error as e:
                log_server_event(f"Error accepting new connection: {e}")
            except KeyboardInterrupt:
                log_server_event("Server shutting down by admin (Ctrl+C).")
                break


    except socket.error as e:
        log_server_event(f"Socket error: {e}")
    except Exception as e:
        log_server_event(f"An unexpected error occurred: {e}")
    finally:
        log_server_event("Server shutdown sequence started.")
        # Wait for active threads to finish (optional, might take time)
        # for thread in threading.enumerate():
        #     if thread is not threading.main_thread():
        #         thread.join(timeout=2)
        
        with data_lock: # Final save
            save_json(USERS_FILE, users_data)
            save_json(ROOMS_FILE, rooms_data)
        log_server_event("All data saved.")
        server_socket.close()
        log_server_event("Server socket closed.")

if __name__ == "__main__":
    # Ensure server log file exists
    if not os.path.exists(SERVER_LOG_FILE):
        with open(SERVER_LOG_FILE, 'w', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [SERVER] Log file created.\n")
    main_server()