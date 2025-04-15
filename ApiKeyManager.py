import json
import os
import time
from datetime import datetime, timedelta, timezone, time as dt_time
from collections import defaultdict
import logging

# --- Configuration ---
DEFAULT_JSON_FILE = 'api_keys_single_threaded_v2.json' # Use a distinct name
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ApiKeyManagerError(Exception):
    """Custom exception for API Key Manager errors."""
    pass

class NoAvailableKeyError(ApiKeyManagerError):
    """Raised when no available key meeting the criteria can be found."""
    pass

class ApiKeyManager:
    """
    Manages API keys with usage limits (daily and requests per minute)
    and automatic daily usage reset. Configuration is saved in the JSON file.

    *** NOTE: This implementation is NOT thread-safe. ***
    Do not share instances of this class across multiple threads without
    external locking.

    Attributes:
        json_file (str): Path to the JSON file storing key data and config.
        daily_limit (int | None): Max times a key can be used per day.
        requests_per_minute (int | None): Max requests per minute per key.
        reset_hour_utc (int | None): The UTC hour (0-23) when daily usage resets.
        reset_interval_days (int | None): Number of days after which usage resets.
        data (dict): In-memory representation of the JSON data.
                     Includes 'keys', 'config', 'last_reset_time'.
        _key_timestamps (defaultdict): In-memory tracking of recent request timestamps
                                      for rate limiting. {key: [monotonic_timestamp1,...]}
        _active_key (str | None): Stores the key obtained via __enter__ for __exit__.
    """

    def __init__(self,
                 json_file=DEFAULT_JSON_FILE,
                 daily_limit=None,
                 requests_per_minute=None,
                 reset_hour_utc=None,
                 reset_interval_days=None):
        """
        Initializes the ApiKeyManager.

        Loads configuration from the JSON file if it exists, but values
        explicitly passed to this constructor (if not None) will take precedence.

        Args:
            json_file (str): Path to the JSON file for persistence.
            daily_limit (int | None): Maximum daily usage per key. Overrides JSON if not None.
            requests_per_minute (int | None): Maximum requests per minute per key. Overrides JSON if not None.
            reset_hour_utc (int | None): UTC hour (0-23) for daily reset. Overrides JSON if not None.
            reset_interval_days (int | None): Interval in days for usage reset. Overrides JSON if not None.

        Raises:
            ValueError: If reset parameters (from args or JSON) are invalid.
            ApiKeyManagerError: If there's an issue loading/initializing data.
        """

        self.json_file = json_file
        # Store initial args temporarily
        self._init_args = {
            'daily_limit': daily_limit,
            'requests_per_minute': requests_per_minute,
            'reset_hour_utc': reset_hour_utc,
            'reset_interval_days': reset_interval_days,
        }

        # These will be finalized after loading/merging with JSON config
        self.daily_limit = daily_limit
        self.requests_per_minute = requests_per_minute
        self.reset_hour_utc = reset_hour_utc
        self.reset_interval_days = reset_interval_days

        self._key_timestamps = defaultdict(list)
        self._active_key = None
        self.data = None # Will be loaded or initialized
        self.api_keys = [] # Initialize as an empty list

        self._load_or_initialize_data()

        # Final validation after potentially loading from JSON
        if self.reset_hour_utc is not None and not (0 <= self.reset_hour_utc <= 23):
            raise ValueError("reset_hour_utc must be between 0 and 23.")
        if self.reset_interval_days is not None and self.reset_interval_days <= 0:
             raise ValueError("reset_interval_days must be a positive integer.")
        
        # Populate self.api_keys after data is loaded
        self.api_keys = list(self.data.get('keys', {}).keys())


    def _get_now_utc(self) -> datetime:
        """Returns the current time in UTC."""
        return datetime.now(timezone.utc)

    def _load_or_initialize_data(self):
        """Loads data and config, merging with init args, or initializes."""
        now_utc = self._get_now_utc()
        initial_reset_time_str = now_utc.isoformat()

        if os.path.exists(self.json_file):
            try:
                with open(self.json_file, 'r') as f:
                    loaded_data = json.load(f)

                # Basic Validation
                if not isinstance(loaded_data, dict):
                    raise ApiKeyManagerError(f"Invalid format in {self.json_file}: root should be a dictionary.")
                if 'keys' not in loaded_data: loaded_data['keys'] = {}
                if 'last_reset_time' not in loaded_data:
                     logging.warning(f"'last_reset_time' missing in {self.json_file}. Setting to current time.")
                     loaded_data['last_reset_time'] = initial_reset_time_str
                # Config is optional, default to empty if missing
                saved_config = loaded_data.get('config', {})
                if 'config' not in loaded_data: loaded_data['config'] = saved_config # Ensure it exists in data

                # --- Merge Saved Config with Init Args ---
                config_params = ['daily_limit', 'requests_per_minute', 'reset_hour_utc', 'reset_interval_days']
                for param in config_params:
                    init_val = self._init_args.get(param)
                    saved_val = saved_config.get(param) # Can be None

                    if init_val is not None:
                        # Init arg takes precedence
                        if saved_val is not None and init_val != saved_val:
                            logging.warning(f"Initialization value for '{param}' ({init_val}) overrides saved value ({saved_val}) in {self.json_file}.")
                        setattr(self, param, init_val) # Use init value
                    elif saved_val is not None:
                        # Init arg is None, use saved value
                        logging.info(f"Loaded '{param}' ({saved_val}) from {self.json_file}.")
                        setattr(self, param, saved_val) # Use saved value
                    else:
                         # Both are None, keep as None
                         setattr(self, param, None)

                # Validate last_reset_time format
                try:
                    datetime.fromisoformat(loaded_data['last_reset_time'].replace('Z', '+00:00'))
                except ValueError:
                     logging.warning(f"Invalid 'last_reset_time' format in {self.json_file}. Resetting to current time.")
                     loaded_data['last_reset_time'] = initial_reset_time_str

                # Ensure usage_today exists
                for key_data in loaded_data.get('keys', {}).values():
                    if 'usage_today' not in key_data:
                        key_data['usage_today'] = 0

                self.data = loaded_data
                # Update config in data to reflect the final merged config
                self.data['config'] = self._get_current_config()
                logging.info(f"Loaded API key data from {self.json_file}")


            except json.JSONDecodeError as e:
                raise ApiKeyManagerError(f"Error decoding JSON from {self.json_file}: {e}")
            except Exception as e:
                raise ApiKeyManagerError(f"Error loading data from {self.json_file}: {e}")

        else:
            # Initialize data structure if file doesn't exist
            # Use the init args provided (which might be None)
            self.daily_limit = self._init_args['daily_limit']
            self.requests_per_minute = self._init_args['requests_per_minute']
            self.reset_hour_utc = self._init_args['reset_hour_utc']
            self.reset_interval_days = self._init_args['reset_interval_days']

            self.data = {
                'keys': {},
                'config': self._get_current_config(), # Save the initial config
                'last_reset_time': initial_reset_time_str
            }
            logging.info(f"JSON file '{self.json_file}' not found. Initializing new data structure.")
            self._save_data_internal() # Save initial structure

        # --- Perform reset check & cleanup timestamps after loading/initializing ---
        self._check_and_reset_internal(now_utc)
        self._cleanup_timestamps_internal()

    def _get_current_config(self) -> dict:
         """Returns a dictionary of the current instance configuration."""
         return {
             'daily_limit': self.daily_limit,
             'requests_per_minute': self.requests_per_minute, # Now included
             'reset_hour_utc': self.reset_hour_utc,
             'reset_interval_days': self.reset_interval_days,
         }

    def _save_data_internal(self):
        """Saves the current state of self.data to the JSON file."""
        if not self.data:
            logging.error("Attempted to save data, but self.data is not initialized.")
            return

        try:
            # Ensure config reflects current state before saving
            self.data['config'] = self._get_current_config()
            try:
                 datetime.fromisoformat(self.data['last_reset_time'].replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                 logging.error("Invalid 'last_reset_time' format before saving. Forcing current time.")
                 self.data['last_reset_time'] = self._get_now_utc().isoformat()

            temp_file = self.json_file + ".tmp"
            with open(temp_file, 'w') as f:
                json.dump(self.data, f, indent=4)
            os.replace(temp_file, self.json_file) # Atomic rename
        except IOError as e:
            logging.error(f"Failed to save data to {self.json_file}: {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred during save: {e}")


    def _check_and_reset_internal(self, now_utc: datetime):
        """Internal reset check logic."""
        # --- This logic remains unchanged ---
        if not self.data: return
        last_reset_str = self.data.get('last_reset_time')
        if not last_reset_str:
             logging.error("'last_reset_time' is missing. Setting to now.")
             self.data['last_reset_time'] = now_utc.isoformat()
             last_reset_str = self.data['last_reset_time']
        try:
            last_reset_time = datetime.fromisoformat(last_reset_str.replace('Z', '+00:00'))
            if last_reset_time.tzinfo is None: last_reset_time = last_reset_time.replace(tzinfo=timezone.utc)
        except ValueError:
             logging.error(f"Could not parse last_reset_time '{last_reset_str}'. Reset check skipped. Setting to now.")
             self.data['last_reset_time'] = now_utc.isoformat()
             return

        reset_needed, reason = False, ""
        if self.reset_interval_days is not None:
            if now_utc >= last_reset_time + timedelta(days=self.reset_interval_days):
                reset_needed, reason = True, f"interval of {self.reset_interval_days} days"
        if not reset_needed and self.reset_hour_utc is not None:
            reset_dt = dt_time(self.reset_hour_utc, tzinfo=timezone.utc)
            potential = datetime.combine(last_reset_time.date(), reset_dt)
            next_reset = potential + timedelta(days=1) if potential <= last_reset_time else potential
            if now_utc >= next_reset:
                reset_needed, reason = True, f"daily reset hour UTC {self.reset_hour_utc}:00"

        if reset_needed:
            logging.info(f"Resetting daily usage counts. Reason: Passed {reason}. Last reset: {last_reset_time.isoformat()}")
            keys_updated = 0
            for key_data in self.data.get('keys', {}).values():
                 if key_data.get('usage_today', 0) != 0:
                     key_data['usage_today'] = 0
                     keys_updated += 1
            self.data['last_reset_time'] = now_utc.isoformat()
            logging.info(f"Reset usage_today for {keys_updated} keys." if keys_updated > 0 else "No keys required usage reset.")
            self._save_data_internal()

    def _cleanup_timestamps_internal(self):
        """Removes timestamps older than 1 minute from _key_timestamps."""
        # --- This logic remains unchanged ---
        if not self.requests_per_minute: return
        now = time.monotonic()
        cutoff = now - 60
        for key in list(self._key_timestamps.keys()):
            valid_timestamps = [ts for ts in self._key_timestamps[key] if ts >= cutoff]
            if not valid_timestamps: del self._key_timestamps[key]
            else: self._key_timestamps[key] = valid_timestamps


    def add_key(self, api_key: str):
        """Adds a new API key to the manager."""
        # --- This logic remains unchanged ---
        if not api_key or not isinstance(api_key, str): raise ValueError("API key must be a non-empty string.")
        self._check_and_reset_internal(self._get_now_utc())
        if api_key in self.data['keys']: raise ApiKeyManagerError(f"API key '{api_key}' already exists.")
        self.data['keys'][api_key] = {"usage_today": 0}
        logging.info(f"Added new API key: {api_key}")
        self._save_data_internal()

    def remove_key(self, api_key: str):
        """Removes an API key from the manager."""
        # --- This logic remains unchanged ---
        self._check_and_reset_internal(self._get_now_utc())
        if api_key not in self.data['keys']: raise ApiKeyManagerError(f"API key '{api_key}' not found.")
        del self.data['keys'][api_key]
        if api_key in self._key_timestamps: del self._key_timestamps[api_key]
        logging.info(f"Removed API key: {api_key}")
        self._save_data_internal()

    def get_key(self) -> str:
        """Returns an available API key that hasn't exceeded its limits."""
        # --- This logic remains unchanged ---
        self._check_and_reset_internal(self._get_now_utc())
        self._cleanup_timestamps_internal()
        if not self.data.get('keys'): raise NoAvailableKeyError("No API keys configured.")

        for key, key_data in self.data['keys'].items():
            if self.daily_limit is not None and key_data.get('usage_today', 0) >= self.daily_limit:
                 continue
            if self.requests_per_minute is not None and len(self._key_timestamps.get(key, [])) >= self.requests_per_minute:
                 continue
            return key # Return first available

        raise NoAvailableKeyError("All API keys have reached their usage limits.")

    def record_usage(self, api_key: str):
        """Records the usage of a specific API key."""
        # --- This logic remains unchanged ---
        if not api_key or not isinstance(api_key, str):
            logging.warning(f"Attempted to record usage for invalid key: {api_key}"); return
        self._check_and_reset_internal(self._get_now_utc())
        if api_key not in self.data.get('keys', {}):
             raise ApiKeyManagerError(f"Attempted to record usage for unknown key: {api_key}")
        key_data = self.data['keys'][api_key]
        key_data['usage_today'] = key_data.get('usage_today', 0) + 1
        if self.requests_per_minute is not None: self._key_timestamps[api_key].append(time.monotonic())
        self._save_data_internal()

    def get_usage_stats(self) -> dict:
        """ Returns current usage statistics for all keys. """
        # --- This logic remains unchanged ---
        self._check_and_reset_internal(self._get_now_utc())
        return json.loads(json.dumps(self.data.get('keys', {}))) # Deep copy

    def get_last_reset_time(self) -> datetime | None:
         """ Returns the last reset time as a datetime object, or None if unavailable. """
         # --- This logic remains unchanged ---
         last_reset_str = self.data.get('last_reset_time')
         if last_reset_str:
             try:
                 dt = datetime.fromisoformat(last_reset_str.replace('Z', '+00:00'))
                 return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
             except ValueError: logging.error(f"Could not parse stored last_reset_time: {last_reset_str}")
         return None

    def __enter__(self):
        """Context manager entry point. Gets an available key."""
        # --- This logic remains unchanged ---
        self._active_key = self.get_key()
        return self._active_key

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit point. Records usage for the key."""
        # --- This logic remains unchanged ---
        key_to_record = self._active_key
        self._active_key = None
        if key_to_record:
            try: self.record_usage(key_to_record)
            except ApiKeyManagerError as e: logging.error(f"Error recording usage in __exit__ for key '{key_to_record}': {e}")
        return False # Don't suppress exceptions


# --- Example Usage (Demonstrating Loading) ---
if __name__ == "__main__":
    KEY_FILE = DEFAULT_JSON_FILE # Use the constant defined above
    # --- Cleanup ---
    if os.path.exists(KEY_FILE): os.remove(KEY_FILE)
    if os.path.exists(KEY_FILE + ".tmp"): os.remove(KEY_FILE + ".tmp")

    print(f"--- Initializing ApiKeyManager First Time ---")
    try:
        # Initialize with explicit parameters the first time
        manager1 = ApiKeyManager(
            json_file=KEY_FILE,
            daily_limit=50,         # Lower limit for testing
            requests_per_minute=5,  # Lower limit for testing
            reset_hour_utc=3
        )
        print(f"Manager 1 RPM Limit: {manager1.requests_per_minute}")
        manager1.add_key("load_test_key_1")
        manager1.add_key("load_test_key_2")
        print("Added keys and saved initial config.")
        # Use one key
        with manager1 as k: print(f"Used key {k}")

    except Exception as e:
        print(f"Error during first initialization: {e}")
        import traceback
        traceback.print_exc()

    print("-" * 20)
    # --- Simulate script restart ---
    print(f"--- Initializing ApiKeyManager Second Time (Loading from JSON) ---")
    try:
        # Initialize *only* with the file path
        # It should load daily_limit=50, requests_per_minute=5, reset_hour_utc=3 from JSON
        manager2 = ApiKeyManager(json_file=KEY_FILE)

        print(f"Manager 2 Loaded Daily Limit: {manager2.daily_limit}")
        print(f"Manager 2 Loaded RPM Limit: {manager2.requests_per_minute}") # Should be 5
        print(f"Manager 2 Loaded Reset Hour: {manager2.reset_hour_utc}")

        # Check usage stats (key 1 should have usage 1)
        print("\nUsage stats loaded by Manager 2:")
        print(json.dumps(manager2.get_usage_stats(), indent=2))

        # Demonstrate override:
        print("\n--- Initializing Third Time (Overriding RPM) ---")
        manager3 = ApiKeyManager(json_file=KEY_FILE, requests_per_minute=20) # Override RPM
        print(f"Manager 3 Daily Limit (from JSON): {manager3.daily_limit}")
        print(f"Manager 3 RPM Limit (Overridden): {manager3.requests_per_minute}") # Should be 20
        print(f"Manager 3 Reset Hour (from JSON): {manager3.reset_hour_utc}")


    except ApiKeyManagerError as e:
        print(f"API Key Manager Error: {e}")
    except ValueError as e:
        print(f"Configuration Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during example execution: {e}")
        import traceback
        traceback.print_exc()

    # finally:
        # Optional cleanup
        # if os.path.exists(KEY_FILE): os.remove(KEY_FILE)
        # if os.path.exists(KEY_FILE + ".tmp"): os.remove(KEY_FILE + ".tmp")