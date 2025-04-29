import json
import os
import time
from datetime import datetime, timedelta, timezone, time as dt_time
from collections import defaultdict
import logging
import typing
import copy # Imported for potential deep copies if needed, though not directly used now

# --- Configuration ---
DEFAULT_JSON_FILE = 'api_keys_manager_data.json' # Use a distinct name
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ApiKeyManagerError(Exception):
    """Custom exception for API Key Manager errors."""
    pass

class NoAvailableKeyError(ApiKeyManagerError):
    """Raised when no available key meeting the criteria can be found."""
    pass

class ApiKeyManager:
    """
    Manages API keys with usage limits (RPD, RPM, TPD, TPM),
    automatic daily usage reset, and temporary cooldowns.
    Configuration is saved in the JSON file.

    *** NOTE: This implementation is NOT thread-safe. ***
    Do not share instances of this class across multiple threads without
    external locking.

    Attributes:
        json_file (str): Path to the JSON file storing key data and config.
        daily_limit (int | None): Max times a key can be used per day (RPD).
        requests_per_minute (int | None): Max requests per minute per key (RPM).
        tokens_per_day (int | None): Max tokens per day per key (TPD).
        tokens_per_minute (int | None): Max tokens per minute per key (TPM).
        reset_hour_utc (int | None): The UTC hour (0-23) when daily usage resets.
        reset_interval_days (int | None): Number of days after which usage resets.
        data (dict): In-memory representation of the JSON data.
                     Includes 'keys', 'config', 'last_reset_time'.
        _key_timestamps (defaultdict): In-memory tracking of recent request timestamps
                                      for RPM limiting. {key: [monotonic_timestamp1,...]}
        _key_token_timestamps (defaultdict): In-memory tracking of recent token usage
                                            for TPM limiting. {key: [(monotonic_timestamp, tokens_used),...]}
        _key_cooldowns (defaultdict): In-memory tracking of key cooldown end times.
                                     {key: end_monotonic_timestamp}
        _active_key (str | None): Stores the key obtained via __enter__ for __exit__.
    """

    def __init__(self,
                 json_file: str = DEFAULT_JSON_FILE,
                 daily_limit: typing.Optional[int] = None,
                 requests_per_minute: typing.Optional[int] = None,
                 tokens_per_day: typing.Optional[int] = None,
                 tokens_per_minute: typing.Optional[int] = None,
                 reset_hour_utc: typing.Optional[int] = None,
                 reset_interval_days: typing.Optional[int] = None):
        """
        Initializes the ApiKeyManager.

        Loads configuration from the JSON file if it exists, but values
        explicitly passed to this constructor (if not None) will take precedence
        and be saved back to the JSON file immediately if they override loaded values.

        Args:
            json_file (str): Path to the JSON file for persistence.
            daily_limit (int | None): Maximum daily requests per key (RPD). Overrides JSON if not None.
            requests_per_minute (int | None): Maximum requests per minute per key (RPM). Overrides JSON if not None.
            tokens_per_day (int | None): Maximum daily tokens per key (TPD). Overrides JSON if not None.
            tokens_per_minute (int | None): Maximum tokens per minute per key (TPM). Overrides JSON if not None.
            reset_hour_utc (int | None): UTC hour (0-23) for daily reset. Overrides JSON if not None.
            reset_interval_days (int | None): Interval in days for usage reset. Overrides JSON if not None.

        Raises:
            ValueError: If limit values passed are not positive integers or reset parameters are invalid.
            ApiKeyManagerError: If there's an issue loading/initializing data.
        """
        # Initial validation of *passed* arguments
        if daily_limit is not None and daily_limit <= 0: raise ValueError("daily_limit must be a positive integer.")
        if requests_per_minute is not None and requests_per_minute <= 0: raise ValueError("requests_per_minute must be a positive integer.")
        if tokens_per_day is not None and tokens_per_day <= 0: raise ValueError("tokens_per_day must be a positive integer.")
        if tokens_per_minute is not None and tokens_per_minute <= 0: raise ValueError("tokens_per_minute must be a positive integer.")
        if reset_hour_utc is not None and not (0 <= reset_hour_utc <= 23): raise ValueError("reset_hour_utc must be between 0 and 23.")
        if reset_interval_days is not None and reset_interval_days <= 0: raise ValueError("reset_interval_days must be a positive integer.")


        self.json_file = json_file
        # Store initial args temporarily to compare against loaded values
        self._init_args = {
            'daily_limit': daily_limit,
            'requests_per_minute': requests_per_minute,
            'tokens_per_day': tokens_per_day,
            'tokens_per_minute': tokens_per_minute,
            'reset_hour_utc': reset_hour_utc,
            'reset_interval_days': reset_interval_days,
        }

        # Initialize instance attributes to None first. They will be set by _init_args or loaded values.
        self.daily_limit = None
        self.requests_per_minute = None
        self.tokens_per_day = None
        self.tokens_per_minute = None
        self.reset_hour_utc = None
        self.reset_interval_days = None

        self._key_timestamps = defaultdict(list)
        self._key_token_timestamps = defaultdict(list)
        self._key_cooldowns = defaultdict(float) # Stores end monotonic timestamp
        self._active_key = None
        self.data = None # Will be loaded or initialized

        self._load_or_initialize_data()

        # Final validation of the *effective* configuration (after loading/merging)
        # Check that loaded values didn't violate constraints. Redundant if load logic is robust, but safe.
        if self.reset_hour_utc is not None and not (0 <= self.reset_hour_utc <= 23):
            raise ValueError("Loaded reset_hour_utc must be between 0 and 23.")
        if self.reset_interval_days is not None and self.reset_interval_days <= 0:
            raise ValueError("Loaded reset_interval_days must be a positive integer.")
        if self.daily_limit is not None and self.daily_limit <= 0:
            raise ValueError("Loaded daily_limit must be a positive integer.")
        if self.requests_per_minute is not None and self.requests_per_minute <= 0:
            raise ValueError("Loaded requests_per_minute must be a positive integer.")
        if self.tokens_per_day is not None and self.tokens_per_day <= 0:
            raise ValueError("Loaded tokens_per_day must be a positive integer.")
        if self.tokens_per_minute is not None and self.tokens_per_minute <= 0:
            raise ValueError("Loaded tokens_per_minute must be a positive integer.")


    def _get_now_utc(self) -> datetime:
        """Returns the current time in UTC."""
        return datetime.now(timezone.utc)

    def _get_monotonic_time(self) -> float:
        """Returns the current monotonic time."""
        return time.monotonic()

    def _load_or_initialize_data(self):
        """Loads data and config, merging with init args, or initializes."""
        now_utc = self._get_now_utc()
        initial_reset_time_str = now_utc.isoformat()
        config_needs_save = False # Flag to track if overrides require saving

        config_params = [
            'daily_limit', 'requests_per_minute', 'tokens_per_day',
            'tokens_per_minute', 'reset_hour_utc', 'reset_interval_days'
        ]

        if os.path.exists(self.json_file):
            try:
                with open(self.json_file, 'r') as f:
                    loaded_data = json.load(f)

                # Basic Validation
                if not isinstance(loaded_data, dict):
                    raise ApiKeyManagerError(f"Invalid format in {self.json_file}: root should be a dictionary.")
                if 'keys' not in loaded_data or not isinstance(loaded_data['keys'], dict):
                    logging.warning(f"'keys' missing or not a dict in {self.json_file}. Initializing empty.")
                    loaded_data['keys'] = {}
                if 'last_reset_time' not in loaded_data:
                    logging.warning(f"'last_reset_time' missing in {self.json_file}. Setting to current time.")
                    loaded_data['last_reset_time'] = initial_reset_time_str
                    config_needs_save = True # Need to save the added reset time

                saved_config = loaded_data.get('config', {})
                if not isinstance(saved_config, dict):
                     logging.warning(f"'config' is not a dict in {self.json_file}. Initializing empty.")
                     saved_config = {}
                # Ensure 'config' key exists in loaded_data, even if empty initially
                loaded_data['config'] = saved_config

                # --- Determine Effective Config: Merge Saved Config with Init Args ---
                effective_config = {}
                for param in config_params:
                    init_val = self._init_args.get(param)
                    saved_val = saved_config.get(param) # Can be None or missing

                    if init_val is not None:
                        # Init arg takes precedence
                        effective_config[param] = init_val
                        if saved_val is not None and init_val != saved_val:
                            logging.warning(f"Initialization value for '{param}' ({init_val}) overrides saved value ({saved_val}) in {self.json_file}.")
                            config_needs_save = True
                        elif saved_val is None and param in saved_config: # Saved explicitly as None
                            if init_val is not None: # Overriding explicit None with value
                                config_needs_save = True
                        elif param not in saved_config: # Saved value was missing
                            config_needs_save = True # Adding a new value from init args
                    elif saved_val is not None:
                        # Init arg is None, use saved value
                        effective_config[param] = saved_val
                        logging.info(f"Loaded '{param}' ({saved_val}) from {self.json_file}.")
                    else:
                        # Init arg is None, saved value is None or missing -> effective value is None
                        effective_config[param] = None
                        # Check if key was missing in saved_config and needs adding (even if None)
                        if param not in saved_config:
                            config_needs_save = True # Ensure key exists in saved config eventually

                # Update instance attributes from the effective config
                for param, value in effective_config.items():
                    setattr(self, param, value)

                # Validate last_reset_time format after potential loading
                try:
                    datetime.fromisoformat(loaded_data['last_reset_time'].replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    logging.warning(f"Invalid 'last_reset_time' format in {self.json_file}. Resetting to current time.")
                    loaded_data['last_reset_time'] = initial_reset_time_str
                    config_needs_save = True # Need to save the corrected reset time

                # Ensure usage fields exist and are numeric in loaded keys
                # Also, track if any key data needed correction (for potential save later)
                keys_data_corrected = False
                for key, key_data in loaded_data.get('keys', {}).items():
                    if not isinstance(key_data, dict):
                        logging.warning(f"Invalid data format for key '{key}'. Resetting.")
                        loaded_data['keys'][key] = {"usage_today": 0, "tokens_today": 0}
                        keys_data_corrected = True
                        continue

                    usage_updated = False
                    if not isinstance(key_data.get('usage_today'), (int, float)) or key_data.get('usage_today') < 0:
                        logging.warning(f"'usage_today' missing or invalid for key '{key}'. Setting to 0.")
                        key_data['usage_today'] = 0
                        usage_updated = True
                    if not isinstance(key_data.get('tokens_today'), (int, float)) or key_data.get('tokens_today') < 0:
                         logging.warning(f"'tokens_today' missing or invalid for key '{key}'. Setting to 0.")
                         key_data['tokens_today'] = 0
                         usage_updated = True
                    if usage_updated:
                         keys_data_corrected = True

                self.data = loaded_data
                # Update config dict *within* self.data *before* potential save
                self.data['config'] = self._get_current_config()

                # Save immediately if configuration was overridden or corrected during loading
                # Also save if key data was corrected or last_reset_time was fixed.
                if config_needs_save or keys_data_corrected:
                    if config_needs_save:
                        logging.info(f"Configuration updated during initialization. Saving changes to {self.json_file}.")
                    if keys_data_corrected:
                        logging.info(f"Key usage data corrected during initialization. Saving changes to {self.json_file}.")
                    self._save_data_internal()

            except json.JSONDecodeError as e:
                raise ApiKeyManagerError(f"Error decoding JSON from {self.json_file}: {e}")
            except Exception as e:
                # Catching broader exceptions during complex load/merge phase
                raise ApiKeyManagerError(f"Error processing data from {self.json_file}: {e}")

        else:
            # Initialize data structure if file doesn't exist
            # Use the init args provided (which might be None). Instance attrs are set based on them.
            for param, value in self._init_args.items():
                if value is not None:
                    setattr(self, param, value)

            self.data = {
                'keys': {},
                'config': self._get_current_config(), # Save the initial config based on instance attrs
                'last_reset_time': initial_reset_time_str
            }
            logging.info(f"JSON file '{self.json_file}' not found. Initializing new data structure.")
            self._save_data_internal() # Save initial structure immediately

        # --- Perform reset check & cleanup timestamps after loading/initializing ---
        self._check_and_reset_internal(now_utc) # Checks if reset is needed based on loaded time
        self._cleanup_timestamps_internal() # Clean up potentially stale in-memory timestamps


    def _get_current_config(self) -> dict:
        """Returns a dictionary of the current instance configuration attributes."""
        return {
            'daily_limit': self.daily_limit,
            'requests_per_minute': self.requests_per_minute,
            'tokens_per_day': self.tokens_per_day,
            'tokens_per_minute': self.tokens_per_minute,
            'reset_hour_utc': self.reset_hour_utc,
            'reset_interval_days': self.reset_interval_days,
        }

    def _save_data_internal(self):
        """Saves the current state of self.data to the JSON file."""
        if not self.data:
            logging.error("Attempted to save data, but self.data is not initialized.")
            return

        try:
            # Ensure config dict in data reflects current instance state before saving
            self.data['config'] = self._get_current_config()
            # Ensure last reset time is valid ISO format before saving
            original_last_reset_time_str = self.data.get('last_reset_time') # Store for logging error if needed
            try:
                 # Basic check for ISO format string
                 datetime.fromisoformat(str(self.data['last_reset_time']).replace('Z', '+00:00'))
            except (ValueError, AttributeError, TypeError):
                 now_iso = self._get_now_utc().isoformat()
                 logging.error(f"Invalid 'last_reset_time' ({original_last_reset_time_str}) format before saving. Forcing current time: {now_iso}.")
                 self.data['last_reset_time'] = now_iso
            # Ensure usage data is non-negative numeric
            for key, key_data in self.data.get('keys', {}).items():
                # Defensive check: ensure key_data is a dict
                if not isinstance(key_data, dict):
                     logging.warning(f"Saving: Found non-dict data for key '{key}'. Resetting to default.")
                     self.data['keys'][key] = {"usage_today": 0, "tokens_today": 0}
                     continue
                if not isinstance(key_data.get('usage_today'), (int, float)) or key_data.get('usage_today') < 0:
                    logging.warning(f"Saving: Correcting invalid 'usage_today' for key {key}. Setting to 0.")
                    key_data['usage_today'] = 0
                if not isinstance(key_data.get('tokens_today'), (int, float)) or key_data.get('tokens_today') < 0:
                    logging.warning(f"Saving: Correcting invalid 'tokens_today' for key {key}. Setting to 0.")
                    key_data['tokens_today'] = 0


            temp_file = self.json_file + ".tmp"
            with open(temp_file, 'w') as f:
                json.dump(self.data, f, indent=4)
            # Attempt atomic replace, fall back to rename on Windows Error 183
            try:
                os.replace(temp_file, self.json_file)
            except OSError as e:
                # Handle common Windows error when file exists during replace
                # Also handle PermissionError which might occur if file is temporarily locked
                if (hasattr(e, 'winerror') and e.winerror == 183 and os.path.exists(self.json_file)) or isinstance(e, PermissionError):
                    try:
                        os.remove(self.json_file)
                        os.rename(temp_file, self.json_file)
                    except OSError as e2:
                         logging.error(f"Failed to replace/rename file after initial OSError/PermissionError: {e2}")
                         # Attempt to clean up temp file if possible
                         if os.path.exists(temp_file):
                             try: os.remove(temp_file)
                             except OSError: pass
                else:
                    # Re-raise original error if it's not the expected Windows error or rename fails
                    raise
        except IOError as e:
            logging.error(f"Failed to write data to {self.json_file} or temp file: {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred during save: {e}")
            # Attempt cleanup if temp file exists
            if 'temp_file' in locals() and os.path.exists(temp_file):
                 try: os.remove(temp_file)
                 except OSError: pass # Ignore error during cleanup


    def _check_and_reset_internal(self, now_utc: datetime):
        """Checks if daily limits need resetting based on rules and performs the reset."""
        if not self.data: return

        last_reset_str = self.data.get('last_reset_time')
        original_last_reset_iso = None # Store original valid ISO string for later comparison

        # Handle missing or invalid last_reset_time
        last_reset_time = None
        if last_reset_str:
            try:
                # Ensure it's treated as UTC
                parsed_time = datetime.fromisoformat(str(last_reset_str).replace('Z', '+00:00'))
                # Ensure timezone aware (assume UTC if not specified, force UTC if different)
                if parsed_time.tzinfo is None:
                    last_reset_time = parsed_time.replace(tzinfo=timezone.utc)
                elif parsed_time.tzinfo != timezone.utc:
                     last_reset_time = parsed_time.astimezone(timezone.utc)
                else:
                    last_reset_time = parsed_time

                original_last_reset_iso = last_reset_time.isoformat() # Store valid original time
            except (ValueError, TypeError):
                logging.error(f"Could not parse last_reset_time '{last_reset_str}'. Reset check skipped. Forcing reset time to now.")
                last_reset_str = None # Force setting to now_utc below

        if last_reset_time is None:
             last_reset_time = now_utc # Use the provided 'now_utc'
             new_reset_time_iso = now_utc.isoformat()
             self.data['last_reset_time'] = new_reset_time_iso
             logging.warning(f"Invalid or missing 'last_reset_time'. Setting to current check time: {new_reset_time_iso}")
             # Save immediately as this is a corrective action
             self._save_data_internal()
             # No need to perform reset check on this run, as we just set the time
             return # Exit after fixing missing/invalid time

        # If we have a valid last_reset_time, proceed with checks
        reset_needed, reason = False, ""
        # Check interval-based reset first (if configured)
        if self.reset_interval_days is not None and self.reset_interval_days > 0:
            # Use >= for safety, covering cases where execution might be delayed
            if now_utc >= last_reset_time + timedelta(days=self.reset_interval_days):
                reset_needed = True
                reason = f"interval of {self.reset_interval_days} days"

        # Check daily reset hour (if configured and interval didn't trigger)
        if not reset_needed and self.reset_hour_utc is not None:
            # Calculate the *next* potential reset time based on the *last* reset time
            reset_dt = dt_time(self.reset_hour_utc, tzinfo=timezone.utc)
            # Combine last reset *date* with the target reset *time*
            potential_reset_this_cycle = datetime.combine(last_reset_time.date(), reset_dt)

            # Determine the absolute next reset occurrence relative to the last reset time
            if potential_reset_this_cycle <= last_reset_time:
                 # Reset time for the day of the last reset has already passed or is exactly now.
                 # The next scheduled reset is at the specified hour on the *next* calendar day.
                 next_reset_occurrence = datetime.combine(last_reset_time.date() + timedelta(days=1), reset_dt)
            else:
                 # Reset time for the day of the last reset is still in the future.
                 # The next scheduled reset is later today (relative to last reset).
                 next_reset_occurrence = potential_reset_this_cycle

            # Check if the current time is at or after the next scheduled reset time
            if now_utc >= next_reset_occurrence:
                reset_needed = True
                reason = f"daily reset hour UTC {self.reset_hour_utc:02d}:00"


        if reset_needed:
            logging.info(f"Resetting daily usage counts. Reason: Passed {reason}. Last reset: {last_reset_time.isoformat()}. Check time: {now_utc.isoformat()}")
            keys_updated = 0
            for key, key_data in self.data.get('keys', {}).items():
                # Ensure key_data is a dict before accessing keys
                if isinstance(key_data, dict):
                    usage_reset = False
                    if key_data.get('usage_today', 0) != 0:
                        key_data['usage_today'] = 0
                        usage_reset = True
                    if key_data.get('tokens_today', 0) != 0:
                        key_data['tokens_today'] = 0
                        usage_reset = True
                    if usage_reset:
                        keys_updated += 1
                else:
                    # Log if key_data is not a dict, though load should prevent this
                    logging.warning(f"Skipping reset for non-dict key data for key '{key}': {key_data}")

            new_reset_time_iso = now_utc.isoformat()
            self.data['last_reset_time'] = new_reset_time_iso # Update reset time in data

            # Save if counters were reset OR if the time *must* be updated (interval trigger)
            # For hour-based reset, only save if counters changed.
            # For interval-based, save always if interval passed, because the timestamp *must* update.
            save_required = False
            if keys_updated > 0:
                logging.info(f"Reset daily usage for {keys_updated} keys.")
                save_required = True
            elif self.reset_interval_days is not None and reason.startswith("interval"):
                 # Interval triggered, save the new reset time even if counts were 0
                 logging.info("Interval reset triggered, saving updated last_reset_time even though usage counts were already zero.")
                 save_required = True
            else:
                 logging.info("Reset time passed, but no key usage needed resetting.")
                 # If only hour based, no need to save if nothing changed.
                 # Check if the calculated new time is different from the original (covers edge cases)
                 if original_last_reset_iso is None or new_reset_time_iso != original_last_reset_iso:
                     logging.info(f"Saving updated last_reset_time ({new_reset_time_iso}) as it changed from original ({original_last_reset_iso}).")
                     save_required = True


            if save_required:
                 self._save_data_internal()


    def _cleanup_timestamps_internal(self):
        """Removes timestamps older than 1 minute from internal tracking."""
        now_mono = self._get_monotonic_time()
        cutoff = now_mono - 60.0 # 60 seconds cutoff

        # Cleanup RPM timestamps (_key_timestamps)
        if self.requests_per_minute is not None:
            keys_to_delete_rpm = []
            for key, timestamps in self._key_timestamps.items():
                valid_timestamps = [ts for ts in timestamps if ts >= cutoff]
                if not valid_timestamps:
                    # Check if key still exists in self.data before deleting from timestamps
                    # to prevent errors if remove_key was called concurrently (though class is not thread-safe)
                    if key in self.data.get('keys', {}):
                        keys_to_delete_rpm.append(key)
                    # else: Key no longer exists, defaultdict will handle removal if accessed again
                else:
                    self._key_timestamps[key] = valid_timestamps
            for key in keys_to_delete_rpm:
                # Check again before deleting, safety for non-thread-safe env
                if key not in self.data.get('keys',{}): continue
                if not any(ts >= cutoff for ts in self._key_timestamps.get(key, [])):
                    self._key_timestamps.pop(key, None)


        # Cleanup TPM timestamps (_key_token_timestamps)
        if self.tokens_per_minute is not None:
             keys_to_delete_tpm = []
             for key, entries in self._key_token_timestamps.items():
                 valid_entries = [(ts, tokens) for ts, tokens in entries if ts >= cutoff]
                 if not valid_entries:
                     if key in self.data.get('keys', {}):
                         keys_to_delete_tpm.append(key)
                 else:
                     self._key_token_timestamps[key] = valid_entries
             for key in keys_to_delete_tpm:
                 if key not in self.data.get('keys',{}): continue
                 if not any(ts >= cutoff for ts, tokens in self._key_token_timestamps.get(key, [])):
                     self._key_token_timestamps.pop(key, None)

        # Cleanup expired cooldowns (_key_cooldowns)
        keys_to_delete_cooldown = []
        for key, expiry_time in self._key_cooldowns.items():
            # Check key existence before deciding to delete cooldown
            if key not in self.data.get('keys', {}):
                 keys_to_delete_cooldown.append(key) # Remove cooldown for non-existent key
            elif expiry_time <= now_mono:
                keys_to_delete_cooldown.append(key)
                logging.debug(f"Cooldown expired for key {key[:4]}...{key[-4:]}")
        for key in keys_to_delete_cooldown:
            self._key_cooldowns.pop(key, None)


    def add_key(self, api_key: str):
        """Adds a new API key to the manager."""
        if not api_key or not isinstance(api_key, str):
            raise ValueError("API key must be a non-empty string.")

        # Ensure data is current before modification, handle potential reset
        self._check_and_reset_internal(self._get_now_utc())

        # Initialize 'keys' if it doesn't exist (paranoid check)
        if 'keys' not in self.data or not isinstance(self.data['keys'], dict):
            self.data['keys'] = {}

        if api_key in self.data['keys']:
            raise ApiKeyManagerError(f"API key ending with '...{api_key[-4:]}' already exists.")

        self.data['keys'][api_key] = {"usage_today": 0, "tokens_today": 0}
        logging.info(f"Added new API key: {api_key[:4]}...{api_key[-4:]}")
        self._save_data_internal()

    def remove_key(self, api_key: str):
        """Removes an API key from the manager."""
        # Ensure data is current
        self._check_and_reset_internal(self._get_now_utc())

        if 'keys' not in self.data or api_key not in self.data.get('keys', {}):
            raise ApiKeyManagerError(f"API key '{api_key[:4]}...{api_key[-4:]}' not found.")

        # Remove from persistent storage
        del self.data['keys'][api_key]

        # Remove from in-memory tracking (use pop with default to avoid KeyErrors)
        self._key_timestamps.pop(api_key, None)
        self._key_token_timestamps.pop(api_key, None)
        self._key_cooldowns.pop(api_key, None)

        logging.info(f"Removed API key: {api_key[:4]}...{api_key[-4:]}")
        self._save_data_internal()

    def is_key_usable(self, key: str, key_data: dict, now_mono: float) -> bool:
        """Checks if a single key is currently usable based on all limits."""
        # 0. Basic checks
        if not isinstance(key_data, dict):
            logging.warning(f"Invalid key_data encountered for key {key[:4]}...{key[-4:]}. Marking unusable.")
            return False # Treat invalid data as unusable

        # 1. Check Cooldown
        if key in self._key_cooldowns and self._key_cooldowns[key] > now_mono:
            # logging.debug(f"Key {key[:4]}... unusable due to cooldown.")
            return False

        # 2. Check RPD (Daily Request Limit)
        if self.daily_limit is not None:
            # Use .get() with default 0 for safety
            if key_data.get('usage_today', 0) >= self.daily_limit:
                # logging.debug(f"Key {key[:4]}... unusable due to RPD limit.")
                return False

        # 3. Check TPD (Daily Token Limit)
        if self.tokens_per_day is not None:
             if key_data.get('tokens_today', 0) >= self.tokens_per_day:
                 # logging.debug(f"Key {key[:4]}... unusable due to TPD limit.")
                 return False

        # 4. Check RPM (Requests Per Minute Limit)
        # Needs cleanup beforehand to be accurate
        if self.requests_per_minute is not None:
            # Get current timestamps for this key (cleanup should have run)
            request_timestamps = self._key_timestamps.get(key, [])
            if len(request_timestamps) >= self.requests_per_minute:
                 # logging.debug(f"Key {key[:4]}... unusable due to RPM limit.")
                 return False # Already hit limit in the current window

        # 5. Check TPM (Tokens Per Minute Limit)
        # Needs cleanup beforehand to be accurate
        if self.tokens_per_minute is not None:
            token_entries = self._key_token_timestamps.get(key, [])
            # Sum tokens from entries within the valid window (cleanup ensures this)
            current_minute_tokens = sum(tokens for ts, tokens in token_entries)
            # Use >= for the check against the limit
            if current_minute_tokens >= self.tokens_per_minute:
                # logging.debug(f"Key {key[:4]}... unusable due to TPM limit.")
                return False

        # If none of the limits were hit, the key is usable
        return True

    def get_key(self) -> str:
        """
        Returns a single available API key that hasn't exceeded its limits
        and is not on cooldown. Iterates through keys in their stored order.

        Raises:
            NoAvailableKeyError: If no keys are configured or all keys are currently unusable.
        """
        # Ensure limits are checked against current state and timestamps cleaned
        self._check_and_reset_internal(self._get_now_utc())
        self._cleanup_timestamps_internal()
        now_mono = self._get_monotonic_time()

        keys_data = self.data.get('keys')
        if not keys_data:
            raise NoAvailableKeyError("No API keys configured.")

        # Iterate through keys - Python dicts maintain insertion order >= 3.7
        for key, key_data in keys_data.items():
            if self.is_key_usable(key, key_data, now_mono):
                return key # Return the first available key found

        # If loop finishes without returning, no keys were usable
        raise NoAvailableKeyError("All API keys have reached their usage limits or are on cooldown.")

    def get_keys(self, n: int = 1) -> typing.List[str]:
        """
        Returns a list of up to 'n' available API keys that haven't exceeded
        their limits and are not on cooldown. Iterates through keys in stored order.

        Args:
            n (int): The desired number of keys. Defaults to 1.
                     If n <= 0, it attempts to return 1 key.
                     If n is greater than the number of available keys,
                     it returns all available keys found.

        Returns:
            List[str]: A list of usable API key strings. Can be empty if n > 0
                       but no keys are available.

        Raises:
            NoAvailableKeyError: If n > 0 and no keys are configured.
                                 (Note: Does NOT raise if keys are configured but none are currently usable)
        """
        # Treat 0 or negative as a request for 1 key for consistency with get_key failure modes
        if n <= 0:
            n = 1

        # Ensure limits are checked against current state and timestamps cleaned
        self._check_and_reset_internal(self._get_now_utc())
        self._cleanup_timestamps_internal()
        now_mono = self._get_monotonic_time()

        keys_data = self.data.get('keys')
        if not keys_data:
             # Raise error only if no keys are configured *at all*
             raise NoAvailableKeyError("No API keys configured.")

        usable_keys = []
        # Iterate through keys - Python dicts maintain insertion order >= 3.7
        for key, key_data in keys_data.items():
            if self.is_key_usable(key, key_data, now_mono):
                usable_keys.append(key)
                if len(usable_keys) == n:
                    break # Found the requested number

        # Return the list found (might be empty if none were usable)
        return usable_keys


    def record_usage(self, api_key: str, tokens_used: int = 1):
        """
        Records the usage of a specific API key, incrementing both request
        and token counts for daily limits, and adding timestamps for
        per-minute limits. Saves the updated daily counts.

        Args:
            api_key (str): The API key that was used.
            tokens_used (int): The number of tokens consumed in this usage. Defaults to 1.
                               Provide 0 if only tracking request rate, not token usage.
                               Must be non-negative.

        Raises:
            ApiKeyManagerError: If the key is not found in the manager.
            ValueError: If tokens_used is negative.
        """
        if not isinstance(tokens_used, int) or tokens_used < 0:
            raise ValueError("tokens_used must be a non-negative integer.")
        if not api_key or not isinstance(api_key, str):
            raise ValueError("api_key must be a non-empty string.")

        # Run checks first to ensure data/reset status is up-to-date
        # This does NOT save yet, saving happens after updating counters.
        self._check_and_reset_internal(self._get_now_utc())
        # Cleanup old timestamps *before* adding new ones
        self._cleanup_timestamps_internal()
        now_mono = self._get_monotonic_time()

        # Ensure key exists in persistent data
        if 'keys' not in self.data or api_key not in self.data['keys']:
            raise ApiKeyManagerError(f"Attempted to record usage for unknown key: {api_key[:4]}...{api_key[-4:]}")

        key_data = self.data['keys'][api_key]
        if not isinstance(key_data, dict):
             # Should not happen if load/add logic is correct, but handle defensively
             logging.error(f"Data for key {api_key[:4]}...{api_key[-4:]} is not a dictionary. Cannot record usage.")
             # Attempt to fix the data structure before proceeding? Or just raise? Raising is safer.
             # self.data['keys'][api_key] = {"usage_today": 0, "tokens_today": 0}
             # key_data = self.data['keys'][api_key]
             raise ApiKeyManagerError(f"Invalid data structure for key {api_key[:4]}...{api_key[-4:]}.")


        # Increment persistent daily counters safely using .get()
        key_data['usage_today'] = key_data.get('usage_today', 0) + 1
        if tokens_used > 0:
             key_data['tokens_today'] = key_data.get('tokens_today', 0) + tokens_used

        # Add to in-memory minute counters (after cleanup)
        if self.requests_per_minute is not None:
            self._key_timestamps[api_key].append(now_mono)
        if self.tokens_per_minute is not None and tokens_used > 0:
            self._key_token_timestamps[api_key].append((now_mono, tokens_used))

        # Save updated daily usage counts
        self._save_data_internal()


    def mark_unusable(self, api_key: str, cooldown_seconds: int = 60):
        """
        Marks a specific API key as unusable for a specified duration (in-memory only).
        The key will not be returned by get_key() or get_keys() during this time.

        Args:
            api_key (str): The API key to mark as unusable.
            cooldown_seconds (int): The duration in seconds for the cooldown. Defaults to 60.
                                    Must be a non-negative integer.

        Raises:
            ApiKeyManagerError: If the key is not found in the manager's persistent data.
            ValueError: If cooldown_seconds is negative.
        """
        if not isinstance(cooldown_seconds, int) or cooldown_seconds < 0:
            raise ValueError("cooldown_seconds must be a non-negative integer.")

        # Check if the key actually exists in our managed list
        if 'keys' not in self.data or api_key not in self.data['keys']:
            raise ApiKeyManagerError(f"Cannot mark unknown key as unusable: {api_key[:4]}...{api_key[-4:]}")

        now_mono = self._get_monotonic_time()
        cooldown_end_time = now_mono + cooldown_seconds
        self._key_cooldowns[api_key] = cooldown_end_time
        logging.info(f"Marked key {api_key[:4]}...{api_key[-4:]} as unusable for {cooldown_seconds} seconds (until monotonic time {cooldown_end_time:.2f}).")
        # No need to save data, as cooldown is transient, in-memory only


    def get_usage_stats(self) -> dict:
        """
        Returns current daily usage statistics (requests and tokens) for all keys
        based on the persisted data.
        Performs a reset check before returning stats to ensure they are current.
        Returns a deep copy to prevent accidental modification of internal data.
        """
        self._check_and_reset_internal(self._get_now_utc()) # Ensure stats reflect potential reset
        # Return a deep copy to prevent accidental modification of internal data
        return copy.deepcopy(self.data.get('keys', {}))

    def get_config(self) -> dict:
        """ Returns a copy of the current configuration of the manager. """
        # Ensure config in self.data is up-to-date before copying
        self.data['config'] = self._get_current_config()
        return copy.deepcopy(self.data.get('config', {}))

    def get_last_reset_time(self) -> typing.Optional[datetime]:
        """ Returns the last reset time as a timezone-aware UTC datetime object, or None if unavailable/invalid. """
        last_reset_str = self.data.get('last_reset_time')
        if last_reset_str:
            try:
                dt = datetime.fromisoformat(str(last_reset_str).replace('Z', '+00:00'))
                # Ensure timezone info (assume UTC if none provided in string, force if different)
                if dt.tzinfo is None:
                    return dt.replace(tzinfo=timezone.utc)
                elif dt.tzinfo != timezone.utc:
                     return dt.astimezone(timezone.utc)
                else:
                    return dt
            except (ValueError, TypeError):
                logging.error(f"Could not parse stored last_reset_time: {last_reset_str}")
        return None

    def __enter__(self):
        """
        Context manager entry point. Gets a single available key.

        Returns:
            str: An available API key.

        Raises:
            NoAvailableKeyError: If no key is currently available (see get_key).
        """
        # get_key already performs necessary checks (reset, cleanup)
        self._active_key = self.get_key() # Raises NoAvailableKeyError if none available
        return self._active_key

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Context manager exit point. Records usage (1 request, 1 token)
        for the key obtained via __enter__, provided no exception occurred
        within the 'with' block.

        If an exception occurred within the 'with' block (exc_type is not None),
        usage is typically *not* recorded, assuming the operation failed.

        Note: This automatically records 1 request and 1 token usage. If you need
              to record a different number of tokens, or record usage even if
              an exception occurs, use get_key() and record_usage() manually.
        """
        key_to_record = self._active_key
        self._active_key = None # Reset active key state

        # Only record usage if the 'with' block completed without exception
        if exc_type is None and key_to_record:
            try:
                # Use default tokens_used=1 for context manager success case
                self.record_usage(key_to_record, tokens_used=1)
            except ApiKeyManagerError as e:
                # Log error if key somehow became unknown or invalid between __enter__ and __exit__
                logging.error(f"Error recording usage in __exit__ for key '{key_to_record[:4]}...{key_to_record[-4:]}': {e}")
            except ValueError as e:
                 # Should not happen with default tokens_used=1, but log defensively
                 logging.error(f"Unexpected ValueError during usage recording in __exit__: {e}")
            except Exception as e:
                 # Catch any other unexpected errors during recording
                 logging.error(f"Unexpected exception during usage recording in __exit__: {e}", exc_info=True)

        # Return False to indicate that exceptions (if any occurred *within* the 'with' block)
        # should be re-raised and not suppressed by the context manager.
        return False